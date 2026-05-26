"""
l7_auto.py - Orchestrator: run the L7 DoS tests that matter against an
auth-gated (HTTP 401/403) target, with pre-flight health check and a
consolidated summary.

Why this exists:
  When the target returns "401/403 authentication failed", only a subset
  of L7 techniques is worth testing. Cache-bust, generic POST flood, and
  algorithmic payloads are blocked by auth middleware before they reach
  the expensive handler. This script runs only the techniques that bypass
  or burn through the auth gate:

    1. Slowloris       (worker held before auth check runs)
    2. Slow read       (server still has to send the 403 slowly)
    3. Slow body       (variable; depends on stack)
    4. HTTP GET flood  (burns TLS handshake + auth-check cycles)
    5. Login flood     (optional, with --login-path; password-hashing trap)

Authorisation:
  Single prompt at the start. Each sub-test inherits L7_AUDIT_CONFIRMED=<host>
  so it doesn't re-prompt. Stops on Ctrl+C.

Usage:
  python l7_auto.py --host xxx --port 51080 --tls --insecure \
      --per-test-duration 60 --cool-down 20 \
      --login-path /api/auth/login --login-body login.json
"""

import argparse
import datetime as dt
import http.client
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
L7_AUDIT = SCRIPT_DIR / "l7_audit_py36.py"


def confirm(host):
    # type: (str) -> None
    print("\n=== L7 DoS auto-test orchestrator ===")
    print("TARGET:   {}".format(host))
    print("Sub-tests will run sequentially, each writing its own evidence files.")
    print("Run ONLY against systems you own or have written authorisation to test.\n")
    typed = input('Type the target host ("{}") to confirm authorisation: '.format(host)).strip()
    if typed != host:
        print("Confirmation did not match. Aborting.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def preflight(host, port, tls, insecure, path):
    # type: (str, int, bool, bool, str) -> dict
    out = {
        "host": host, "port": port, "tls": tls, "insecure": insecure, "path": path,
        "tcp": None, "tls_handshake": None, "tls_error": None,
        "http_status": None, "http_latency_s": None, "http_error": None,
        "auth_gated": None,
    }

    # 1. TCP
    t0 = time.monotonic()
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.close()
        out["tcp"] = round(time.monotonic() - t0, 3)
    except OSError as e:
        out["tcp"] = False
        out["tls_error"] = "TCP: {}".format(e)
        return out

    # 2. TLS handshake (if applicable)
    if tls:
        try:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            s = socket.create_connection((host, port), timeout=5)
            t0 = time.monotonic()
            ws = ctx.wrap_socket(s, server_hostname=host)
            out["tls_handshake"] = round(time.monotonic() - t0, 3)
            ws.close()
        except (OSError, ssl.SSLError) as e:
            out["tls_handshake"] = False
            out["tls_error"] = "{}: {}".format(type(e).__name__, e)
            return out

    # 3. HTTP baseline
    try:
        if tls:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=10, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)
        t0 = time.monotonic()
        conn.request("GET", path, headers={"Host": host, "User-Agent": "l7-auto/1.0",
                                            "Connection": "close"})
        resp = conn.getresponse()
        _ = resp.read(512)
        out["http_status"] = resp.status
        out["http_latency_s"] = round(time.monotonic() - t0, 3)
        out["auth_gated"] = resp.status in (401, 403)
        conn.close()
    except (OSError, http.client.HTTPException) as e:
        out["http_error"] = "{}: {}".format(type(e).__name__, e)

    return out


def preflight_pretty(pf):
    # type: (dict) -> str
    lines = []
    lines.append("Pre-flight against {}:{}".format(pf["host"], pf["port"]))
    lines.append("  TCP connect:    {}".format(
        "OK ({}s)".format(pf["tcp"]) if pf["tcp"] not in (None, False) else "FAIL"))
    if pf["tls"]:
        if pf["tls_handshake"] not in (None, False):
            lines.append("  TLS handshake:  OK ({}s)".format(pf["tls_handshake"]))
        else:
            lines.append("  TLS handshake:  FAIL ({})".format(pf["tls_error"]))
    if pf["http_status"] is not None:
        lines.append("  HTTP baseline:  status={} latency={}s {}".format(
            pf["http_status"], pf["http_latency_s"],
            "(auth-gated)" if pf["auth_gated"] else ""))
    elif pf["http_error"]:
        lines.append("  HTTP baseline:  FAIL ({})".format(pf["http_error"]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------


def run_subtest(args, env, log_path, run_dir):
    # type: (List[str], dict, Path, Path) -> int
    """Run l7_audit_py36.py subcommand with the given args. Returns exit code."""
    run_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(L7_AUDIT)] + args + ["--evidence-dir", str(run_dir)]
    with open(str(log_path), "wb") as fh:
        proc = subprocess.Popen(cmd, env=env, stdout=fh, stderr=subprocess.STDOUT)
        try:
            return proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise


def parse_jsonl_verdict(jsonl_path):
    # type: (Path) -> dict
    """Walk a per-test JSONL and classify it as DEMONSTRATED / PARTIAL / NO IMPACT."""
    if not jsonl_path.exists():
        return {"verdict": "NO DATA", "probes": 0, "failed": 0, "ratio": 0.0,
                "max_latency": 0.0, "notes": "no JSONL produced"}
    probes = failed = 0
    latencies = []
    last_state = {}
    with open(str(jsonl_path)) as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            probes += 1
            if not ev.get("probe_responded", False):
                failed += 1
            latencies.append(ev.get("probe_latency_s", 0))
            last_state = ev
    if probes == 0:
        return {"verdict": "NO DATA", "probes": 0, "failed": 0, "ratio": 0.0,
                "max_latency": 0.0, "notes": "JSONL empty"}
    ratio = failed / float(probes)
    max_lat = max(latencies) if latencies else 0
    if ratio >= 0.5:
        verdict = "DEMONSTRATED"
    elif ratio > 0 or max_lat > 5:
        verdict = "PARTIAL"
    else:
        verdict = "NO IMPACT"
    return {"verdict": verdict, "probes": probes, "failed": failed,
            "ratio": round(ratio, 2), "max_latency": round(max_lat, 2),
            "notes": "last state: " + json.dumps({k: v for k, v in last_state.items()
                                                    if k not in ("ts", "probe_latency_s")})}


def find_jsonl(run_dir, technique):
    # type: (Path, str) -> Optional[Path]
    matches = sorted(run_dir.glob("{}_*.jsonl".format(technique)))
    return matches[-1] if matches else None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--path", default="/",
                   help="Path to probe in pre-flight and slow-* tests")
    p.add_argument("--per-test-duration", type=int, default=60)
    p.add_argument("--cool-down", type=int, default=20,
                   help="Seconds between tests so target can recover")
    p.add_argument("--sockets", type=int, default=150,
                   help="Concurrent sockets for slow-* tests")
    p.add_argument("--rps", type=float, default=50,
                   help="Rate for http-flood and login-flood")
    p.add_argument("--login-path",
                   help="If set, also runs login flood against this path")
    p.add_argument("--login-body",
                   help="JSON/form body file for login flood (required with --login-path)")
    p.add_argument("--login-content-type", default="application/json")
    p.add_argument("--evidence-dir", default="./evidence")
    p.add_argument("--skip-preflight-abort", action="store_true",
                   help="Continue even if pre-flight fails (not recommended)")
    args = p.parse_args()

    if args.login_path and not args.login_body:
        p.error("--login-body is required when --login-path is set")

    confirm(args.host)

    run_id = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    run_root = Path(args.evidence_dir) / "auto_{}_{}".format(args.host, run_id)
    run_root.mkdir(parents=True, exist_ok=True)
    summary_md = run_root / "summary.md"
    preflight_txt = run_root / "00_preflight.txt"

    print("\nEvidence directory: {}\n".format(run_root))

    # --- Pre-flight ---
    print("Running pre-flight health check...")
    pf = preflight(args.host, args.port, args.tls, args.insecure, args.path)
    pf_text = preflight_pretty(pf)
    print(pf_text)
    with open(str(preflight_txt), "w") as f:
        f.write(pf_text + "\n\n")
        f.write(json.dumps(pf, indent=2))
    if pf["tcp"] is False or (args.tls and pf["tls_handshake"] is False) \
            or pf["http_status"] is None:
        print("\nPre-flight indicates the target is not reachable as configured.")
        if not args.skip_preflight_abort:
            print("Aborting. Use --skip-preflight-abort to override (not recommended).")
            sys.exit(2)

    # Prepare environment for sub-tests
    env = os.environ.copy()
    env["L7_AUDIT_CONFIRMED"] = args.host
    common = ["--host", args.host, "--port", str(args.port),
              "--duration", str(args.per_test_duration), "--probe-interval", "5"]
    if args.tls:
        common.append("--tls")
    if args.insecure:
        common.append("--insecure")

    # --- Test plan ---
    tests = [
        ("slow-headers", [
            "slow-headers", "--sockets", str(args.sockets),
            "--keepalive-interval", "15"]),
        ("slow-read", [
            "slow-read", "--path", args.path,
            "--sockets", str(args.sockets),
            "--read-interval", "10", "--recv-buf", "128"]),
        ("slow-body", [
            "slow-body", "--path", args.path,
            "--sockets", str(args.sockets),
            "--keepalive-interval", "15"]),
        ("http-flood", [
            "http-flood", "--path", args.path,
            "--rps", str(args.rps), "--workers", "20"]),
    ]
    if args.tls:
        # TLS-only attack — only run if target speaks TLS.
        tests.append(("tls-handshake-flood", [
            "tls-handshake-flood",
            "--rps", str(args.rps), "--workers", "20",
            "--no-resumption"]))
    if args.login_path:
        tests.append(("post-flood", [
            "post-flood", "--path", args.login_path,
            "--rps", str(min(args.rps, 25)), "--workers", "10",
            "--body-file", args.login_body,
            "--content-type", args.login_content_type]))

    results = []
    try:
        for i, (technique, subargs) in enumerate(tests, 1):
            label = technique + (" (login flood)" if subargs[0] == "post-flood" else "")
            print("\n--- [{}/{}] {} ---".format(i, len(tests), label))
            sub_dir = run_root / "{:02d}_{}".format(i, technique)
            sub_log = run_root / "{:02d}_{}.log".format(i, technique)
            t0 = time.monotonic()
            rc = run_subtest(subargs + common, env, sub_log, sub_dir)
            elapsed = round(time.monotonic() - t0, 1)
            jsonl = find_jsonl(sub_dir, technique)
            verdict = parse_jsonl_verdict(jsonl) if jsonl else \
                      {"verdict": "NO DATA", "probes": 0, "failed": 0, "ratio": 0,
                       "max_latency": 0, "notes": "subprocess rc={}".format(rc)}
            verdict["label"] = label
            verdict["elapsed_s"] = elapsed
            verdict["exit_code"] = rc
            verdict["jsonl"] = str(jsonl) if jsonl else None
            results.append(verdict)
            print("Result: {} (probes={}, failed={}, max_latency={}s)".format(
                verdict["verdict"], verdict["probes"],
                verdict["failed"], verdict["max_latency"]))
            if i < len(tests) and args.cool_down > 0:
                print("Cooling down {}s...".format(args.cool_down))
                time.sleep(args.cool_down)
    except KeyboardInterrupt:
        print("\nInterrupted. Writing partial summary.")

    # --- Summary ---
    with open(str(summary_md), "w") as f:
        f.write("# L7 DoS auto-test summary\n\n")
        f.write("- Target: `{}:{}`{}\n".format(
            args.host, args.port, " (TLS)" if args.tls else ""))
        f.write("- Run ID: `{}`\n".format(run_id))
        f.write("- Per-test duration: {}s, cool-down: {}s\n".format(
            args.per_test_duration, args.cool_down))
        f.write("\n## Pre-flight\n\n```\n{}\n```\n".format(pf_text))
        f.write("\n## Results\n\n")
        f.write("| # | Test | Verdict | Probes (failed/total) | Max probe latency | Exit |\n")
        f.write("|---|------|---------|-----------------------|-------------------|------|\n")
        for i, r in enumerate(results, 1):
            f.write("| {} | {} | **{}** | {}/{} | {}s | {} |\n".format(
                i, r["label"], r["verdict"], r["failed"], r["probes"],
                r["max_latency"], r["exit_code"]))
        f.write("\n## Skipped (low value vs auth-gated target)\n\n")
        f.write("- `cache-bust`: 401/403 cheap to generate, often cached at edge.\n")
        f.write("- `payload` (algorithmic): auth middleware blocks parsing.\n")
        f.write("- `post-flood` against business endpoints: blocked by auth.\n")
        f.write("\n## Evidence files\n\n")
        for i, r in enumerate(results, 1):
            f.write("- `{:02d}_{}.log` + `{:02d}_{}/`\n".format(
                i, r["label"].split()[0], i, r["label"].split()[0]))

    print("\n=== Run complete ===")
    print("Summary: {}".format(summary_md))


if __name__ == "__main__":
    main()
