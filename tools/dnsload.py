#!/usr/bin/env python3
"""Small DNS load tester for the ESP32 AdBlocker. Standard library only.

  python3 tools/dnsload.py 192.168.0.254 burst blocked
  python3 tools/dnsload.py 192.168.0.254 rate cached --rates 100,200,400

It sends real queries to a live DNS server: run it on your own network only.

  burst   N queries sent back to back, as fast as this computer can send
  rate    a steady rate for a few seconds

Each query has its own ID; a reply counts only if its ID matches and it
arrives within the timeout. Reports sent, answered, lost and latency
percentiles.
"""
import argparse
import random
import select
import socket
import struct
import time


def make_query(qid, name, qtype=1):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


def names_for(kind, n):
    if kind == "blocked":
        pool = ["analytics.112.press", "googleads.g.doubleclick.net", "app-measurement.com",
                "pagead2.googlesyndication.com", "google-analytics.com"]
        return [pool[i % len(pool)] for i in range(n)]
    if kind == "cached":
        pool = ["example.com", "github.com", "wikipedia.org", "apple.com", "cloudflare.com"]
        return [pool[i % len(pool)] for i in range(n)]
    # uncached: a fresh name every time, so every query goes upstream (NXDOMAIN)
    tag = random.randrange(1 << 30)
    return ["lt%x-%d.example.com" % (tag, i) for i in range(n)]


def run(server, names, rate, timeout):
    """rate=None means send as fast as possible (a burst)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.setblocking(False)
    pending = {}
    latencies = []
    ids = random.sample(range(1, 65536), len(names))
    start = time.monotonic()
    i = 0
    last_send = start

    def drain():
        while True:
            try:
                data = s.recv(4096)
            except BlockingIOError:
                return
            if len(data) < 12:
                continue
            qid = struct.unpack(">H", data[:2])[0]
            t0 = pending.pop(qid, None)
            if t0 is not None:
                latencies.append((time.monotonic() - t0) * 1000)

    while i < len(names):
        now = time.monotonic()
        due = len(names) if rate is None else min(len(names), int((now - start) * rate) + 1)
        while i < due:
            try:
                s.sendto(make_query(ids[i], names[i]), (server, 53))
                pending[ids[i]] = time.monotonic()
            except BlockingIOError:
                break   # Mac's own send buffer full; try again next pass
            i += 1
        last_send = time.monotonic()
        r, _, _ = select.select([s], [], [], 0.001)
        if r:
            drain()

    end = last_send + timeout
    while pending and time.monotonic() < end:
        r, _, _ = select.select([s], [], [], 0.05)
        if r:
            drain()
    duration = last_send - start
    s.close()

    latencies.sort()
    sent = len(names)
    got = len(latencies)
    pct = lambda p: latencies[min(got - 1, int(p * got))] if got else float("nan")
    return {
        "sent": sent,
        "answered": got,
        "lost_pct": 100.0 * (sent - got) / sent,
        "send_qps": sent / duration if duration > 0 else float("inf"),
        "p50": pct(0.50),
        "p95": pct(0.95),
        "p99": pct(0.99),
        "max": latencies[-1] if got else float("nan"),
    }


def show(label, r):
    print("%-28s sent %5d  answered %5d  lost %5.1f%%  at %6.0f q/s   ms p50 %6.1f  p95 %6.1f  p99 %6.1f  max %6.1f"
          % (label, r["sent"], r["answered"], r["lost_pct"], r["send_qps"], r["p50"], r["p95"], r["p99"], r["max"]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("server")
    ap.add_argument("mode", choices=["burst", "rate"])
    ap.add_argument("kind", choices=["blocked", "cached", "uncached"])
    ap.add_argument("--sizes", default="10,20,50,100,200")
    ap.add_argument("--rates", default="50,100,200,400")
    ap.add_argument("--seconds", type=float, default=5)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--stop-loss", type=float, default=10.0, help="stop stepping up past this loss %%")
    a = ap.parse_args()

    if a.kind == "cached":   # warm the cache first
        run(a.server, names_for("cached", 5), None, 2.0)

    if a.mode == "burst":
        for n in [int(x) for x in a.sizes.split(",")]:
            r = run(a.server, names_for(a.kind, n), None, a.timeout)
            show("%s burst of %d" % (a.kind, n), r)
            time.sleep(1.5)
            if r["lost_pct"] > a.stop_loss:
                break
    else:
        for q in [int(x) for x in a.rates.split(",")]:
            r = run(a.server, names_for(a.kind, int(q * a.seconds)), q, a.timeout)
            show("%s at %d q/s" % (a.kind, q), r)
            time.sleep(2)
            if r["lost_pct"] > a.stop_loss:
                break


if __name__ == "__main__":
    main()
