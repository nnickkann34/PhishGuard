"""2.7 Denial of Service (Advanced defence): resource-exhaustion via expensive requests.

Attack
------
The /api/check/batch endpoint runs the model once per URL in the batch. A single
request carrying thousands of URLs is therefore an "expensive request": it ties
up a worker for a long time. An attacker sends a burst of these to exhaust the
server's capacity, so that ordinary single-URL checks from real users hang or
fail.

Defence (InferenceGuard)
------------------------
All model inference runs in a bounded thread pool fronted by an asyncio
semaphore (capacity = workers + queue). When every slot is taken the server
rejects *immediately* with 503 + Retry-After instead of queueing without limit,
and any single job that runs past the timeout is abandoned with a 503. The event
loop is never blocked, so health checks and quick requests stay responsive even
while the flood is in progress.

Measurement
-----------
With the defence OFF (PG_DOS_PROTECTION=false) inference runs inline on the event
loop, so a big batch blocks everything. With it ON, we measure that:
  * legitimate single checks still return quickly during the flood, and
  * the excess load is shed as 503s rather than silently piling up.
"""
from __future__ import annotations

import statistics
import threading
import time
import urllib.error
import urllib.request
import json

from _harness import running_api, rule

PHISH = "http://paypal.com.secure-login.xyz/verify/account/update/confirm"


def _post(base: str, path: str, payload: dict, timeout: float):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{base}{path}", data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, time.perf_counter() - start, None
    except urllib.error.HTTPError as e:
        return e.status, time.perf_counter() - start, e.headers.get("Retry-After")
    except Exception as e:  # timeout / connection dropped
        return None, time.perf_counter() - start, repr(e)


def _flood(base: str, n_requests: int, batch_size: int, timeout: float):
    """Fire n_requests expensive batches concurrently; return their outcomes."""
    results = []
    lock = threading.Lock()
    urls = [f"{PHISH}?x={i}" for i in range(batch_size)]

    def worker():
        out = _post(base, "/api/check/batch", {"urls": urls}, timeout)
        with lock:
            results.append(out)

    threads = [threading.Thread(target=worker) for _ in range(n_requests)]
    for t in threads:
        t.start()
    return threads, results


def _probe_latency(base: str, samples: int, timeout: float):
    """Measure single-check latency (what a real user experiences)."""
    lats, fails = [], 0
    for _ in range(samples):
        status, dt, _ = _post(base, "/api/check", {"url": PHISH}, timeout)
        if status == 200:
            lats.append(dt)
        else:
            fails += 1
        time.sleep(0.05)
    return lats, fails


def run_scenario(label: str, env: dict, batch_size: int, n_flood: int):
    with running_api(label, env) as base:
        # Warm the model so the first call's lazy work doesn't skew timings.
        _post(base, "/api/check", {"url": PHISH}, timeout=30)

        # Baseline: how fast is a single check with no load?
        base_lat, _ = _probe_latency(base, 5, timeout=10)
        baseline = statistics.median(base_lat) if base_lat else float("nan")

        # Start the flood, then immediately probe user-facing latency.
        threads, flood_results = _flood(base, n_flood, batch_size, timeout=20)
        probe_lats, probe_fails = _probe_latency(base, 8, timeout=8)
        for t in threads:
            t.join()

        statuses = [s for s, _, _ in flood_results]
        busy = sum(1 for s in statuses if s == 503)
        ok = sum(1 for s in statuses if s == 200)
        dropped = sum(1 for s in statuses if s is None)
        under_load = statistics.median(probe_lats) if probe_lats else float("nan")

        print(f"\n  Results for: {label}")
        print(f"    batch size (URLs per request): {batch_size}")
        print(f"    concurrent expensive requests: {n_flood}")
        print(f"    single-check median latency, idle:        {baseline*1000:7.0f} ms")
        print(f"    single-check median latency, under flood: {under_load*1000:7.0f} ms"
              if probe_lats else "    single-check under flood: ALL FAILED/HUNG")
        print(f"    user checks that failed during flood:     {probe_fails} / 8")
        print(f"    flood requests -> 200 ok: {ok}   503 shed: {busy}   hung/dropped: {dropped}")
        return {
            "baseline": baseline, "under_load": under_load,
            "probe_fails": probe_fails, "busy": busy, "ok": ok, "dropped": dropped,
        }


def main():
    rule("2.7  DENIAL OF SERVICE  —  expensive-request flood")
    print("Scenario: an attacker sends a burst of large batch requests while a\n"
          "real user tries to check single links at the same time.")

    vuln = run_scenario(
        "DEFENCE OFF (vulnerable)",
        {"PG_DOS_PROTECTION": "false", "PG_MAX_BATCH_URLS": "20000", "PG_MAX_BODY_BYTES": "80000000"},
        batch_size=6000, n_flood=6,
    )
    safe = run_scenario(
        "DEFENCE ON (InferenceGuard)",
        {"PG_DOS_PROTECTION": "true", "PG_INFERENCE_WORKERS": "2", "PG_INFERENCE_QUEUE": "4",
         "PG_INFERENCE_TIMEOUT_SECONDS": "5", "PG_MAX_BATCH_URLS": "50"},
        batch_size=50, n_flood=20,
    )

    rule("SUMMARY")
    print(f"{'':28}{'DEFENCE OFF':>16}{'DEFENCE ON':>16}")
    def row(name, a, b, fmt):
        print(f"{name:28}{fmt(a):>16}{fmt(b):>16}")
    ms = lambda x: ("hung" if x != x else f"{x*1000:.0f} ms")  # noqa: E731
    row("user latency (idle)", vuln["baseline"], safe["baseline"], ms)
    row("user latency (under flood)", vuln["under_load"], safe["under_load"], ms)
    row("user checks failed /8", vuln["probe_fails"], safe["probe_fails"], str)
    row("attack reqs shed (503)", vuln["busy"], safe["busy"], str)
    print("\nReading: with the defence OFF the attacker's batches run inline and the\n"
          "real user's checks stall (or fail). With InferenceGuard ON, user latency\n"
          "stays close to idle and the excess attacker load is rejected with 503s.")


if __name__ == "__main__":
    main()
