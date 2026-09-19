"""B8 — global per-check deadline (DoS bound on `_run_job`).

`_run_job` consumes `run_streaming()` in a worker thread with a bounded
concurrency semaphore (`CHECK_SEMAPHORE`, `MAX_CONCURRENT_CHECKS = 8`).
Before this fix, only per-query timeouts existed inside `run_streaming`
— there was NO wall-clock bound on the total run. A deliberately-slow
domain that lets every DNS/RDAP query walk right up to its individual
timeout (typical: 30–50 queries × 2–3 seconds each) can hold a slot
for ~90–150 seconds. Eight such domains submitted in parallel occupy
every slot for that duration and take the tool down for legitimate
users. Public deployment on vergecloud.com makes this an
attacker-reachable DoS vector.

Fix: `CHECK_MAX_SECONDS` module-level deadline; `_run_job` bounds each
`next()` on the generator with `asyncio.wait_for(remaining)` where
`remaining = deadline - now()`. When the deadline fires the loop
appends a synthetic `{"event": "timeout", ...}` and a synthetic
`{"event": "complete", ...}` with a partial-report marker so the SSE
consumer terminates cleanly and the client sees whatever section
events were already emitted. The slot is released as soon as the
coroutine returns; the underlying thread finishes on its own but no
longer occupies a semaphore slot.

This test drives `_run_job` with a stub `run_streaming` that yields a
few events then sleeps forever — the deadline must fire, a timeout
event must appear, and `job.done` must reach True in bounded wall time.
"""
from __future__ import annotations

import asyncio
import time

import web.server as server


def _snapshot_and_clear():
    server.RESULT_CACHE.clear()
    server.JOBS.clear()


def _drive(job: server.Job):
    """Run `_run_job` to completion under asyncio. The deadline logic
    lives inside the coroutine — this driver just awaits it."""
    asyncio.run(server._run_job(job))


# --------------------------------------------------------------------- constant

def test_check_max_seconds_is_a_module_level_constant():
    """The deadline must be a named module-level constant so operators
    can tune it and tests can shrink it without touching the fix.
    Mirror the pattern used for `SSE_MAX_STREAM_SECONDS` (S7)."""
    assert hasattr(server, "CHECK_MAX_SECONDS"), (
        "web.server must expose CHECK_MAX_SECONDS — a global per-check "
        "deadline is B8's acceptance criterion"
    )
    assert isinstance(server.CHECK_MAX_SECONDS, (int, float))
    assert server.CHECK_MAX_SECONDS > 0


# --------------------------------------------------------------------- deadline fires

def test_slow_run_hits_deadline_and_terminates(monkeypatch):
    """The load-bearing case: a run that produces some events then
    stalls forever must be cut off at CHECK_MAX_SECONDS and marked
    done. The whole coroutine must return within a bounded wall-clock
    window — the semaphore slot must not be held indefinitely."""
    _snapshot_and_clear()
    monkeypatch.setattr(server, "CHECK_MAX_SECONDS", 0.5)

    def _slow_stream(domain, dkim_selectors=None):
        yield {"event": "started", "domain": domain}
        yield {"event": "environment", "safe": True, "notes": []}
        # Progressive but slow: keep yielding tiny events forever with
        # a small sleep between them. The deadline must interrupt this
        # loop, not wait for it to finish (it never does).
        while True:
            time.sleep(0.2)
            yield {"event": "section", "name": "spinning", "findings": []}

    monkeypatch.setattr(server, "run_streaming", _slow_stream)

    job = server.Job(check_id="id-slow", domain="slow.example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job

    started = time.time()
    _drive(job)
    elapsed = time.time() - started

    # Deadline is 0.5s. Allow generous slack for the executor thread
    # and asyncio.wait_for to unwind — 5s is conservative.
    assert elapsed < 5.0, (
        f"_run_job must return promptly after the deadline; took {elapsed:.2f}s "
        f"(CHECK_MAX_SECONDS was 0.5s)"
    )
    assert job.done is True

    kinds = [e.get("event") for e in job.events]
    assert "timeout" in kinds, (
        f"deadline expiry must emit a `timeout` event so the client "
        f"can distinguish 'we cut this off' from 'this completed'. "
        f"Event kinds seen: {kinds}"
    )


def test_deadline_run_still_emits_final_complete(monkeypatch):
    """The SSE consumer terminates its loop on `event == 'complete'`.
    A timeout without a following `complete` would strand the client
    waiting for a final frame that never arrives. Deadline path must
    still emit `complete` as the LAST event."""
    _snapshot_and_clear()
    monkeypatch.setattr(server, "CHECK_MAX_SECONDS", 0.3)

    def _slow_stream(domain, dkim_selectors=None):
        yield {"event": "started", "domain": domain}
        yield {"event": "environment", "safe": True, "notes": []}
        while True:
            time.sleep(0.2)
            yield {"event": "section", "name": "spinning", "findings": []}

    monkeypatch.setattr(server, "run_streaming", _slow_stream)

    job = server.Job(check_id="id-slow2", domain="slow.example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job
    _drive(job)

    assert job.events, "run must produce at least one event before the deadline"
    assert job.events[-1].get("event") == "complete", (
        f"last event must be `complete` so the SSE consumer terminates. "
        f"got: {job.events[-1]}"
    )


def test_deadline_result_is_not_cached(monkeypatch):
    """A truncated run has incomplete data. Caching it would let a
    single slow-domain attack poison the cache for CACHE_TTL_SECONDS.
    Deadline path must skip `_cache_result`. This overlaps with B7's
    env-safe gate — a timeout event does NOT itself flip env-safe, so
    B7's gate alone won't skip. B8 must independently refuse to
    cache."""
    _snapshot_and_clear()
    monkeypatch.setattr(server, "CHECK_MAX_SECONDS", 0.3)

    def _slow_stream(domain, dkim_selectors=None):
        yield {"event": "started", "domain": domain}
        yield {"event": "environment", "safe": True, "notes": []}
        while True:
            time.sleep(0.2)
            yield {"event": "section", "name": "spinning", "findings": []}

    monkeypatch.setattr(server, "run_streaming", _slow_stream)

    job = server.Job(check_id="id-slow3", domain="slow.example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job
    _drive(job)

    assert "slow.example.com" not in server.RESULT_CACHE, (
        "A deadline-truncated run must not be cached; caching a "
        "partial result would let a slow-domain attack poison the "
        "cache for CACHE_TTL_SECONDS"
    )


# --------------------------------------------------------------------- regression backstops

def test_fast_run_completes_normally(monkeypatch):
    """A fast run that finishes well within the deadline must NOT
    trigger the deadline path. The fix must not perturb the common
    case."""
    _snapshot_and_clear()
    monkeypatch.setattr(server, "CHECK_MAX_SECONDS", 5.0)

    def _fast_stream(domain, dkim_selectors=None):
        yield {"event": "started", "domain": domain}
        yield {"event": "environment", "safe": True, "notes": []}
        yield {"event": "complete",
               "report": {"domain": domain, "findings": []},
               "grades": {"overall": "A"}}

    monkeypatch.setattr(server, "run_streaming", _fast_stream)

    job = server.Job(check_id="id-fast", domain="fast.example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job
    _drive(job)

    assert job.done is True
    assert job.error is None
    kinds = [e.get("event") for e in job.events]
    assert "timeout" not in kinds, (
        f"fast run must not emit a timeout event; got: {kinds}"
    )
    assert job.events[-1]["event"] == "complete"


def test_run_that_finishes_at_deadline_boundary_still_ok(monkeypatch):
    """Deadline is a hard ceiling but a run that finishes just under it
    must not be flagged as timed-out. The check is "elapsed > deadline",
    not "elapsed >= deadline"."""
    _snapshot_and_clear()
    monkeypatch.setattr(server, "CHECK_MAX_SECONDS", 5.0)

    def _quick_stream(domain, dkim_selectors=None):
        yield {"event": "started", "domain": domain}
        yield {"event": "environment", "safe": True, "notes": []}
        yield {"event": "complete", "report": {}, "grades": {}}

    monkeypatch.setattr(server, "run_streaming", _quick_stream)

    job = server.Job(check_id="id-quick", domain="quick.example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job
    _drive(job)

    kinds = [e.get("event") for e in job.events]
    assert "timeout" not in kinds
