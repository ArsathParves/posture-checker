"""B7 — cache poisoning across users under a flipping environment.

`RESULT_CACHE` is process-wide and shared across every visitor. Before
this fix, `_run_job` stored the finished Job into the cache
unconditionally (as long as `job.error` was None), so a run computed
while the network path was degraded — TXT truncation not honoured, TCP/53
blocked, DNS interception in place — was served for the next
`CACHE_TTL_SECONDS` (5 minutes) to *every* subsequent request for the
same domain, even after the network path recovered.

The concrete failure mode: a check on `cloudflare.com` computed during a
transient corp-VPN interception reports SPF absent (per CLAUDE.md rule 1
this is already the "unretrievable" state, not "absent" — but on the
absent path the tool would emit FAIL). That FAIL is cached and returned
to a user on a clean network who sees a confident wrong answer with no
signal that it was tainted.

RFC-side: caching is a presentation layer; findings must reflect the
current environment state. There is no reasonable way to serve a
degraded-run finding as fresh to a different user.

Fix (surgical): before `_cache_result(job, …)` in `_run_job`, inspect
`job.events` for `{"event": "environment", …}`. Cache ONLY when the
event is present AND `safe` is True. Missing event and `safe=False` are
both treated as "do not cache" — conservative default is correctness.
"""
from __future__ import annotations

import asyncio
import time

import web.server as server


def _snapshot_and_clear():
    """Clear the module-level cache and JOBS dict before each test.
    Global state — no test should inherit or leak entries."""
    server.RESULT_CACHE.clear()
    server.JOBS.clear()


def _make_stream(events: list[dict]):
    """Return a run_streaming stand-in that yields the supplied events
    in order. Matches the real generator's contract: a plain iterable
    of dicts terminated by a `complete` event."""
    def _fake(domain, dkim_selectors=None):
        for ev in events:
            yield ev
    return _fake


def _drive(job: server.Job):
    """Run `_run_job` to completion synchronously. `_run_job` is an
    async coroutine that awaits a run_in_executor call on a next() over
    the (synchronous) generator; asyncio.run gives us a fresh loop and
    the executor drives the generator to exhaustion."""
    asyncio.run(server._run_job(job))


# --------------------------------------------------------------------- negative

def test_degraded_environment_result_is_not_cached(monkeypatch):
    """The load-bearing case: when the environment event says
    `safe=False`, the run's result MUST NOT enter the cache. The next
    caller for this domain must receive a fresh run against the current
    network state, not the previous degraded snapshot."""
    _snapshot_and_clear()

    fake_events = [
        {"event": "started", "domain": "example.com", "punycode": "example.com",
         "checked_at": "2026-09-19T00:00:00Z"},
        {"event": "environment", "safe": False,
         "notes": ["TCP/53 blocked", "DNS interception suspected"]},
        {"event": "complete", "report": {}, "grades": {}},
    ]
    monkeypatch.setattr(server, "run_streaming", _make_stream(fake_events))

    job = server.Job(check_id="id-degraded", domain="example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job
    _drive(job)

    assert job.done is True
    assert job.error is None, (
        "The check itself completed without exception — the guard "
        "should have skipped caching, not marked the run failed"
    )
    assert "example.com" not in server.RESULT_CACHE, (
        "Degraded-environment result must not enter RESULT_CACHE; "
        f"cache keys: {list(server.RESULT_CACHE.keys())}"
    )


def test_missing_environment_event_is_not_cached(monkeypatch):
    """Defence-in-depth: if for any reason the environment event is
    absent from `job.events` (future refactor, malformed stream, …),
    the safe default is to NOT cache. A positive `safe=True` signal is
    the only thing that unlocks caching."""
    _snapshot_and_clear()

    fake_events = [
        {"event": "started", "domain": "example.com", "punycode": "example.com",
         "checked_at": "2026-09-19T00:00:00Z"},
        # no environment event
        {"event": "complete", "report": {}, "grades": {}},
    ]
    monkeypatch.setattr(server, "run_streaming", _make_stream(fake_events))

    job = server.Job(check_id="id-missing-env", domain="example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job
    _drive(job)

    assert "example.com" not in server.RESULT_CACHE, (
        "Result without an environment=safe=True marker must not be "
        "cached; conservative default is correctness"
    )


# --------------------------------------------------------------------- positive

def test_healthy_environment_result_is_cached(monkeypatch):
    """Regression backstop: when `safe=True`, caching MUST still
    happen. B7's fix must not disable the cache for the common case
    — only gate it on env health."""
    _snapshot_and_clear()

    fake_events = [
        {"event": "started", "domain": "example.com", "punycode": "example.com",
         "checked_at": "2026-09-19T00:00:00Z"},
        {"event": "environment", "safe": True, "notes": []},
        {"event": "complete", "report": {}, "grades": {}},
    ]
    monkeypatch.setattr(server, "run_streaming", _make_stream(fake_events))

    job = server.Job(check_id="id-healthy", domain="example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job
    _drive(job)

    assert "example.com" in server.RESULT_CACHE, (
        f"Healthy-environment result must be cached; cache keys: "
        f"{list(server.RESULT_CACHE.keys())}"
    )
    cached_job, expires_at = server.RESULT_CACHE["example.com"]
    assert cached_job is job
    assert expires_at > time.time(), "cached entry must have a future expiry"


def test_cached_healthy_result_survives_ttl_window(monkeypatch):
    """The healthy cache path must set an expiry `CACHE_TTL_SECONDS`
    ahead. Not testing exact expiry (time.time() drift) — testing that
    the entry is retrievable via _cache_get immediately after caching,
    which is the observable contract."""
    _snapshot_and_clear()

    fake_events = [
        {"event": "started", "domain": "example.com", "punycode": "example.com",
         "checked_at": "2026-09-19T00:00:00Z"},
        {"event": "environment", "safe": True, "notes": []},
        {"event": "complete", "report": {}, "grades": {}},
    ]
    monkeypatch.setattr(server, "run_streaming", _make_stream(fake_events))

    job = server.Job(check_id="id-fresh", domain="example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job
    _drive(job)

    got = server._cache_get("example.com")
    assert got is job


# --------------------------------------------------------------------- error path

def test_errored_run_still_not_cached_regardless_of_env(monkeypatch):
    """Rule-1 sanity: an errored run (exception in the check) is
    already excluded from the cache by the pre-existing `if not
    job.error:` gate. The B7 fix must NOT accidentally start caching
    error runs by inverting the gate. This is a backstop against a
    refactor that consolidates the two conditions incorrectly."""
    _snapshot_and_clear()

    def _raising(domain, dkim_selectors=None):
        yield {"event": "started", "domain": domain, "punycode": domain,
               "checked_at": "2026-09-19T00:00:00Z"}
        yield {"event": "environment", "safe": True, "notes": []}
        raise RuntimeError("boom")

    monkeypatch.setattr(server, "run_streaming", _raising)

    job = server.Job(check_id="id-error", domain="example.com",
                     dkim_selectors=[])
    server.JOBS[job.check_id] = job
    _drive(job)

    assert job.error is not None, "test setup should surface the RuntimeError"
    assert "example.com" not in server.RESULT_CACHE, (
        "Errored run must not be cached even when env event says safe=True"
    )
