"""Regression tests for F4/P6 — web/server.RESULT_CACHE had no size cap.

A long-running web deployment that services many distinct domains grows
RESULT_CACHE without bound. Each entry pins a whole Job (its full event
list, including per-section findings) so growth is not trivial. Even
with the TTL sweep (entries expire after CACHE_TTL_SECONDS), an entry
that is inserted and never re-requested still occupies memory until its
TTL passes — a 5-minute window across a large fleet of scans is enough
to matter.

Fix: OrderedDict with LRU eviction, capped at a module-level constant so
operators can tune it and tests can shrink it. TTL semantics are
unchanged — LRU bounds *size*, not *freshness*.
"""
from __future__ import annotations

import time
from collections import OrderedDict

import web.server as server


def _clear():
    server.RESULT_CACHE.clear()


def _fake_job(domain: str) -> server.Job:
    """Build a completed Job stub — the LRU logic never touches the
    events / _wake / semaphore internals, so a bare Job suffices."""
    j = server.Job(check_id=f"id-{domain}", domain=domain, dkim_selectors=[])
    j.done = True
    return j


def test_result_cache_is_an_ordered_dict():
    """The container must preserve insertion order for LRU eviction.
    A plain dict happens to preserve order in CPython 3.7+, but only
    OrderedDict has the move_to_end API we need for touch-on-hit."""
    assert isinstance(server.RESULT_CACHE, OrderedDict), (
        "RESULT_CACHE must be an OrderedDict for LRU semantics; "
        f"got {type(server.RESULT_CACHE).__name__}"
    )


def test_result_cache_has_a_maximum_size_constant():
    """The cap must be a named module-level constant so operators can
    tune it, and tests can shrink it without touching the fix."""
    assert hasattr(server, "_RESULT_CACHE_MAX")
    assert isinstance(server._RESULT_CACHE_MAX, int)
    assert server._RESULT_CACHE_MAX > 0


def test_result_cache_evicts_oldest_when_full(monkeypatch):
    """Insert cap+1 entries via the same helper the worker uses; size
    must stay at cap and the FIRST-inserted entry (never touched
    again) must be gone."""
    _clear()
    monkeypatch.setattr(server, "_RESULT_CACHE_MAX", 4)
    expires = time.time() + 300
    for i in range(5):  # 5 > cap 4
        domain = f"host{i}.example.com"
        server._cache_result(_fake_job(domain), expires)

    assert len(server.RESULT_CACHE) == 4
    assert "host0.example.com" not in server.RESULT_CACHE
    assert "host4.example.com" in server.RESULT_CACHE


def test_result_cache_touching_an_entry_marks_it_recently_used(monkeypatch):
    """LRU, not FIFO — a cache hit on an existing entry must refresh
    its recency so it survives the next eviction sweep."""
    _clear()
    monkeypatch.setattr(server, "_RESULT_CACHE_MAX", 3)
    expires = time.time() + 300
    for name in ("a", "b", "c"):
        server._cache_result(_fake_job(f"{name}.example.com"), expires)

    # Touch 'a' via the read helper — must mark it most-recently-used
    got = server._cache_get("a.example.com")
    assert got is not None

    # Insert one more; LRU victim should now be 'b', not 'a'
    server._cache_result(_fake_job("d.example.com"), expires)

    assert "a.example.com" in server.RESULT_CACHE
    assert "b.example.com" not in server.RESULT_CACHE
    assert "c.example.com" in server.RESULT_CACHE
    assert "d.example.com" in server.RESULT_CACHE


def test_result_cache_get_returns_none_on_expiry(monkeypatch):
    """LRU must not regress the existing TTL behaviour: an entry past
    its expiry is treated as absent."""
    _clear()
    monkeypatch.setattr(server, "_RESULT_CACHE_MAX", 10)
    # Insert with an expiry already in the past
    server._cache_result(_fake_job("stale.example.com"), time.time() - 1)
    assert server._cache_get("stale.example.com") is None


def test_result_cache_get_returns_job_on_fresh_hit(monkeypatch):
    """Sanity: within TTL, _cache_get returns the stored Job."""
    _clear()
    monkeypatch.setattr(server, "_RESULT_CACHE_MAX", 10)
    job = _fake_job("fresh.example.com")
    server._cache_result(job, time.time() + 300)
    got = server._cache_get("fresh.example.com")
    assert got is job
