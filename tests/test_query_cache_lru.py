"""Regression tests for D1 — dnsmod._qcache had no size cap.

A long-running web process that scans many distinct domains grew _qcache
without bound. Each entry is small individually, but at ~10 rdtypes per
domain and no eviction, memory pressure builds indefinitely on a shared
server.

Fix: OrderedDict with LRU eviction. Cap is a module-level constant so
tests can pin it small without affecting production sizing.

TTL semantics (already covered by test_query_cache.py) must remain
unchanged — LRU eviction bounds *size*, not *freshness*.
"""
from __future__ import annotations

import time

import posture.dnsmod as dnsmod


def _clear():
    dnsmod._qcache.clear()


def test_qcache_has_a_maximum_size_constant():
    """The cap must be a named module-level constant so operators can
    tune it, and tests can shrink it without touching the fix."""
    assert hasattr(dnsmod, "_QCACHE_MAX")
    assert isinstance(dnsmod._QCACHE_MAX, int)
    assert dnsmod._QCACHE_MAX > 0


def test_qcache_evicts_oldest_when_full(monkeypatch):
    """Insert cap+1 entries; size must stay at cap and the FIRST-inserted
    entry (never touched again) must be gone."""
    _clear()
    monkeypatch.setattr(dnsmod, "_QCACHE_MAX", 4)

    def fake(domain, rdtype, nameservers=None):
        return {"ok": True, "records": [domain], "ttl": 300}

    monkeypatch.setattr(dnsmod, "_query_uncached", fake)
    for i in range(5):  # 5 > cap 4
        dnsmod.query(f"host{i}.example.com", "A")

    assert len(dnsmod._qcache) == 4
    # host0 was inserted first and never touched again → must be evicted
    assert ("host0.example.com", "A", None) not in dnsmod._qcache
    # host4 (most recent) must still be present
    assert ("host4.example.com", "A", None) in dnsmod._qcache


def test_qcache_touching_an_entry_marks_it_recently_used(monkeypatch):
    """LRU, not FIFO — a hit on an old entry must refresh its recency."""
    _clear()
    monkeypatch.setattr(dnsmod, "_QCACHE_MAX", 3)

    def fake(domain, rdtype, nameservers=None):
        return {"ok": True, "records": [domain], "ttl": 300}

    monkeypatch.setattr(dnsmod, "_query_uncached", fake)
    dnsmod.query("a.example.com", "A")  # oldest
    dnsmod.query("b.example.com", "A")
    dnsmod.query("c.example.com", "A")

    # Touch 'a' — it should now count as most-recently-used
    dnsmod.query("a.example.com", "A")

    # Insert one more; the LRU victim should now be 'b', not 'a'
    dnsmod.query("d.example.com", "A")

    assert ("a.example.com", "A", None) in dnsmod._qcache
    assert ("b.example.com", "A", None) not in dnsmod._qcache
    assert ("c.example.com", "A", None) in dnsmod._qcache
    assert ("d.example.com", "A", None) in dnsmod._qcache


def test_qcache_lru_does_not_break_ttl_semantics(monkeypatch):
    """D1 fix must not regress the N5 TTL behaviour: within TTL the
    entry serves from cache; past TTL it refetches."""
    _clear()
    calls = []

    def fake(domain, rdtype, nameservers=None):
        calls.append(rdtype)
        return {"ok": True, "records": ["203.0.113.1"], "ttl": 300}

    monkeypatch.setattr(dnsmod, "_query_uncached", fake)
    dnsmod.query("example.com", "A")
    dnsmod.query("example.com", "A")
    assert len(calls) == 1  # second call served from cache

    # Force expiry
    key = ("example.com", "A", None)
    res, _ = dnsmod._qcache[key]
    dnsmod._qcache[key] = (res, time.time() - 1)
    dnsmod.query("example.com", "A")
    assert len(calls) == 2, "expired entry must be refetched even under LRU"
