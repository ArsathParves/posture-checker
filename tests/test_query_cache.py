"""Regression tests for the TTL-aware DNS query cache (N5).

Previously _qcache was time-agnostic — the same lookup returned stale data
for the full process lifetime. Fix keys each entry on (value, expiry).
"""
from __future__ import annotations

import time
from unittest.mock import patch

import posture.dnsmod as dnsmod


def _clear_cache():
    dnsmod._qcache.clear()


def test_second_query_within_ttl_is_served_from_cache():
    _clear_cache()
    calls = []

    def fake(domain, rdtype, nameservers=None):
        calls.append((domain, rdtype))
        return {"ok": True, "records": ["203.0.113.1"], "ttl": 300}

    with patch.object(dnsmod, "_query_uncached", side_effect=fake):
        a = dnsmod.query("example.com", "A")
        b = dnsmod.query("example.com", "A")
    assert a is b or a == b
    assert len(calls) == 1  # second call served from cache


def test_expired_entry_is_refetched():
    _clear_cache()
    calls = []

    def fake(domain, rdtype, nameservers=None):
        calls.append((domain, rdtype))
        return {"ok": True, "records": ["203.0.113.1"], "ttl": 1}

    with patch.object(dnsmod, "_query_uncached", side_effect=fake):
        dnsmod.query("example.com", "A")
        # Force expiry by rewinding the stored timestamp
        key = ("example.com", "A", None)
        res, _ = dnsmod._qcache[key]
        dnsmod._qcache[key] = (res, time.time() - 1)
        dnsmod.query("example.com", "A")
    assert len(calls) == 2, "expired entry should be refetched"


def test_error_result_uses_short_ttl():
    """Errors cached with 60s TTL (shorter than successes) so transient DNS
    failures don't stick around."""
    _clear_cache()
    with patch.object(dnsmod, "_query_uncached",
                      return_value={"ok": False, "error": "TIMEOUT"}):
        dnsmod.query("example.com", "A")
    key = ("example.com", "A", None)
    _, expiry = dnsmod._qcache[key]
    # Cached, and expiry within ~60s window
    assert expiry - time.time() <= 65
    assert expiry - time.time() >= 55


def test_different_rdtypes_do_not_collide():
    _clear_cache()
    calls = []

    def fake(domain, rdtype, nameservers=None):
        calls.append(rdtype)
        return {"ok": True, "records": [], "ttl": 300}

    with patch.object(dnsmod, "_query_uncached", side_effect=fake):
        dnsmod.query("example.com", "A")
        dnsmod.query("example.com", "AAAA")
    assert calls == ["A", "AAAA"]
