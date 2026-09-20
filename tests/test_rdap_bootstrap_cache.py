"""Regression tests for P5 — the audit claimed `rdap_endpoint_for`
re-fetched IANA's `data.iana.org/rdap/dns.json` on every call, making
the right-to-left label walk N × HTTP-latency on a domain with many
labels and turning every scan into a bootstrap fetch.

Honest correction: at the version pinned in this test the bootstrap
IS process-cached with a 24-hour TTL in `_bootstrap_cache["dns"]`
(and the IP-bootstrap path in `_ip_bootstrap["ipv4"]`). The audit was
stale. These tests exist to lock the caching in — the failure mode
they guard against (a well-intentioned refactor that removes the
cache and turns every scan into a 20-second `requests.get`) is
exactly the kind of regression the file is supposed to prevent.

Contract pinned:
  - The first `_load_bootstrap()` call issues one HTTPS GET.
  - Subsequent calls within the TTL return the cached mapping without
    calling `requests.get` again.
  - Expiry: when the cached expiry timestamp is in the past, the next
    call re-fetches (once).
  - `rdap_endpoint_for` reuses the same cache — walking multi-label
    domains (`example.co.in`) does not multiply fetches.
"""
from __future__ import annotations

import time
from unittest.mock import patch

import posture.core as core


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


_STUB_BOOTSTRAP = {
    "services": [
        [["com"], ["https://rdap.verisign.com/com/v1/"]],
        [["in"], ["https://rdap.registry.in/"]],
        [["net"], ["https://rdap.verisign.com/net/v1/"]],
    ]
}


def _clear_cache():
    core._bootstrap_cache.clear()


def test_first_call_fetches_then_subsequent_calls_use_cache():
    """One fetch on cold cache; subsequent lookups within TTL return
    from `_bootstrap_cache["dns"]` without issuing a second GET."""
    _clear_cache()
    calls = []

    def fake_get(url, headers=None, timeout=None):
        calls.append(url)
        return _FakeResp(_STUB_BOOTSTRAP)

    with patch("posture.core.requests.get", side_effect=fake_get):
        m1 = core._load_bootstrap()
        m2 = core._load_bootstrap()
        m3 = core._load_bootstrap()

    assert len(calls) == 1, (
        f"expected 1 bootstrap fetch across 3 calls; got {len(calls)}: "
        f"{calls}"
    )
    assert m1 is m2 is m3
    assert m1["com"].endswith("/")


def test_cache_expiry_triggers_refetch():
    """When the cached expiry timestamp has passed, the next call
    re-fetches once (and re-primes the cache)."""
    _clear_cache()
    calls = []

    def fake_get(url, headers=None, timeout=None):
        calls.append(url)
        return _FakeResp(_STUB_BOOTSTRAP)

    with patch("posture.core.requests.get", side_effect=fake_get):
        core._load_bootstrap()
        assert len(calls) == 1
        # Force expiry.
        data, _ = core._bootstrap_cache["dns"]
        core._bootstrap_cache["dns"] = (data, time.time() - 1)
        core._load_bootstrap()
        assert len(calls) == 2, (
            f"expected refetch after expiry; got {len(calls)} fetches"
        )
        # Still within the fresh 24h window now.
        core._load_bootstrap()
        assert len(calls) == 2


def test_rdap_endpoint_for_uses_cache_across_multi_label_walk():
    """A multi-label walk (`example.co.in`) exercises `_load_bootstrap`
    from inside `rdap_endpoint_for`. Even when the tool queries the
    same bootstrap for many domain checks in a session, only one
    fetch should ever hit the wire per TTL window."""
    _clear_cache()
    calls = []

    def fake_get(url, headers=None, timeout=None):
        calls.append(url)
        return _FakeResp(_STUB_BOOTSTRAP)

    with patch("posture.core.requests.get", side_effect=fake_get):
        # Simulate a session running 20 lookups. Even one fetch is fine;
        # >1 would mean the cache is broken.
        for host in ["example.com", "a.co.in", "b.co.in", "c.in",
                     "d.net", "e.co.in", "f.com"] * 3:
            core.rdap_endpoint_for(host)

    assert len(calls) == 1, (
        f"bootstrap must be fetched once per session; got {len(calls)} "
        f"fetches: {calls}"
    )


def test_ttl_is_24_hours():
    """Pin the TTL constant so a refactor lowering it (e.g., to 60s
    'for testing') would trip a failure. IANA changes the bootstrap
    file rarely; 24h matches what the file itself advertises via
    `publication`."""
    _clear_cache()

    def fake_get(url, headers=None, timeout=None):
        return _FakeResp(_STUB_BOOTSTRAP)

    with patch("posture.core.requests.get", side_effect=fake_get):
        t_before = time.time()
        core._load_bootstrap()
        _, expiry = core._bootstrap_cache["dns"]

    seconds = expiry - t_before
    # 24h = 86400s; allow a modest 60s jitter for slow CI.
    assert 86340 < seconds < 86460, (
        f"expected ~24h TTL, got {seconds:.0f}s. Bootstrap TTL is a "
        f"correctness/perf hinge — do not reduce it silently."
    )
