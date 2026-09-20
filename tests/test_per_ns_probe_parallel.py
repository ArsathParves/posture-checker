"""Regression tests for P4 — `dnsmod.probe_each_ns` iterated over
nameservers sequentially. On a domain with 6 slow-to-respond NSes,
that's 6 × TIMEOUT worst-case (up to 6 * 4s = 24s of wall time) which
dominates the tool's total runtime and — worse — makes the SSE
streamer's `Delegation` section feel hung.

Fix contract:
  - `probe_each_ns` submits SOA queries in parallel using a bounded
    `ThreadPoolExecutor`. Bound comes from the same rationale as
    `_PARENT_QUERY_MAX` — don't over-fan on TLDs with 13 anycast
    nodes.
  - Return-shape is byte-identical to the sequential version: same
    keys, same value semantics, same error strings. Downstream check
    code, JSON output, and cached fixtures must not need to change.
  - Every NS in `ns_map` still appears in the result (no in-flight
    drops). Order of keys does not matter — callers already treat
    the return as a mapping, not a list.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import dns.exception
import dns.flags
import dns.rdatatype

import posture.dnsmod as dnsmod


class _FakeSOA:
    """Minimal SOA response stand-in returned by the udp fake."""

    def __init__(self, serial: int, ip: str):
        self.flags = dns.flags.AA
        self._serial = serial
        self.ip = ip

        class _RR:
            def __init__(s, serial):
                s.serial = serial

        class _RRSet:
            def __init__(s, serial):
                s.rdtype = dns.rdatatype.SOA
                s._rr = _RR(serial)

            def __getitem__(s, idx):
                return s._rr

            def __iter__(s):
                yield s._rr

        self.answer = [_RRSet(serial)]


def _slow_udp_fake(delay: float):
    """Every UDP query sleeps `delay` seconds before returning a fake
    SOA response — lets us measure whether the six-NS probe ran in
    parallel (~delay total) or serially (~6*delay total)."""
    def fake(msg, ip, timeout=None):
        time.sleep(delay)
        return _FakeSOA(serial=2026010101, ip=ip)
    return fake


def _six_ns_map() -> dict:
    return {
        f"ns{i}.example.": {"ipv4": [f"192.0.2.{i}"], "ipv6": []}
        for i in range(1, 7)
    }


def test_probe_each_ns_runs_in_parallel():
    """Six NSes with a 0.4s per-query stall must complete in well under
    the sequential lower bound (6 * 0.4 = 2.4s). Parallel execution
    should finish in a bit more than 0.4s; leave headroom for CI
    jitter but keep the bar decisively below sequential."""
    ns_map = _six_ns_map()

    with patch("dns.query.udp", side_effect=_slow_udp_fake(0.4)):
        t0 = time.perf_counter()
        out = dnsmod.probe_each_ns("example.com", ns_map)
        elapsed = time.perf_counter() - t0

    assert set(out.keys()) == set(ns_map.keys()), (
        f"every NS must appear in results. Got {out.keys()!r}"
    )
    assert elapsed < 1.5, (
        f"expected parallel execution (~0.4s per query, 6 queries "
        f"concurrent → ~0.5s wall), got {elapsed:.2f}s. Sequential "
        f"lower bound is 2.4s."
    )
    for host, r in out.items():
        assert r["reachable"] is True
        assert r["serial"] == 2026010101


def test_return_shape_unchanged_for_success():
    """Regression pin on the shape of the result dict. A parallel
    rewrite that dropped `authoritative` or renamed `rtt_ms` would
    silently break the emit layer in checks.py."""
    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}

    with patch("dns.query.udp", side_effect=_slow_udp_fake(0.01)):
        out = dnsmod.probe_each_ns("example.com", ns_map)

    r = out["ns1.example."]
    assert set(r.keys()) >= {"reachable", "authoritative", "serial",
                             "rtt_ms", "ip", "error"}
    assert r["reachable"] is True
    assert r["authoritative"] is True
    assert r["ip"] == "192.0.2.1"
    assert r["error"] is None
    assert isinstance(r["rtt_ms"], (int, float))


def test_timeout_still_bucketed_as_TIMEOUT():
    """Regression pin: a `dns.exception.Timeout` from any single NS
    still produces `error: "TIMEOUT"` — the parallel wrapper must not
    swallow, re-wrap, or rename."""
    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}

    def fake(msg, ip, timeout=None):
        raise dns.exception.Timeout()

    with patch("dns.query.udp", side_effect=fake):
        out = dnsmod.probe_each_ns("example.com", ns_map)

    r = out["ns1.example."]
    assert r["reachable"] is False
    assert r["error"] == "TIMEOUT"
    assert r["ip"] == "192.0.2.1"


def test_no_address_ns_still_reported():
    """An NS with neither IPv4 nor IPv6 addresses is unprobeable but
    must still appear in results with `reachable=False`,
    `error="no_address"`. Regression guard on the loop that used to
    `continue` — the parallel path must preserve this branch."""
    ns_map = {
        "ns1.example.": {"ipv4": [], "ipv6": []},
        "ns2.example.": {"ipv4": ["192.0.2.2"], "ipv6": []},
    }

    with patch("dns.query.udp", side_effect=_slow_udp_fake(0.01)):
        out = dnsmod.probe_each_ns("example.com", ns_map)

    assert out["ns1.example."]["reachable"] is False
    assert out["ns1.example."]["error"] == "no_address"
    assert out["ns2.example."]["reachable"] is True


def test_ipv6_fallback_still_used_when_no_ipv4():
    """E6 regression pin: an AAAA-only NS falls back to its IPv6
    literal for the probe. The parallel rewrite must not regress the
    v4→v6 fallback path (which was itself an earlier fix)."""
    ns_map = {"ns1.example.": {"ipv4": [], "ipv6": ["2001:db8::53"]}}
    seen = []

    def fake(msg, ip, timeout=None):
        seen.append(ip)
        return _FakeSOA(serial=1, ip=ip)

    with patch("dns.query.udp", side_effect=fake):
        out = dnsmod.probe_each_ns("example.com", ns_map)

    assert seen == ["2001:db8::53"]
    assert out["ns1.example."]["reachable"] is True
    assert out["ns1.example."]["ip"] == "2001:db8::53"
