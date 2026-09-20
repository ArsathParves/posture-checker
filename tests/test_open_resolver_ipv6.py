"""Regression tests for FN5 — the open-resolver check silently skipped
IPv6-only nameservers and never probed dual-stack NSes over v6.

Two false-PASS classes the old check missed:

  (1) IPv6-only NS: v0.5's `open_resolver_check` did
      `ip = (ips.get("ipv4") or [None])[0]` and, on absent v4, emitted
      `{"tested": False, "reason": "no A record"}`. The v6 stack of
      the same NS could serve open recursion to the whole IPv6
      internet and the tool would report clean.

  (2) Dual-stack NS with divergent ACL: v4 gateway blocks external
      recursion but the v6 gateway ACL was never wired up (a real,
      common misconfiguration during v6 rollout). Probing only v4
      declares PASS while v6 leaks.

Fix contract:
  - Every nameserver with an IPv6 address is probed over v6.
  - A dual-stack NS is probed over BOTH families and the worst-case
    wins for `open` detection.
  - IPv6-only NSes are marked `tested=True`, not silently skipped
    with a "no A record" reason (that message was misleading: the NS
    had a v6 address; the tool just refused to use it).
  - IPv4-only NSes are still probed (regression guard for the pre-
    FN5 dual-stack case).
"""
from __future__ import annotations

from unittest.mock import patch

import dns.flags
import dns.rcode
import dns.rrset

import posture.dnsmod as dnsmod


def _mock_resp(ra: bool, answered: bool, rcode: int = dns.rcode.NOERROR):
    class R:
        pass
    r = R()
    r.flags = dns.flags.RA if ra else 0
    r.answer = []
    if answered:
        r.answer = [dns.rrset.from_text_list(
            "www.google.com.", 60, "IN", "A", ["1.2.3.4"])]
    r.rcode = lambda: rcode
    return r


def _ip_family(ip: str) -> str:
    return "v6" if ":" in ip else "v4"


def test_ipv6_only_ns_is_probed_not_skipped():
    """An NS that publishes only AAAA (no A) must still be tested for
    open recursion. Silently skipping it — as v0.5 did with the
    misleading "no A record" reason — leaves a v6-open resolver
    undetected."""
    ns_map = {"ns1.example.": {"ipv4": [], "ipv6": ["2001:db8::53"]}}
    calls = []

    def udp_fake(msg, ip, timeout=None):
        calls.append(ip)
        return _mock_resp(ra=False, answered=False)

    with patch("dns.query.udp", side_effect=udp_fake):
        out = dnsmod.open_resolver_check(ns_map)

    per = out["per_ns"]["ns1.example."]
    assert per.get("tested") is True, (
        f"IPv6-only NS must be tested, not silently skipped. Got {per!r}"
    )
    assert any(":" in ip for ip in calls), (
        f"expected at least one v6 probe, but all probes went to: {calls}"
    )


def test_dual_stack_ns_is_probed_over_both_families():
    """When an NS publishes both A and AAAA, both address families are
    probed. Address-family-specific ACLs are a real misconfiguration
    class — probing only v4 misses a v6 leak."""
    ns_map = {"ns1.example.": {
        "ipv4": ["192.0.2.1"],
        "ipv6": ["2001:db8::53"],
    }}
    calls = []

    def udp_fake(msg, ip, timeout=None):
        calls.append(ip)
        return _mock_resp(ra=False, answered=False)

    with patch("dns.query.udp", side_effect=udp_fake):
        dnsmod.open_resolver_check(ns_map)

    v4_calls = [ip for ip in calls if ":" not in ip]
    v6_calls = [ip for ip in calls if ":" in ip]
    assert v4_calls, f"expected ≥1 v4 probe, got calls={calls}"
    assert v6_calls, (
        f"expected ≥1 v6 probe on a dual-stack NS (FN5). Got calls={calls}"
    )


def test_v6_open_recursion_flagged_when_v4_refuses():
    """The load-bearing FN5 case: dual-stack NS where v4 refuses
    recursion (RA=0) but v6 serves it (RA=1, answered). Old check
    only saw the clean v4 side and declared PASS. New behaviour must
    surface `open=True`."""
    ns_map = {"ns1.example.": {
        "ipv4": ["192.0.2.1"],
        "ipv6": ["2001:db8::53"],
    }}

    def udp_fake(msg, ip, timeout=None):
        if ":" in ip:
            return _mock_resp(ra=True, answered=True)
        return _mock_resp(ra=False, answered=False)

    with patch("dns.query.udp", side_effect=udp_fake):
        out = dnsmod.open_resolver_check(ns_map)

    assert out["any_open"] is True, (
        f"v6-only-open recursion must trip any_open=True. Got {out}"
    )
    assert out["per_ns"]["ns1.example."]["open"] is True


def test_ipv4_only_ns_still_probed_when_no_ipv6():
    """Regression guard for the pre-FN5 v4-only case: an NS without
    an AAAA must still be probed over v4 — the fix must not break
    the common case."""
    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    calls = []

    def udp_fake(msg, ip, timeout=None):
        calls.append(ip)
        return _mock_resp(ra=False, answered=False)

    with patch("dns.query.udp", side_effect=udp_fake):
        out = dnsmod.open_resolver_check(ns_map)

    assert calls, "expected v4 probes on IPv4-only NS"
    assert all(":" not in ip for ip in calls)
    assert out["per_ns"]["ns1.example."].get("tested") is True


def test_ns_with_no_addresses_at_all_is_untested():
    """Rule-1 pin: an NS with neither A nor AAAA has no probeable
    address. It stays untested — but the reason string must NOT lie
    about which family was checked ("no A record" was misleading
    when we never looked at AAAA either)."""
    ns_map = {"ns1.example.": {"ipv4": [], "ipv6": []}}

    with patch("dns.query.udp", side_effect=AssertionError(
            "should not probe an addressless NS")):
        out = dnsmod.open_resolver_check(ns_map)

    per = out["per_ns"]["ns1.example."]
    assert per["tested"] is False
    assert "no A record" not in (per.get("reason") or ""), (
        f"reason must not claim 'no A record' when we didn't try v6 "
        f"either. Got reason={per.get('reason')!r}"
    )
