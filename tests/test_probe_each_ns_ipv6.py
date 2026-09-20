"""Regression tests for E6 — IPv6-only nameservers.

`probe_each_ns` previously did:
    ip = (ips.get("ipv4") or [None])[0]
    if not ip:
        results[host] = {"reachable": False, "error": "no_A_record", ...}

That's wrong when a nameserver publishes AAAA but no A. Modern
recursive resolvers happily query such an NS over IPv6, so labelling
it "unreachable — no_A_record" produces a false FAIL for a working
delegation. `dns.query.udp` accepts an IPv6 literal directly, so the
fix is just to fall back to `ipv6[0]` when `ipv4` is empty.

Rule 1 also applies: an IPv6-only NS that we CAN reach must not be
reported as unreachable — that would collapse `unretrievable` into
`broken`.
"""
from __future__ import annotations

from unittest.mock import patch

from posture import dnsmod


def _fake_soa_response(*args, **kwargs):
    """Minimal stand-in for dns.query.udp — mimics an authoritative SOA
    answer so probe_each_ns records the NS as reachable, without opening
    a socket. Only what the code reads is populated."""
    import dns.flags
    import dns.rdatatype
    import types

    class _Rdata:
        serial = 2026091901

    class _RRset:
        rdtype = dns.rdatatype.SOA
        def __iter__(self):
            return iter([_Rdata()])
        def __getitem__(self, i):
            return _Rdata()

    class _Resp:
        flags = dns.flags.AA
        answer = [_RRset()]

    return _Resp()


def test_ipv6_only_ns_is_probed_over_v6_and_reported_reachable():
    """If ns.example.com has AAAA but no A, probe_each_ns must use the
    IPv6 address and mark the NS reachable — NOT emit 'no_A_record'."""
    ns_map = {
        "ns.example.com.": {"ipv4": [], "ipv6": ["2001:db8::53"]},
    }
    with patch.object(dnsmod.dns.query, "udp", side_effect=_fake_soa_response):
        results = dnsmod.probe_each_ns("example.com", ns_map)
    row = results["ns.example.com."]
    assert row["reachable"] is True, (
        f"IPv6-only NS must be probed over v6 and reported reachable; got {row!r}"
    )
    assert row.get("ip") == "2001:db8::53", (
        f"the probed IP must be the AAAA address so operators can see "
        f"which endpoint answered; got {row.get('ip')!r}"
    )
    assert row.get("authoritative") is True


def test_dualstack_ns_still_prefers_ipv4():
    """Belt-and-braces: when both A and AAAA exist, prefer the v4 address
    (the historical behaviour, unchanged). A regression that flipped
    the preference would surprise anyone reading the per-NS report."""
    ns_map = {
        "ns.example.com.": {
            "ipv4": ["203.0.113.53"],
            "ipv6": ["2001:db8::53"],
        },
    }
    with patch.object(dnsmod.dns.query, "udp", side_effect=_fake_soa_response):
        results = dnsmod.probe_each_ns("example.com", ns_map)
    assert results["ns.example.com."]["ip"] == "203.0.113.53"


def test_no_addresses_at_all_still_reports_no_address():
    """An NS host with neither A nor AAAA is genuinely unreachable — the
    delegation is broken (or the parent lists a name that doesn't exist).
    Rule 1 pin: this must remain a FAIL (broken), not a UNKNOWN, since
    the parent's own records establish the state."""
    ns_map = {
        "ns.example.com.": {"ipv4": [], "ipv6": []},
    }
    results = dnsmod.probe_each_ns("example.com", ns_map)
    row = results["ns.example.com."]
    assert row["reachable"] is False
    # Error label may be tightened (e.g. "no_address") once IPv6 is
    # supported. Either the old string or a broader "no_address" is
    # acceptable — the important thing is that the row remains a FAIL
    # signal, not a false PASS.
    assert row.get("error") in ("no_A_record", "no_address"), (
        f"NS with neither A nor AAAA must remain a FAIL; got {row!r}"
    )
