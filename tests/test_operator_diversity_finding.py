"""T7 — The anycast classifier (`_is_large_anycast_operator`) is
directly unit-tested in `test_anycast_classifier.py`. This file pins
the call site: `checks._nameservers` must feed the classifier its
inputs correctly and emit the *right finding* on its output.

The failure mode T7 guards against: a refactor that keeps the
classifier logic intact but breaks the wiring — e.g., passing
`org` alone when the ASN is also available, or reading the classifier
result from the wrong field of `ip_rdap`'s return. Either bug would
regress `vergecloud.com` back to a `Network diversity: WARN` finding
even though the classifier itself is green — the same false-positive
the C4 audit item was originally about.

Strategy: monkeypatch the four DNS/IP-registry entry points that
`_nameservers` depends on, then invoke it with a synthetic `Report`.
Assert on the emitted "Network diversity" finding shape.

The DNS/IP monkeypatch targets:
  - `posture.checks.dnsmod.get_ns_and_ips` — NS set + resolved IPs
  - `posture.checks.dnsmod.parent_delegation` — parent-side NS view
  - `posture.checks.dnsmod.probe_each_ns` — per-NS SOA probe
  - `posture.checks.ip_rdap` — IP → (asn, org) mapping

Every fixture uses two NS hosts with fixed IPs; we drive the classifier
by controlling the `ip_rdap` return per IP. The per-NS probes are
faked as reachable+authoritative so the "Nameserver reachability"
finding doesn't derail the fixture.
"""
from __future__ import annotations

import pytest

from posture import checks
from posture.core import Report


# --------------------------------------------------------------------- fake infra

def _stub_ns_and_ips(_domain):
    return {
        "ok": True,
        "ttl": 3600,
        "ns": {
            "ns1.example.": {"ipv4": ["203.0.113.1"], "ipv6": ["2001:db8::1"]},
            "ns2.example.": {"ipv4": ["203.0.113.2"], "ipv6": ["2001:db8::2"]},
        },
    }


def _stub_parent_delegation(_domain):
    # Matches served set → PASS on "Parent delegation vs zone NS".
    return {
        "ok": True,
        "nameservers": ["ns1.example", "ns2.example"],
        "queried_via": ["a.tld-server.example"],
        "consensus": True,
    }


def _stub_probe_each_ns(_domain, ns_map):
    # Reachable + authoritative + agreeing serial for every NS.
    return {
        h: {"reachable": True, "authoritative": True, "serial": 2026091901,
            "rtt_ms": 12, "error": None}
        for h in ns_map
    }


def _install_stubs(monkeypatch, ip_rdap_map: dict[str, dict]):
    """Wire the four entry points. `ip_rdap_map` maps IP → {asn, org, ok}
    to control per-host classification."""
    monkeypatch.setattr(checks.dnsmod, "get_ns_and_ips", _stub_ns_and_ips)
    monkeypatch.setattr(checks.dnsmod, "parent_delegation", _stub_parent_delegation)
    monkeypatch.setattr(checks.dnsmod, "probe_each_ns", _stub_probe_each_ns)
    monkeypatch.setattr(checks.dnsmod, "tcp53_support",
                        lambda d, m: {"ok": True, "all_supported": True,
                                      "supported": list(m),
                                      "unsupported": [], "skipped": []})

    def _fake_ip_rdap(ip):
        return ip_rdap_map.get(ip, {"ok": False})

    monkeypatch.setattr(checks, "ip_rdap", _fake_ip_rdap)


def _new_report() -> Report:
    rep = Report(domain_input="example.test", domain="example.test",
                 punycode="example.test")
    # `_nameservers` reads env for `safe_for_per_ns_checks`.
    rep.data["environment"] = {"safe_for_per_ns_checks": True, "notes": []}
    return rep


def _network_diversity_finding(rep: Report):
    matches = [f for f in rep.findings if f.label == "Network diversity"]
    assert len(matches) == 1, (
        f"expected exactly one 'Network diversity' finding, got {matches!r}"
    )
    return matches[0]


# --------------------------------------------------------------------- tests

def test_all_hosts_on_vergecloud_asn_is_INFO_not_WARN(monkeypatch):
    """The end-to-end ground truth from CLAUDE.md: vergecloud.com posture
    (all NS on AS141383) must NOT emit `Network diversity: WARN`. The
    classifier collapse into an anycast INFO happens at this call site."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 141383, "org": "VergeCloud"},
        "203.0.113.2": {"ok": True, "asn": 141383, "org": "VergeCloud"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _network_diversity_finding(rep)
    assert finding.status == "INFO", (
        f"single-ASN anycast operator must be INFO, not {finding.status!r}. "
        f"detail={finding.detail!r}"
    )
    assert "anycast" in finding.detail.lower(), (
        f"INFO finding must explain the collapse; got detail={finding.detail!r}"
    )


def test_all_hosts_on_unknown_small_asn_is_WARN(monkeypatch):
    """A genuine single-provider dependency (unknown ASN, non-brand-string
    org) must still emit `Network diversity: WARN`. The C4 fix cannot
    have silenced this — it would hide real correlated-failure risk."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 64512, "org": "Generic ISP LLC"},
        "203.0.113.2": {"ok": True, "asn": 64512, "org": "Generic ISP LLC"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _network_diversity_finding(rep)
    assert finding.status == "WARN", (
        f"single small-ASN operator must WARN, not {finding.status!r}. "
        f"detail={finding.detail!r}. If this passes as INFO, the anycast "
        f"classifier is over-broad."
    )
    assert "correlated" in (finding.why or "").lower(), (
        f"WARN copy must name the correlated-failure risk; got why={finding.why!r}"
    )


def test_hosts_on_multiple_asns_is_PASS(monkeypatch):
    """Distinct ASNs across NS hosts is the genuinely diverse case —
    always PASS, regardless of whether any of them is a known anycast
    operator."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 15169, "org": "GOOGLE"},
        "203.0.113.2": {"ok": True, "asn": 13335, "org": "CLOUDFLARENET"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _network_diversity_finding(rep)
    assert finding.status == "PASS", (
        f"multi-ASN posture must PASS; got {finding.status!r}. "
        f"detail={finding.detail!r}"
    )


def test_asn_lookup_missing_falls_back_to_brand_string(monkeypatch):
    """When Team Cymru returns no ASN, the classifier should still
    catch known brand-string operators (Cloudflare, Google, ...). This
    is the fallback path that pre-dated the ASN table and must not
    have regressed."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": None, "org": "CLOUDFLARENET, US"},
        "203.0.113.2": {"ok": True, "asn": None, "org": "CLOUDFLARENET, US"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _network_diversity_finding(rep)
    assert finding.status == "INFO", (
        f"brand-string fallback for anycast must produce INFO; got "
        f"{finding.status!r}. detail={finding.detail!r}"
    )


def test_asn_lookup_missing_and_no_brand_match_is_WARN(monkeypatch):
    """The fallback must not over-classify: an unknown ASN + non-brand
    org string is a real single-operator finding and MUST WARN. This
    is the counter-invariant for the previous test."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": None, "org": "Small Regional ISP"},
        "203.0.113.2": {"ok": True, "asn": None, "org": "Small Regional ISP"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _network_diversity_finding(rep)
    assert finding.status == "WARN", (
        f"unknown-ASN + unknown-brand must WARN, not {finding.status!r}. "
        f"detail={finding.detail!r}"
    )


def test_mixed_one_anycast_one_unknown_asn_is_still_PASS(monkeypatch):
    """Two DISTINCT operators — one large anycast, one small — should
    grade PASS on diversity. The single-operator collapse only kicks
    in when the operator set has cardinality 1. This test guards
    against a bug where the anycast flag would eat the second
    operator and demote a legitimately-diverse setup to INFO."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 141383, "org": "VergeCloud"},
        "203.0.113.2": {"ok": True, "asn": 64512, "org": "Backup ISP"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _network_diversity_finding(rep)
    assert finding.status == "PASS", (
        f"two distinct operators must PASS regardless of anycast flag; "
        f"got {finding.status!r}. detail={finding.detail!r}"
    )
    assert "2 distinct" in finding.detail, (
        f"detail should surface the operator count; got {finding.detail!r}"
    )


def test_skip_asn_suppresses_operator_finding_entirely(monkeypatch):
    """`skip_asn=True` is a caller-explicit opt-out (used by tests and
    by CLI --skip-asn). It must not emit a 'Network diversity' finding
    at all — better absent than misleading. Enforces that the entire
    operator-classification block is gated on the flag."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 141383, "org": "VergeCloud"},
        "203.0.113.2": {"ok": True, "asn": 141383, "org": "VergeCloud"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test", skip_asn=True)
    matches = [f for f in rep.findings if f.label == "Network diversity"]
    assert matches == [], (
        f"skip_asn=True must suppress the operator finding entirely; "
        f"got {matches!r}"
    )
