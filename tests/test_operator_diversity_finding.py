"""BIAS-2 — the nameserver-topology emission.

Historic name "Network diversity" was itself biased: "diversity" framed
multiplicity as virtue, so a single-operator anycast estate (the
architecture of every hyperscale DNS provider) read as a caveat (INFO
"concentrated with one provider") instead of what it is — a stronger
topology than N unicast providers in the same DC.

BIAS-2 renames the finding to "Nameserver topology" and grades the
three cases as:

  - Multiple distinct operators → PASS (correlated-failure risk bounded
    to the intersection).
  - Single operator, verified as a known multi-PoP anycast estate →
    PASS (deliberate topology, not concentration risk).
  - Single operator, NOT verified as anycast → WARN(low) — the
    classifier could not prove multi-PoP; may or may not be a real
    single point of failure.

External consumers pin the finding by ``finding_id="NS_TOPOLOGY"``, the
display-independent handle from T1. That handle is what makes this
rename safe: the JSON API, the SPA and the remediation table all key
off the ID, not the label, so the rebrand does not break them.

The rule-1 boundary the file continues to guard: a genuine single-
operator unknown-ASN posture (e.g. everything on one small regional
ISP) must NOT be silenced by the classifier — it MUST still WARN. The
C4 fix cannot have widened the anycast net.
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
    return {
        "ok": True,
        "nameservers": ["ns1.example", "ns2.example"],
        "queried_via": ["a.tld-server.example"],
        "consensus": True,
    }


def _stub_probe_each_ns(_domain, ns_map):
    return {
        h: {"reachable": True, "authoritative": True, "serial": 2026091901,
            "rtt_ms": 12, "error": None}
        for h in ns_map
    }


def _install_stubs(monkeypatch, ip_rdap_map: dict[str, dict]):
    monkeypatch.setattr(checks.dnsmod, "get_ns_and_ips", _stub_ns_and_ips)
    monkeypatch.setattr(checks.dnsmod, "parent_delegation", _stub_parent_delegation)
    monkeypatch.setattr(checks.dnsmod, "probe_each_ns", _stub_probe_each_ns)
    monkeypatch.setattr(checks.dnsmod, "tcp53_support",
                        lambda d, m: {"ok": True, "all_supported": True,
                                      "supported": list(m),
                                      "unsupported": [], "skipped": []})
    monkeypatch.setattr(checks.dnsmod, "edns_cookie_support",
                        lambda d, m: {"ok": True, "all_supported": True,
                                      "supported": list(m),
                                      "unsupported": [], "skipped": []})

    def _fake_ip_rdap(ip):
        return ip_rdap_map.get(ip, {"ok": False})

    monkeypatch.setattr(checks, "ip_rdap", _fake_ip_rdap)


def _new_report() -> Report:
    rep = Report(domain_input="example.test", domain="example.test",
                 punycode="example.test")
    rep.data["environment"] = {"safe_for_per_ns_checks": True, "notes": []}
    return rep


def _topology_finding(rep: Report):
    matches = [f for f in rep.findings if f.label == "Nameserver topology"]
    assert len(matches) == 1, (
        f"expected exactly one 'Nameserver topology' finding, got {matches!r}"
    )
    return matches[0]


# --------------------------------------------------------------------- verified anycast → PASS

def test_all_hosts_on_vergecloud_asn_is_PASS_not_WARN(monkeypatch):
    """The end-to-end ground truth from CLAUDE.md and the exact bug the
    user reported: vergecloud.com posture (all NS on AS141383) must NOT
    emit ``WARN``. Post-BIAS-2 it grades PASS with confidence=high — the
    ASN table hit is the protocol source of truth."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 141383, "org": "VergeCloud"},
        "203.0.113.2": {"ok": True, "asn": 141383, "org": "VergeCloud"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _topology_finding(rep)
    assert finding.status == "PASS", (
        f"single-ASN anycast operator must PASS, not {finding.status!r}. "
        f"detail={finding.detail!r}"
    )
    assert finding.confidence == "high", (
        f"ASN-table hit is the protocol source of truth — confidence must "
        f"be 'high', got {finding.confidence!r}"
    )
    assert "anycast" in finding.detail.lower(), (
        f"PASS finding must explain the topology; got detail={finding.detail!r}"
    )
    assert finding.finding_id == "NS_TOPOLOGY", (
        f"external consumers pin on finding_id; expected 'NS_TOPOLOGY', "
        f"got {finding.finding_id!r}"
    )


def test_brand_string_only_anycast_is_PASS_medium_confidence(monkeypatch):
    """When the ASN is unknown but the org string matches a known brand,
    the classifier still catches anycast — but confidence drops to
    ``medium`` because the ASN table (the authoritative source) was not
    consulted. Reader can tell "we're pretty sure this is anycast" from
    "we verified it via the AS registry"."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": None, "org": "CLOUDFLARENET, US"},
        "203.0.113.2": {"ok": True, "asn": None, "org": "CLOUDFLARENET, US"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _topology_finding(rep)
    assert finding.status == "PASS", (
        f"brand-string fallback for anycast must PASS post-BIAS-2, not "
        f"{finding.status!r}. detail={finding.detail!r}"
    )
    assert finding.confidence == "medium", (
        f"brand-string fallback lacks ASN verification — confidence must "
        f"be 'medium', got {finding.confidence!r}"
    )


# --------------------------------------------------------------------- genuine SPOF → WARN

def test_all_hosts_on_unknown_small_asn_is_WARN_low_confidence(monkeypatch):
    """A genuine single-provider dependency (unknown ASN, non-brand-string
    org) must still emit WARN — this is the counter-invariant that
    guards against the anycast net widening to swallow real SPOFs."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 64512, "org": "Generic ISP LLC"},
        "203.0.113.2": {"ok": True, "asn": 64512, "org": "Generic ISP LLC"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _topology_finding(rep)
    assert finding.status == "WARN", (
        f"single small-ASN operator must WARN, not {finding.status!r}. "
        f"detail={finding.detail!r}. If this passes as PASS, the anycast "
        f"classifier is over-broad."
    )
    assert finding.confidence == "low", (
        f"unverified single-operator posture must carry low confidence "
        f"(we couldn't prove it isn't anycast either); got "
        f"{finding.confidence!r}"
    )
    assert "correlated" in (finding.why or "").lower(), (
        f"WARN copy must name the correlated-failure risk; got why={finding.why!r}"
    )


def test_unknown_asn_and_no_brand_match_is_WARN(monkeypatch):
    """The brand-string fallback must not over-classify: unknown ASN +
    non-brand org string is a real single-operator finding and MUST
    WARN. Same invariant as the small-ASN test but exercising the
    Cymru-failed / RDAP-only path."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": None, "org": "Small Regional ISP"},
        "203.0.113.2": {"ok": True, "asn": None, "org": "Small Regional ISP"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _topology_finding(rep)
    assert finding.status == "WARN", (
        f"unknown-ASN + unknown-brand must WARN, not {finding.status!r}. "
        f"detail={finding.detail!r}"
    )


# --------------------------------------------------------------------- multi-operator → PASS

def test_hosts_on_multiple_asns_is_PASS_high_confidence(monkeypatch):
    """Distinct ASNs across NS hosts is the genuinely diverse case —
    always PASS, and confidence is high because we have the ASN
    numbers to name each operator."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 15169, "org": "GOOGLE"},
        "203.0.113.2": {"ok": True, "asn": 13335, "org": "CLOUDFLARENET"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _topology_finding(rep)
    assert finding.status == "PASS", (
        f"multi-ASN posture must PASS; got {finding.status!r}. "
        f"detail={finding.detail!r}"
    )
    assert finding.confidence == "high"


def test_mixed_one_anycast_one_unknown_is_still_PASS(monkeypatch):
    """Two DISTINCT operators — one large anycast, one small — grade
    PASS on topology. The anycast-collapse only fires when the operator
    set has cardinality 1."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 141383, "org": "VergeCloud"},
        "203.0.113.2": {"ok": True, "asn": 64512, "org": "Backup ISP"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test")
    finding = _topology_finding(rep)
    assert finding.status == "PASS", (
        f"two distinct operators must PASS regardless of anycast flag; "
        f"got {finding.status!r}. detail={finding.detail!r}"
    )
    assert "2 distinct" in finding.detail, (
        f"detail should surface the operator count; got {finding.detail!r}"
    )


# --------------------------------------------------------------------- opt-out

def test_skip_asn_suppresses_topology_finding_entirely(monkeypatch):
    """`skip_asn=True` is a caller-explicit opt-out — better absent than
    misleading. Enforces that the entire operator-classification block
    is gated on the flag."""
    _install_stubs(monkeypatch, {
        "203.0.113.1": {"ok": True, "asn": 141383, "org": "VergeCloud"},
        "203.0.113.2": {"ok": True, "asn": 141383, "org": "VergeCloud"},
    })
    rep = _new_report()
    checks._nameservers(rep, "example.test", skip_asn=True)
    matches = [f for f in rep.findings if f.label == "Nameserver topology"]
    assert matches == [], (
        f"skip_asn=True must suppress the topology finding entirely; "
        f"got {matches!r}"
    )


# --------------------------------------------------------------------- finding_id stability

def test_finding_id_is_stable_across_all_topology_verdicts(monkeypatch):
    """The finding_id is one handle — status differentiates PASS/WARN,
    but a single ID lets external consumers say "give me the topology
    finding" without knowing which verdict fired."""
    cases = [
        # (ip_rdap_map, expected_status)
        ({"203.0.113.1": {"ok": True, "asn": 141383, "org": "VergeCloud"},
          "203.0.113.2": {"ok": True, "asn": 141383, "org": "VergeCloud"}},
         "PASS"),
        ({"203.0.113.1": {"ok": True, "asn": 64512, "org": "Small ISP"},
          "203.0.113.2": {"ok": True, "asn": 64512, "org": "Small ISP"}},
         "WARN"),
        ({"203.0.113.1": {"ok": True, "asn": 15169, "org": "GOOGLE"},
          "203.0.113.2": {"ok": True, "asn": 13335, "org": "CLOUDFLARENET"}},
         "PASS"),
    ]
    for ip_map, expected_status in cases:
        _install_stubs(monkeypatch, ip_map)
        rep = _new_report()
        checks._nameservers(rep, "example.test")
        finding = _topology_finding(rep)
        assert finding.status == expected_status
        assert finding.finding_id == "NS_TOPOLOGY", (
            f"ip_map={ip_map} → status={finding.status} but "
            f"finding_id={finding.finding_id!r}, expected 'NS_TOPOLOGY'"
        )
