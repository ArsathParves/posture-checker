"""T2 migrations — mark specific existing FAIL findings as CRITICAL.

The T2 mechanism landed in commit 7e9898e. This follow-up routes the
four highest-impact FAIL findings through it:

  - Zone transfer (AXFR) FAIL — full zone leak. Every subdomain and
    internal host is disclosed to any caller. The exact class of
    finding that "one CRITICAL is worse than 8 PASSes" was designed
    for.
  - Open recursive resolver FAIL — DDoS amplification vector. The
    server contributes to attacks on third parties.
  - Registry hold FAIL — `clientHold` / `serverHold`. The domain is
    non-resolving at the registry level, worldwide, for everyone.
  - Registry lifecycle FAIL — `redemptionPeriod` / `pendingDelete`.
    The domain has been deleted at the registry and is inside the
    grace window before anyone else can register it.

Each of these renders as FAIL today and is scored the same as a
`missing AAAA` FAIL. That's the misrepresentation T2 exists to fix —
a Solutions Engineer briefing a BFSI prospect on "your domain is in
redemptionPeriod" reads C/D from the tool, which is not urgent enough.

Test contract: for each migrated finding, when the underlying probe
returns the failure condition, the emitted Finding carries
`severity="CRITICAL"`. Non-failing branches (PASS / UNKNOWN / probe
skipped) must NOT carry CRITICAL — the tag is orthogonal to status
and only applies to the actual failure emissions.
"""
from __future__ import annotations

from posture import checks as c
from posture.core import Report


_CLEAN_ENV = {
    "safe": True, "notes": [],
    "safe_for_per_ns_checks": True, "safe_for_axfr": True,
    "safe_for_direct_dns": True,
}


def _findings(rep, label):
    return [f for f in rep.findings if f.label == label]


# --------------------------------------------------------------------- AXFR open → CRITICAL

def test_axfr_open_is_critical(monkeypatch):
    """Load-bearing: an open AXFR (full zone leak) is CRITICAL. A
    tool that reports it as a plain FAIL cannot distinguish it from a
    missing AAAA record in the same section."""
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": ns_map})
    monkeypatch.setattr(c.dnsmod, "axfr_open_check",
                        lambda d, m: {
                            "any_open": True,
                            "per_ns": {"ns1.example.com.": {
                                "tested": True, "open": True,
                                "records_leaked": 1200,
                            }},
                        })
    monkeypatch.setattr(c.dnsmod, "open_resolver_check",
                        lambda m: {"any_open": False, "per_ns": {}})
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["ns_map"] = ns_map
    rep.data["environment"] = _CLEAN_ENV
    c._security(rep, "example.com")
    findings = _findings(rep, "Zone transfer (AXFR)")
    assert findings
    f = findings[0]
    assert f.status == "FAIL"
    assert f.severity == "CRITICAL", (
        f"open AXFR is a full-zone leak — the exact class of FAIL that "
        f"CRITICAL was designed for. severity: {f.severity!r}"
    )


def test_axfr_refused_is_not_critical(monkeypatch):
    """AXFR PASS (all NSes refused) must not carry CRITICAL — the
    marker is orthogonal to status and only applies to the failure
    emission. Otherwise CRITICAL PASS would render as an implicit
    "critical concern" in the UI."""
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": ns_map})
    monkeypatch.setattr(c.dnsmod, "axfr_open_check",
                        lambda d, m: {
                            "any_open": False,
                            "per_ns": {"ns1.example.com.": {
                                "tested": True, "open": False,
                                "reason": "refused",
                            }},
                        })
    monkeypatch.setattr(c.dnsmod, "open_resolver_check",
                        lambda m: {"any_open": False, "per_ns": {}})
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["ns_map"] = ns_map
    rep.data["environment"] = _CLEAN_ENV
    c._security(rep, "example.com")
    findings = _findings(rep, "Zone transfer (AXFR)")
    assert findings
    f = findings[0]
    assert f.status == "PASS"
    assert f.severity == "", (
        f"AXFR PASS must not carry a CRITICAL marker — the marker is "
        f"scoped to the failure emission only. severity: {f.severity!r}"
    )


# --------------------------------------------------------------------- Open resolver → CRITICAL

def test_open_resolver_is_critical(monkeypatch):
    """An authoritative NS that also answers recursive queries for
    arbitrary third-party names is usable in DNS amplification DDoS
    attacks. CRITICAL — the domain contributes to third-party harm."""
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": ns_map})
    monkeypatch.setattr(c.dnsmod, "axfr_open_check",
                        lambda d, m: {"any_open": False, "per_ns": {}})
    monkeypatch.setattr(c.dnsmod, "open_resolver_check",
                        lambda m: {
                            "any_open": True,
                            "per_ns": {"ns1.example.com.": {
                                "tested": True, "open": True,
                            }},
                        })
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["ns_map"] = ns_map
    rep.data["environment"] = _CLEAN_ENV
    c._security(rep, "example.com")
    findings = _findings(rep, "Open recursive resolver")
    assert findings
    f = findings[0]
    assert f.status == "FAIL"
    assert f.severity == "CRITICAL"


# --------------------------------------------------------------------- Registry hold → CRITICAL

def test_registry_hold_is_critical(monkeypatch):
    """`clientHold` / `serverHold` — the registry has removed the
    domain from DNS delegation. It does not resolve for anyone,
    anywhere, until the hold is lifted. CRITICAL — the most urgent
    finding a BFSI SE can surface."""
    monkeypatch.setattr(c, "rdap_lookup",
                        lambda d: {"ok": True, "data": {},
                                   "endpoint": "https://rdap.test/",
                                   "suffix": "com"})
    monkeypatch.setattr(c, "parse_rdap",
                        lambda raw: {"registrar": "Test Registrar",
                                     "events": {},
                                     "status": ["clientHold"],
                                     "nameservers": [],
                                     "abuse_email": None,
                                     "redacted": False,
                                     "raw": {}})
    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": {}})
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = _CLEAN_ENV
    c._registration(rep, "example.com")
    findings = _findings(rep, "Registry hold")
    assert findings
    f = findings[0]
    assert f.status == "FAIL"
    assert f.severity == "CRITICAL"


def test_registry_lifecycle_is_critical(monkeypatch):
    """`redemptionPeriod` / `pendingDelete` — the domain has been
    deleted at the registry and is inside the grace window before it
    can be re-registered by anyone. CRITICAL — imminent, worldwide,
    irreversible if the grace window closes."""
    monkeypatch.setattr(c, "rdap_lookup",
                        lambda d: {"ok": True, "data": {},
                                   "endpoint": "https://rdap.test/",
                                   "suffix": "com"})
    monkeypatch.setattr(c, "parse_rdap",
                        lambda raw: {"registrar": "Test Registrar",
                                     "events": {},
                                     "status": ["redemptionPeriod"],
                                     "nameservers": [],
                                     "abuse_email": None,
                                     "redacted": False,
                                     "raw": {}})
    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": {}})
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = _CLEAN_ENV
    c._registration(rep, "example.com")
    findings = _findings(rep, "Registry lifecycle")
    assert findings
    f = findings[0]
    assert f.status == "FAIL"
    assert f.severity == "CRITICAL"


# --------------------------------------------------------------------- grade integration

def test_open_axfr_floors_overall_grade(monkeypatch):
    """End-to-end acceptance: a single CRITICAL FAIL in one section
    floors the overall report to F, even when every other check
    passes. This is the T2 acceptance criterion applied to a real
    finding rather than a synthetic one."""
    rep = Report(domain_input="example.com", domain="example.com")
    # Populate the report with many PASSes across sections
    for section in ["Registration & delegation", "Nameserver posture",
                    "Core records", "DNSSEC", "Email authentication"]:
        for i in range(5):
            rep.add(section, f"pass-{i}", "PASS", "")
    # One CRITICAL FAIL in Security posture — the AXFR-style pattern.
    rep.add("Security posture", "Zone transfer (AXFR)", "FAIL",
            "leaked 1200 records", severity="CRITICAL")
    result = c.grade(rep)
    assert result["overall"] == "F", (
        f"one CRITICAL FAIL must floor overall to F despite 25 "
        f"surrounding PASSes; got overall={result['overall']}, "
        f"sections={ {k: v[0] for k, v in result['sections'].items()} }"
    )
