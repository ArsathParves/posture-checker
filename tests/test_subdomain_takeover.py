"""B20 — subdomain takeover / dangling records.

Two threat classes surface here, both of which land as CRITICAL (T2)
because the impact is loss of control of the zone (not a hardening
gap, not a policy-level FAIL):

1. NAMESERVER PARENT-ZONE HIJACK — the "full zone takeover" bullet.
   If any NS in the delegation set is under a parent domain that is
   NXDOMAIN, anyone who registers that parent can attach nameservers
   with the same hostname and take over DNS for the target zone. The
   parent-registrar is the only defender.

2. DANGLING CNAME — a CNAME whose target has no A/AAAA/CNAME. Non-
   apex only (RFC 1912 §2.4 bars apex CNAMEs, though ALIAS/ANAME
   flattening at some providers can present as apex CNAMEs to
   resolvers). When the target sits under a service that lets anyone
   claim tenant names (e.g. `*.s3.amazonaws.com`, `*.github.io`),
   the attacker registers the tenant name and serves content on the
   delegator's FQDN. THAT branch is CRITICAL; a generic dangling
   CNAME with no known takeover service is still FAIL but not
   CRITICAL — the attack requires infrastructure control at the
   target, which is not universally available.

Rule 1 is load-bearing here: an inconclusive probe (parent-zone
lookup timeout, CNAME query error) MUST NOT fire a finding. Every
"UNKNOWN takeover risk" is a false positive that costs an SE a
conversation with a customer — we do not do that.
"""
from __future__ import annotations

from posture import takeover, dnsmod, checks as c
from posture.core import Report


_CLEAN_ENV = {
    "safe": True, "notes": [],
    "safe_for_per_ns_checks": True, "safe_for_axfr": True,
    "safe_for_direct_dns": True, "tcp53_direct": True,
}


# --------------------------------------------------------------------- NS parent-zone check

def test_ns_parent_zone_same_zone_is_ok(monkeypatch):
    """In-bailiwick NSes (`ns1.example.com` for `example.com`) are glue
    records — the parent-zone hijack model does not apply because they
    live inside the target's own zone. Skip without querying."""
    called: list[str] = []
    monkeypatch.setattr(dnsmod, "domain_exists",
                        lambda d: called.append(d) or  # type: ignore[func-returns-value]
                                  {"exists": True, "via": "SOA"})
    res = takeover.nameserver_parent_zone_check(
        "example.com", ["ns1.example.com", "ns2.example.com"])
    assert res["per_ns"]["ns1.example.com"]["status"] == "same_zone"
    assert res["per_ns"]["ns2.example.com"]["status"] == "same_zone"
    assert res["any_hijackable"] is False
    assert called == [], (
        "in-bailiwick NSes must not trigger a parent-zone probe — that "
        "burns a resolver query for no signal and can cause "
        "rate-limit-driven false positives on downstream checks."
    )


def test_ns_parent_zone_registered_is_ok(monkeypatch):
    monkeypatch.setattr(dnsmod, "domain_exists",
                        lambda d: {"exists": True, "via": "SOA"})
    res = takeover.nameserver_parent_zone_check(
        "example.com", ["ns1.some-hosting.example"])
    assert res["per_ns"]["ns1.some-hosting.example"]["status"] == "ok"
    assert res["per_ns"]["ns1.some-hosting.example"]["parent"] == \
        "some-hosting.example"
    assert res["any_hijackable"] is False


def test_ns_parent_zone_nxdomain_is_hijackable(monkeypatch):
    """The canonical B20 case: an NS hostname sits in an unregistered
    parent zone. Any attacker who registers that parent controls DNS
    for the delegating zone. CRITICAL."""
    monkeypatch.setattr(dnsmod, "domain_exists",
                        lambda d: {"exists": False, "via": "SOA",
                                   "error": "NXDOMAIN"})
    res = takeover.nameserver_parent_zone_check(
        "example.com", ["ns1.abandoned-hosting.example"])
    r = res["per_ns"]["ns1.abandoned-hosting.example"]
    assert r["status"] == "unregistered"
    assert r["parent"] == "abandoned-hosting.example"
    assert res["any_hijackable"] is True


def test_ns_parent_zone_lookup_error_is_not_hijackable(monkeypatch):
    """Rule 1: unretrievable ≠ hijackable. A resolver timeout on the
    parent-zone probe must produce UNKNOWN, not FAIL. This is the
    guard against "one flaky network hop grades the report critical"."""
    monkeypatch.setattr(dnsmod, "domain_exists",
                        lambda d: {"exists": False, "via": None,
                                   "error": "no_response"})
    res = takeover.nameserver_parent_zone_check(
        "example.com", ["ns1.some-hosting.example"])
    assert res["per_ns"]["ns1.some-hosting.example"]["status"] == "error"
    assert res["any_hijackable"] is False


def test_ns_parent_zone_mixed_set_reports_per_ns(monkeypatch):
    """A realistic delegation has some in-bailiwick, some external NSes.
    Each must be reported independently — the aggregate `any_hijackable`
    fires as soon as one NS is unregistered."""
    def exists(d):
        if d == "hijackable.example":
            return {"exists": False, "error": "NXDOMAIN"}
        return {"exists": True, "via": "SOA"}
    monkeypatch.setattr(dnsmod, "domain_exists", exists)
    res = takeover.nameserver_parent_zone_check(
        "example.com",
        ["ns1.example.com",
         "ns1.safe-hosting.example",
         "ns1.hijackable.example"])
    assert res["per_ns"]["ns1.example.com"]["status"] == "same_zone"
    assert res["per_ns"]["ns1.safe-hosting.example"]["status"] == "ok"
    assert res["per_ns"]["ns1.hijackable.example"]["status"] == "unregistered"
    assert res["any_hijackable"] is True


# --------------------------------------------------------------------- CNAME dangling / takeover-service

def test_cname_no_cname_is_clean(monkeypatch):
    """Apex domain with A record and no CNAME → no finding."""
    monkeypatch.setattr(dnsmod, "query",
        lambda d, rt, **kw: (
            {"ok": True, "records": []} if rt == "CNAME"
            else {"ok": True, "records": ["93.184.216.34"]}))
    res = takeover.cname_takeover_check("example.com")
    assert res["cname_present"] is False
    assert res["dangling"] is False
    assert res["takeover_service"] is None


def test_cname_resolves_ok_is_clean(monkeypatch):
    """CNAME whose chain terminates at a target with A records → no
    finding. This is the healthy case for every CDN-fronted subdomain."""
    seq = iter([
        {"ok": True, "records": ["dualstack.somecdn.net."]},  # www CNAME
        {"ok": True, "records": []},                          # dualstack CNAME (end)
        {"ok": True, "records": ["203.0.113.5"]},             # dualstack A
        {"ok": True, "records": []},                          # dualstack AAAA
    ])
    monkeypatch.setattr(dnsmod, "query",
                        lambda d, rt, **kw: next(seq))
    res = takeover.cname_takeover_check("www.example.com")
    assert res["cname_present"] is True
    assert res["chain"] == ["dualstack.somecdn.net"]
    assert res["dangling"] is False
    assert res["takeover_service"] is None


def test_cname_dangling_nxdomain_flagged(monkeypatch):
    """CNAME target is NXDOMAIN → dangling. Generic (no known takeover
    service) — FAIL but severity depends on the caller's classification."""
    seq = iter([
        {"ok": True, "records": ["deprovisioned.example.net."]},  # CNAME
        {"ok": False, "error": "NXDOMAIN"},                       # target CNAME
    ])
    monkeypatch.setattr(dnsmod, "query",
                        lambda d, rt, **kw: next(seq))
    res = takeover.cname_takeover_check("legacy.example.com")
    assert res["cname_present"] is True
    assert res["dangling"] is True
    assert res["takeover_service"] is None


def test_cname_dangling_takeover_service_lifts_to_critical(monkeypatch):
    """Dangling CNAME AND target under a known takeover-vulnerable
    service (`*.s3.amazonaws.com`, `*.github.io`, etc.). The service
    suffix tells us this is the CRITICAL branch — anyone can claim the
    tenant name on that provider and serve arbitrary content under the
    delegator's FQDN. This is the specific pattern BUGS.md B20 names."""
    seq = iter([
        {"ok": True, "records": ["orphan-bucket.s3.amazonaws.com."]},
        {"ok": False, "error": "NXDOMAIN"},
    ])
    monkeypatch.setattr(dnsmod, "query",
                        lambda d, rt, **kw: next(seq))
    res = takeover.cname_takeover_check("static.example.com")
    assert res["dangling"] is True
    assert res["takeover_service"] == ".s3.amazonaws.com"


def test_cname_query_error_is_unknown_not_dangling(monkeypatch):
    """Rule 1: a CNAME query timeout on the *first* hop yields no CNAME
    presence signal → return no finding rather than emit a false
    dangling. This is the same guard as the parent-zone error case."""
    monkeypatch.setattr(dnsmod, "query",
        lambda d, rt, **kw: {"ok": False, "error": "TIMEOUT"})
    res = takeover.cname_takeover_check("uncertain.example.com")
    assert res["cname_present"] is False
    assert res["dangling"] is False


# --------------------------------------------------------------------- integration into _security

def _stub_security_deps(monkeypatch, ns_map, dnsmod_exists=None,
                        cname_result=None):
    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": ns_map})
    monkeypatch.setattr(c.dnsmod, "axfr_open_check",
                        lambda d, m: {"any_open": False, "per_ns": {}})
    monkeypatch.setattr(c.dnsmod, "open_resolver_check",
                        lambda m: {"any_open": False, "per_ns": {}})
    if dnsmod_exists is not None:
        monkeypatch.setattr(c.dnsmod, "domain_exists", dnsmod_exists)
    if cname_result is not None:
        monkeypatch.setattr(c.takeover, "cname_takeover_check",
                            lambda d: cname_result)
    else:
        monkeypatch.setattr(c.takeover, "cname_takeover_check",
                            lambda d: {"cname_present": False,
                                       "chain": [], "dangling": False,
                                       "takeover_service": None, "error": None})


def test_security_emits_ns_takeover_critical(monkeypatch):
    """End-to-end: an NS whose parent zone is NXDOMAIN fires
    `Nameserver takeover risk` FAIL with severity=CRITICAL. The
    section then floors overall to F via the T2 mechanism."""
    ns_map = {"ns1.abandoned-hosting.example.": {
        "ipv4": ["192.0.2.1"], "ipv6": []}}
    _stub_security_deps(monkeypatch, ns_map,
        dnsmod_exists=lambda d: {"exists": False, "error": "NXDOMAIN"})
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["ns_map"] = ns_map
    rep.data["environment"] = _CLEAN_ENV
    c._security(rep, "example.com")
    findings = [f for f in rep.findings
                if f.label == "Nameserver takeover risk"]
    assert findings, "must emit a finding for the hijackable NS"
    f = findings[0]
    assert f.status == "FAIL"
    assert f.severity == "CRITICAL"


def test_security_no_ns_takeover_finding_when_parents_registered(monkeypatch):
    """When every NS parent is registered → NO finding emitted (not a
    PASS row either). Only fire on failure. This keeps the report tight
    for the 99% of domains without takeover risk."""
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    _stub_security_deps(monkeypatch, ns_map,
        dnsmod_exists=lambda d: {"exists": True, "via": "SOA"})
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["ns_map"] = ns_map
    rep.data["environment"] = _CLEAN_ENV
    c._security(rep, "example.com")
    findings = [f for f in rep.findings
                if "takeover" in f.label.lower()]
    assert findings == []


def test_security_emits_cname_takeover_critical_when_service_suffix(monkeypatch):
    """A dangling CNAME pointing at a known takeover-vulnerable service
    fires `Subdomain takeover risk` FAIL with severity=CRITICAL."""
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    _stub_security_deps(monkeypatch, ns_map,
        dnsmod_exists=lambda d: {"exists": True, "via": "SOA"},
        cname_result={"cname_present": True,
                      "chain": ["orphan-bucket.s3.amazonaws.com"],
                      "dangling": True,
                      "takeover_service": ".s3.amazonaws.com",
                      "error": "NXDOMAIN"})
    rep = Report(domain_input="static.example.com",
                 domain="static.example.com")
    rep.data["ns_map"] = ns_map
    rep.data["environment"] = _CLEAN_ENV
    c._security(rep, "static.example.com")
    findings = [f for f in rep.findings
                if f.label == "Subdomain takeover risk"]
    assert findings
    f = findings[0]
    assert f.status == "FAIL"
    assert f.severity == "CRITICAL"


def test_security_dangling_cname_without_service_is_fail_not_critical(monkeypatch):
    """A dangling CNAME whose target does NOT match a known takeover
    service is still a FAIL (dangling is broken DNS), but NOT
    CRITICAL — the attack surface is not immediately claimable by an
    arbitrary attacker."""
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    _stub_security_deps(monkeypatch, ns_map,
        dnsmod_exists=lambda d: {"exists": True, "via": "SOA"},
        cname_result={"cname_present": True,
                      "chain": ["deprovisioned.example.net"],
                      "dangling": True,
                      "takeover_service": None,
                      "error": "NXDOMAIN"})
    rep = Report(domain_input="legacy.example.com",
                 domain="legacy.example.com")
    rep.data["ns_map"] = ns_map
    rep.data["environment"] = _CLEAN_ENV
    c._security(rep, "legacy.example.com")
    findings = [f for f in rep.findings
                if f.label == "Subdomain takeover risk"]
    assert findings
    f = findings[0]
    assert f.status == "FAIL"
    assert f.severity == "", (
        f"generic dangling CNAME is FAIL but not CRITICAL — the "
        f"CRITICAL tier is reserved for the case where a third party "
        f"can claim the target name on a public service. "
        f"severity: {f.severity!r}"
    )
