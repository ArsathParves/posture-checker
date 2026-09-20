"""B31 — multi-vantage geo-steering detection via EDNS Client Subnet.

The tool's public-resolver pool (`1.1.1.1 / 8.8.8.8 / 9.9.9.9`) is
US-operated and anycast — from anywhere in the world it answers from
the nearest POP. For a BFSI prospect whose customers are in India,
the tool's cached view of a geo-steered CDN can differ meaningfully
from what those customers actually see:

  - `example.com` may point to a US Cloudfront edge for a
    tool running in the US, but to an APAC edge for Indian eyeballs.
  - Geo-steered DNS is not by itself broken (it is often deliberate
    CDN behaviour), but a Solutions Engineer preparing a customer
    conversation needs to see when it's happening.

B31 adds `dnsmod.multi_vantage_a(domain)`: sends two ECS-tagged A
queries to a resolver that honours EDNS Client Subnet (Google
`8.8.8.8` does; Cloudflare `1.1.1.1` strips ECS by design). One tag
represents a US /24, the other a common India /24. Divergence in the
returned A set is surfaced as INFO + hardening=True — "we observed
this happening", not "you are broken".

Rule 1 sanity:
  - Both probes returned the same A set → PASS (no geo-steering
    observable at the resolver level).
  - Probes returned different A sets → INFO + hardening=True.
  - Probe raised / TIMEOUT / SERVFAIL / no answer → UNKNOWN
    (rule 1: never fall through to a confident PASS on failure).
  - Env self-test flagged direct DNS blocked → skipped (rule 5).

Rule 7 sanity (vendor neutrality): the finding does NOT recommend
switching to VergeCloud. It states the observation and points at
"consider whether your CDN's geo-steering matches your customer
geography".
"""
from __future__ import annotations

import dns.message
import dns.rrset

from posture import dnsmod, checks as c
from posture.core import Report


def _mk_answer(records):
    resp = dns.message.QueryMessage()
    if records:
        resp.answer.append(dns.rrset.from_text_list(
            "example.com.", 60, "IN", "A", list(records)
        ))
    return resp


# --------------------------------------------------------------------- unit: dnsmod.multi_vantage_a

def test_multi_vantage_reports_agreement(monkeypatch):
    """Both ECS-tagged probes return the same A set. Not geo-steered
    at the observable level. `diverges=False`."""
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: _mk_answer(["192.0.2.1"]))
    result = dnsmod.multi_vantage_a("example.com")
    assert result["ok"] is True
    assert result["diverges"] is False
    assert result["us_records"] == ["192.0.2.1"]
    assert result["in_records"] == ["192.0.2.1"]


def test_multi_vantage_reports_divergence(monkeypatch):
    """The two vantages return different A sets — this is the exact
    geo-steered response B31 was built to surface. Real correctness
    signal (not adoption); the finding is INFO + hardening=True."""
    calls = {"n": 0}

    def _fake(q, ip, timeout=None):
        calls["n"] += 1
        # First call: US ECS → US edge. Second: India ECS → APAC edge.
        if calls["n"] == 1:
            return _mk_answer(["192.0.2.10"])  # US edge
        return _mk_answer(["198.51.100.20"])  # APAC edge
    monkeypatch.setattr(dnsmod.dns.query, "udp", _fake)
    result = dnsmod.multi_vantage_a("example.com")
    assert result["ok"] is True
    assert result["diverges"] is True
    assert result["us_records"] == ["192.0.2.10"]
    assert result["in_records"] == ["198.51.100.20"]


def test_multi_vantage_probe_failure_is_ok_false(monkeypatch):
    """Rule 1: probe raised → ok=False. Downstream MUST render UNKNOWN,
    never a confident PASS/FAIL."""
    def _boom(*a, **kw):
        raise Exception("simulated network failure")
    monkeypatch.setattr(dnsmod.dns.query, "udp", _boom)
    result = dnsmod.multi_vantage_a("example.com")
    assert result["ok"] is False


def test_multi_vantage_uses_ecs_honouring_resolver(monkeypatch):
    """Load-bearing implementation detail: Cloudflare 1.1.1.1 strips
    ECS. If B31 sent probes to 1.1.1.1 the "divergence" signal would
    always be False regardless of actual authoritative geo-steering,
    silently masking every geo-steered zone.

    The probe MUST target 8.8.8.8 (Google, honours ECS) — verify by
    inspecting the `ip` positional argument that dns.query.udp was
    invoked with."""
    called_ips = []

    def _fake(q, ip, timeout=None):
        called_ips.append(ip)
        return _mk_answer(["192.0.2.1"])
    monkeypatch.setattr(dnsmod.dns.query, "udp", _fake)
    dnsmod.multi_vantage_a("example.com")
    # Both probes to the same ECS-honouring resolver.
    assert all(ip == "8.8.8.8" for ip in called_ips), (
        f"multi_vantage_a MUST use an ECS-honouring resolver; "
        f"got calls to: {called_ips}"
    )


def test_multi_vantage_attaches_distinct_ecs_prefixes(monkeypatch):
    """The whole point of the probe is that the two queries differ in
    their ECS option — otherwise the resolver serves the same cached
    answer to both. Assert we sent two queries with two different ECS
    subnets, one representing US and one representing India."""
    import dns.edns
    seen_ecs = []

    def _fake(q, ip, timeout=None):
        for opt in q.options:
            if isinstance(opt, dns.edns.ECSOption):
                seen_ecs.append(opt.address)
        return _mk_answer(["192.0.2.1"])
    monkeypatch.setattr(dnsmod.dns.query, "udp", _fake)
    dnsmod.multi_vantage_a("example.com")
    assert len(seen_ecs) == 2, (
        f"expected two ECS-tagged probes; got {len(seen_ecs)}: {seen_ecs}"
    )
    assert seen_ecs[0] != seen_ecs[1], (
        f"US and India ECS prefixes must differ; got {seen_ecs}"
    )


# --------------------------------------------------------------------- integration: _records emission

_CLEAN_ENV = {
    "safe": True, "notes": [],
    "safe_for_per_ns_checks": True, "safe_for_axfr": True,
    "safe_for_direct_dns": True,
}


def _run_records(monkeypatch, mv_out, env=None):
    """Drive `_records` with mostly-stubbed DNS so only the multi-vantage
    emission path exercises the finding."""
    def _fake_query(d, rd, **kw):
        if rd == "A":
            return {"ok": True, "records": ["192.0.2.1"]}
        if rd == "AAAA":
            return {"ok": True, "records": []}
        if rd == "MX":
            return {"ok": True, "records": []}
        if rd == "TXT":
            return {"ok": True, "records": []}
        if rd == "CAA":
            return {"ok": True, "records": ['0 issue "letsencrypt.org"']}
        if rd == "NS":
            return {"ok": True, "records": ["ns1.example.com."]}
        if rd == "CNAME":
            return {"ok": True, "records": []}
        return {"ok": True, "records": []}
    monkeypatch.setattr(c.dnsmod, "query", _fake_query)
    monkeypatch.setattr(c.dnsmod, "multi_vantage_a", lambda d: mv_out)
    monkeypatch.setattr(c.dnsmod, "authoritative_vs_cached",
                        lambda d, m: {"checked": False})
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = env or _CLEAN_ENV
    rep.data["ns_map"] = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    c._records(rep, "example.com")
    return rep


def _findings(rep, label):
    return [f for f in rep.findings if f.label == label]


def test_agreement_emits_pass(monkeypatch):
    """Load-bearing: when both vantages agree, the finding is PASS
    (no observable geo-steering)."""
    rep = _run_records(monkeypatch,
                       {"ok": True, "diverges": False,
                        "us_records": ["192.0.2.1"],
                        "in_records": ["192.0.2.1"]})
    findings = _findings(rep, "Multi-vantage A view")
    assert findings, (
        f"expected `Multi-vantage A view` finding; got labels: "
        f"{[f.label for f in rep.findings]}"
    )
    assert findings[0].status == "PASS"


def test_divergence_emits_info_hardening(monkeypatch):
    """Divergence is INFO (observation, not FAIL) and hardening=True
    (adoption/awareness signal). The finding must NOT recommend
    switching providers — rule 7 vendor neutrality."""
    rep = _run_records(monkeypatch,
                       {"ok": True, "diverges": True,
                        "us_records": ["192.0.2.10"],
                        "in_records": ["198.51.100.20"]})
    findings = _findings(rep, "Multi-vantage A view")
    assert findings
    f = findings[0]
    assert f.status == "INFO", (
        f"divergence is an observation, not a failure; expected INFO, "
        f"got {f.status}"
    )
    assert f.hardening is True, (
        "geo-steering awareness is a hardening/adoption signal, "
        "not a real correctness failure"
    )
    # Rule 7: no vendor-switching recommendation.
    assert "vergecloud" not in f.detail.lower()
    assert "vergecloud" not in (f.why or "").lower()


def test_probe_failure_is_unknown(monkeypatch):
    """Rule 1: probe couldn't run → UNKNOWN, never a confident PASS."""
    rep = _run_records(monkeypatch, {"ok": False, "error": "timeout"})
    findings = _findings(rep, "Multi-vantage A view")
    assert findings
    assert findings[0].status == "UNKNOWN"


def test_env_blocked_suppresses_probe(monkeypatch):
    """Rule 5: env self-test says direct DNS is untrusted → probe
    must not run. Either no finding emitted, or an explicit UNKNOWN.
    Load-bearing invariant: no confident PASS/INFO under blocked env."""
    called = {"n": 0}

    def _spy(d):
        called["n"] += 1
        return {"ok": True, "diverges": False,
                "us_records": ["192.0.2.1"],
                "in_records": ["192.0.2.1"]}

    def _fake_query(d, rd, **kw):
        if rd == "CAA":
            return {"ok": True, "records": ['0 issue "letsencrypt.org"']}
        return {"ok": True, "records": []}
    monkeypatch.setattr(c.dnsmod, "query", _fake_query)
    monkeypatch.setattr(c.dnsmod, "multi_vantage_a", _spy)
    monkeypatch.setattr(c.dnsmod, "authoritative_vs_cached",
                        lambda d, m: {"checked": False})
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {
        "safe": False, "notes": ["DNS interception"],
        "safe_for_per_ns_checks": False, "safe_for_axfr": False,
        "safe_for_direct_dns": False,
    }
    rep.data["ns_map"] = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    c._records(rep, "example.com")
    assert called["n"] == 0, (
        "multi_vantage_a MUST NOT run when env self-test flags direct "
        "DNS as blocked — rule 5 says never emit a confident finding "
        "on an untrustworthy path"
    )
    # If any finding was emitted, it must be UNKNOWN (never confident).
    for f in _findings(rep, "Multi-vantage A view"):
        assert f.status == "UNKNOWN"
