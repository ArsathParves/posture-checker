"""B26 — authoritative nameservers' own TCP/53 support (RFC 7766).

RFC 7766 (Mar 2016) upgrades DNS-over-TCP from OPTIONAL to MUST for
every DNS server. This is not a hardening preference — a nameserver
that refuses TCP breaks:

  - Any response larger than 512 bytes without EDNS0.
  - EDNS0 responses larger than the queried buffer (4096 default).
  - DNSKEY responses at signed zones (routinely exceed 512).
  - Any query that receives a TC (truncation) flag — resolvers MUST
    retry over TCP.

A domain whose authoritative NS refuses TCP will silently break
resolution the moment a large response is needed. This is the same
class of failure that caused the SPF-truncated false-absent incident
on the environment side — mirrored on the target side.

Distinct from environment self-test's TCP/53 gate (posture.selftest):
that tests whether the *tool's own network path* has TCP outbound;
this tests whether the *target's authoritative nameservers* accept
inbound TCP/53.

Rule 1 sanity:
  - Env self-test says TCP is blocked → UNKNOWN (rule 5: never
    produce confident findings on an untrustworthy path).
  - Query returned via TCP → NS supports TCP.
  - Query timed out / connection refused → NS does not support TCP.
  - Some NSes support, some fail → WARN (any large response will
    randomly break depending on which NS resolvers hit).
  - All NSes fail → FAIL (zone is broken for DNSSEC and large TXT).
  - Zero NSes with usable IPs → no finding (nothing to test).
"""
from __future__ import annotations

from posture import dnsmod, checks as c
from posture.core import Report


# --------------------------------------------------------------------- unit: dnsmod.tcp53_support

def test_tcp53_support_all_respond(monkeypatch):
    """Every configured NS returns via TCP/53 → all supported."""
    def _fake_tcp(q, ip, timeout=None):
        import dns.message
        return dns.message.QueryMessage()
    monkeypatch.setattr(dnsmod.dns.query, "tcp", _fake_tcp)
    ns_map = {
        "ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []},
        "ns2.example.com.": {"ipv4": ["192.0.2.2"], "ipv6": []},
    }
    result = dnsmod.tcp53_support("example.com", ns_map)
    assert result["ok"] is True
    assert result["all_supported"] is True
    assert set(result["supported"]) == {"ns1.example.com.", "ns2.example.com."}
    assert result["unsupported"] == []


def test_tcp53_support_partial_failure(monkeypatch):
    """One NS accepts TCP/53, the other times out. Both must be
    surfaced with their correct classification — a partial answer is
    a real risk (resolvers hit different NSes; large answers randomly
    break)."""
    import dns.message

    def _fake_tcp(q, ip, timeout=None):
        if ip == "192.0.2.2":
            raise TimeoutError("simulated TCP/53 refused")
        return dns.message.QueryMessage()
    monkeypatch.setattr(dnsmod.dns.query, "tcp", _fake_tcp)
    ns_map = {
        "ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []},
        "ns2.example.com.": {"ipv4": ["192.0.2.2"], "ipv6": []},
    }
    result = dnsmod.tcp53_support("example.com", ns_map)
    assert result["ok"] is True
    assert result["all_supported"] is False
    assert result["supported"] == ["ns1.example.com."]
    assert result["unsupported"] == ["ns2.example.com."]


def test_tcp53_support_all_fail(monkeypatch):
    """Zero NSes accept TCP/53. Downstream must FAIL — the zone is
    resolvable only for tiny responses."""
    def _fake_tcp(q, ip, timeout=None):
        raise ConnectionRefusedError("simulated TCP/53 closed")
    monkeypatch.setattr(dnsmod.dns.query, "tcp", _fake_tcp)
    ns_map = {
        "ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []},
    }
    result = dnsmod.tcp53_support("example.com", ns_map)
    assert result["ok"] is True
    assert result["all_supported"] is False
    assert result["unsupported"] == ["ns1.example.com."]


def test_tcp53_support_skips_ns_with_no_ips(monkeypatch):
    """An NS with no A / AAAA records cannot be probed at all. Must
    appear in `skipped`, not incorrectly categorised as unsupported —
    unretrievable is not the same as broken (rule 1)."""
    def _fake_tcp(q, ip, timeout=None):
        import dns.message
        return dns.message.QueryMessage()
    monkeypatch.setattr(dnsmod.dns.query, "tcp", _fake_tcp)
    ns_map = {
        "ns1.example.com.": {"ipv4": [], "ipv6": []},
        "ns2.example.com.": {"ipv4": ["192.0.2.2"], "ipv6": []},
    }
    result = dnsmod.tcp53_support("example.com", ns_map)
    assert result["skipped"] == ["ns1.example.com."]
    assert result["supported"] == ["ns2.example.com."]


# --------------------------------------------------------------------- integration: _nameservers emission

_CLEAN_ENV = {
    "safe": True, "notes": [],
    "safe_for_per_ns_checks": True, "safe_for_axfr": True,
    "safe_for_direct_dns": True,
}


def _run_nameservers(monkeypatch, tcp_out, env=None):
    """Drive `_nameservers` with all other DNS calls stubbed so only
    the TCP/53 emission path exercises the finding."""
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": ns_map})
    monkeypatch.setattr(c.dnsmod, "parent_delegation",
                        lambda d: {"ok": False, "error": "stub"})
    monkeypatch.setattr(c.dnsmod, "probe_each_ns",
                        lambda d, m: {h: {"reachable": True,
                                          "authoritative": True,
                                          "serial": 1, "rtt_ms": 10}
                                      for h in m})
    monkeypatch.setattr(c.dnsmod, "tcp53_support", lambda d, m: tcp_out)
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = env or _CLEAN_ENV
    c._nameservers(rep, "example.com", skip_asn=True)
    return rep


def _findings(rep, label):
    return [f for f in rep.findings if f.label == label]


def test_all_ns_support_tcp53_is_pass(monkeypatch):
    """Load-bearing hardening/correctness signal: every NS supports
    TCP/53. PASS."""
    rep = _run_nameservers(monkeypatch,
                           {"ok": True, "all_supported": True,
                            "supported": ["ns1.example.com."],
                            "unsupported": [], "skipped": []})
    findings = _findings(rep, "Nameserver TCP/53 support")
    assert findings, (
        f"expected `Nameserver TCP/53 support` finding; got labels: "
        f"{[f.label for f in rep.findings]}"
    )
    assert findings[0].status == "PASS"


def test_partial_tcp53_failure_is_warn(monkeypatch):
    """One of two NSes refuses TCP/53. Any resolver retrying over TCP
    that lands on the broken one gets no answer — a real breakage
    risk for large DNSSEC responses. WARN (not FAIL) because the zone
    still resolves through the working NS. Not hardening — this is
    real correctness."""
    rep = _run_nameservers(monkeypatch,
                           {"ok": True, "all_supported": False,
                            "supported": ["ns1.example.com."],
                            "unsupported": ["ns2.example.com."],
                            "skipped": []})
    findings = _findings(rep, "Nameserver TCP/53 support")
    assert findings
    f = findings[0]
    assert f.status == "WARN"
    assert f.hardening is False, (
        "TCP/53 refusal by any NS is a real breakage path for large "
        "responses / DNSSEC — must not be routed to hardening"
    )
    assert "ns2.example.com" in f.detail
    assert "7766" in f.detail or "RFC 7766" in f.detail


def test_all_tcp53_fail_is_fail(monkeypatch):
    """Zero NSes accept TCP/53. The zone is broken for anything larger
    than the UDP 512-byte cap — DNSSEC validation, large TXT, etc.
    FAIL — not just a hardening gap."""
    rep = _run_nameservers(monkeypatch,
                           {"ok": True, "all_supported": False,
                            "supported": [],
                            "unsupported": ["ns1.example.com."],
                            "skipped": []})
    findings = _findings(rep, "Nameserver TCP/53 support")
    assert findings
    assert findings[0].status == "FAIL"


def test_tcp53_probe_failure_produces_unknown(monkeypatch):
    """The probe itself couldn't run (env self-test flagged TCP
    out-of-scope, or ns_map was empty). Rule 1 + rule 5: never confabulate
    a confident finding here."""
    rep = _run_nameservers(monkeypatch,
                           {"ok": False, "error": "env_no_tcp"})
    findings = _findings(rep, "Nameserver TCP/53 support")
    assert findings
    assert findings[0].status == "UNKNOWN"


def test_env_tcp_blocked_skips_probe(monkeypatch):
    """Rule 5: when the environment self-test says TCP is blocked, the
    check MUST report UNKNOWN — a target-side FAIL under a blocked
    environment is the exact false-broken class CLAUDE.md forbids
    ('reported absent when the truth is unretrievable')."""
    called = {"n": 0}

    def _spy(d, m):
        called["n"] += 1
        return {"ok": True, "all_supported": True, "supported": list(m),
                "unsupported": [], "skipped": []}
    ns_map = {"ns1.example.com.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": ns_map})
    monkeypatch.setattr(c.dnsmod, "parent_delegation",
                        lambda d: {"ok": False, "error": "stub"})
    monkeypatch.setattr(c.dnsmod, "tcp53_support", _spy)
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {
        "safe": False, "notes": ["TCP/53 blocked"],
        "safe_for_per_ns_checks": False, "safe_for_axfr": False,
        "safe_for_direct_dns": False,
    }
    c._nameservers(rep, "example.com", skip_asn=True)
    findings = _findings(rep, "Nameserver TCP/53 support")
    # Either: no finding emitted at all (folded into the reachability
    # UNKNOWN block that already skips), OR an explicit UNKNOWN with the
    # env-blocked reason. Both preserve rule-1 separation. The
    # load-bearing invariant is: the probe was NOT run.
    assert called["n"] == 0, (
        "TCP/53 probe must not run when the env self-test says TCP is "
        "blocked — a confident FAIL/PASS on an untrustworthy path is "
        "the exact rule-5 violation"
    )
    # If a finding was emitted, it must be UNKNOWN.
    for f in findings:
        assert f.status == "UNKNOWN", (
            f"under blocked env, TCP/53 finding must be UNKNOWN, "
            f"got {f.status}"
        )
