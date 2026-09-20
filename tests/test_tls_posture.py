"""B30 — TLS / HTTPS posture.

The tool audits DNS-plane hygiene extensively but never inspects the
serving-plane security posture. A BFSI SE briefing a customer expects
at minimum:

  - Certificate expiry — the #1 outage class after registration lapse.
  - Negotiated TLS protocol version — TLS 1.0/1.1 deprecated by
    RFC 8996; PCI-DSS forbids 1.0.
  - HSTS header — RFC 6797. `Strict-Transport-Security` with
    `max-age` ≥ 6 months is the industry baseline; missing HSTS is a
    hardening gap for a bank.

CAA-vs-served-issuer alignment (RFC 8659 §3, is the actually-issued
cert's CA permitted by the CAA policy) is DEFERRED to a follow-up —
requires cert-issuer normalisation against CAA CA identifier strings
which is not a one-commit change.

Rule 1: an HTTPS probe that fails to connect emits UNKNOWN, never
FAIL. A customer domain may serve HTTPS from a load balancer that
throttles our IP; we must never conflate "we could not reach the
service" with "the service is broken".

Rule 5: gated on `env.safe_for_direct_dns` — an intercepted TLS path
(corporate MITM CA in the trust store) would produce false PASS on
chain validity. Skip silently rather than emit misleading results.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from posture import tlsprobe, checks as c
from posture.core import Report


_CLEAN_ENV = {
    "safe": True, "notes": [],
    "safe_for_per_ns_checks": True, "safe_for_axfr": True,
    "safe_for_direct_dns": True, "tcp53_direct": True,
}


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _future(days: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days)


def _past(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


# --------------------------------------------------------------------- probe_tls primitive

def test_probe_tls_returns_cert_and_protocol(monkeypatch):
    """The primitive must return normalised cert info (not_before,
    not_after, issuer, subject) plus the negotiated protocol string.
    All downstream findings key off this shape — the contract is the
    testable surface."""
    fake_cert = {
        "subject": ((("commonName", "www.example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
        "subjectAltName": (("DNS", "www.example.com"), ("DNS", "example.com")),
    }

    class FakeSock:
        def getpeercert(self): return fake_cert
        def version(self): return "TLSv1.3"
        def close(self): pass

    monkeypatch.setattr(tlsprobe, "_open_tls_socket",
                        lambda h, p, t: FakeSock())
    res = tlsprobe.probe_tls("example.com")
    assert res["ok"] is True
    assert res["protocol"] == "TLSv1.3"
    assert res["cert"]["subject_cn"] == "www.example.com"
    assert res["cert"]["issuer_cn"] == "Test CA"
    assert res["cert"]["not_after"].startswith("2027-01-01")
    assert "example.com" in res["cert"]["san"]


def test_probe_tls_timeout_is_unknown(monkeypatch):
    """Rule 1: connection timeout must not be reported as a cert or
    protocol failure — the check simply didn't run."""
    import socket
    def raise_timeout(h, p, t):
        raise socket.timeout("timed out")
    monkeypatch.setattr(tlsprobe, "_open_tls_socket", raise_timeout)
    res = tlsprobe.probe_tls("example.com")
    assert res["ok"] is False
    assert res["error"] == "timeout"


def test_probe_tls_cert_verify_failure_is_reported_distinctly(monkeypatch):
    """Chain validation failures need their own error tag — a Solutions
    Engineer must be able to distinguish "we couldn't reach the host"
    from "we reached it and the cert is broken"."""
    import ssl
    def raise_verify(h, p, t):
        raise ssl.SSLCertVerificationError("verify failed")
    monkeypatch.setattr(tlsprobe, "_open_tls_socket", raise_verify)
    res = tlsprobe.probe_tls("example.com")
    assert res["ok"] is False
    assert res["error"] == "cert_verify_failed"


# --------------------------------------------------------------------- probe_hsts primitive

def test_probe_hsts_present_full_value(monkeypatch):
    class FakeResp:
        status_code = 200
        headers = {"Strict-Transport-Security":
                   "max-age=31536000; includeSubDomains; preload"}
    monkeypatch.setattr(tlsprobe.requests, "get",
                        lambda url, **kw: FakeResp())
    res = tlsprobe.probe_hsts("example.com")
    assert res["ok"] is True
    assert res["present"] is True
    assert res["max_age"] == 31536000
    assert res["include_subdomains"] is True
    assert res["preload"] is True


def test_probe_hsts_absent(monkeypatch):
    class FakeResp:
        status_code = 200
        headers = {}
    monkeypatch.setattr(tlsprobe.requests, "get",
                        lambda url, **kw: FakeResp())
    res = tlsprobe.probe_hsts("example.com")
    assert res["ok"] is True
    assert res["present"] is False


def test_probe_hsts_network_error_is_unknown(monkeypatch):
    """Rule 1: request timeout → UNKNOWN, not `hsts absent`. Otherwise
    a corporate firewall blocking the tool would show the customer's
    bank as "no HSTS" when the truth is "we couldn't tell"."""
    import requests as _req
    def raise_timeout(url, **kw):
        raise _req.exceptions.Timeout("timed out")
    monkeypatch.setattr(tlsprobe.requests, "get", raise_timeout)
    res = tlsprobe.probe_hsts("example.com")
    assert res["ok"] is False
    assert res["error"] == "Timeout"


# --------------------------------------------------------------------- emission: cert expiry

def _stub_probes(monkeypatch, tls=None, hsts=None):
    if tls is not None:
        monkeypatch.setattr(c.tlsprobe, "probe_tls", lambda d: tls)
    if hsts is not None:
        monkeypatch.setattr(c.tlsprobe, "probe_hsts", lambda d: hsts)


def _run_tls_section(monkeypatch, tls_result, hsts_result):
    _stub_probes(monkeypatch, tls=tls_result, hsts=hsts_result)
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = _CLEAN_ENV
    c._tls_posture(rep, "example.com")
    return rep


def test_cert_expiry_healthy_is_pass(monkeypatch):
    tls = {"ok": True, "protocol": "TLSv1.3",
           "cert": {"subject_cn": "example.com",
                    "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(90)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 31536000,
            "include_subdomains": True, "preload": False}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "Certificate expiry"][0]
    assert f.status == "PASS"


def test_cert_expiry_soon_is_warn(monkeypatch):
    tls = {"ok": True, "protocol": "TLSv1.3",
           "cert": {"subject_cn": "example.com",
                    "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(15)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 31536000,
            "include_subdomains": True, "preload": False}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "Certificate expiry"][0]
    assert f.status == "WARN"


def test_cert_expiry_imminent_is_fail(monkeypatch):
    """Cert expires in <7 days → FAIL. A cert-expiry-driven outage is
    an "operations lost track" event and is the second most common
    customer-visible outage after registration lapse."""
    tls = {"ok": True, "protocol": "TLSv1.3",
           "cert": {"subject_cn": "example.com",
                    "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(3)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 31536000,
            "include_subdomains": True, "preload": False}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "Certificate expiry"][0]
    assert f.status == "FAIL"


def test_cert_already_expired_is_fail(monkeypatch):
    tls = {"ok": True, "protocol": "TLSv1.3",
           "cert": {"subject_cn": "example.com",
                    "issuer_cn": "Test CA",
                    "not_before": _iso(_past(400)),
                    "not_after": _iso(_past(2)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 31536000,
            "include_subdomains": True, "preload": False}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "Certificate expiry"][0]
    assert f.status == "FAIL"


# --------------------------------------------------------------------- emission: TLS version

def test_tls13_is_pass(monkeypatch):
    tls = {"ok": True, "protocol": "TLSv1.3",
           "cert": {"subject_cn": "example.com", "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(90)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 31536000,
            "include_subdomains": True, "preload": False}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "TLS protocol version"][0]
    assert f.status == "PASS"


def test_tls12_is_pass(monkeypatch):
    tls = {"ok": True, "protocol": "TLSv1.2",
           "cert": {"subject_cn": "example.com", "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(90)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 31536000,
            "include_subdomains": True, "preload": False}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "TLS protocol version"][0]
    assert f.status == "PASS"


def test_tls11_is_fail(monkeypatch):
    """RFC 8996 formally deprecates TLS 1.0 and 1.1; PCI-DSS forbids
    TLS 1.0 for cardholder data. An SE briefing a bank must call this
    out as a FAIL, not a hardening WARN."""
    tls = {"ok": True, "protocol": "TLSv1.1",
           "cert": {"subject_cn": "example.com", "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(90)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 31536000,
            "include_subdomains": True, "preload": False}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "TLS protocol version"][0]
    assert f.status == "FAIL"


# --------------------------------------------------------------------- emission: HSTS

def test_hsts_present_long_maxage_is_pass(monkeypatch):
    tls = {"ok": True, "protocol": "TLSv1.3",
           "cert": {"subject_cn": "example.com", "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(90)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 31536000,
            "include_subdomains": True, "preload": True}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "HSTS"][0]
    assert f.status == "PASS"


def test_hsts_short_maxage_is_warn(monkeypatch):
    """max-age < 6 months (15,552,000 s) is below the industry
    baseline. WARN — the header exists but its safety window is short."""
    tls = {"ok": True, "protocol": "TLSv1.3",
           "cert": {"subject_cn": "example.com", "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(90)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 3600,
            "include_subdomains": False, "preload": False}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "HSTS"][0]
    assert f.status == "WARN"


def test_hsts_absent_is_hardening_warn(monkeypatch):
    """HSTS absence is a hardening gap (WARN), not a FAIL — the site
    still works over HTTPS. The `hardening=True` flag routes this to
    the hardening bucket so the correctness grade stays clean."""
    tls = {"ok": True, "protocol": "TLSv1.3",
           "cert": {"subject_cn": "example.com", "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(90)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": False}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    f = [f for f in rep.findings if f.label == "HSTS"][0]
    assert f.status == "WARN"
    assert f.hardening is True


# --------------------------------------------------------------------- unretrievable / gated

def test_tls_probe_failure_is_unknown_not_fail(monkeypatch):
    """Rule 1: if the TLS probe cannot reach the host, we emit UNKNOWN.
    A `Certificate expiry` FAIL when we didn't even see a cert would be
    the exact false finding rule 1 forbids."""
    tls = {"ok": False, "error": "timeout"}
    hsts = {"ok": False, "error": "Timeout"}
    rep = _run_tls_section(monkeypatch, tls, hsts)
    cert_f = [f for f in rep.findings if f.label == "Certificate expiry"]
    tls_f = [f for f in rep.findings if f.label == "TLS protocol version"]
    hsts_f = [f for f in rep.findings if f.label == "HSTS"]
    assert cert_f and cert_f[0].status == "UNKNOWN"
    assert tls_f and tls_f[0].status == "UNKNOWN"
    assert hsts_f and hsts_f[0].status == "UNKNOWN"


def test_tls_section_skipped_when_env_not_safe(monkeypatch):
    """Rule 5: an intercepted TLS path (corporate MITM CA in the trust
    store) would produce false PASS on chain validity. When the env
    self-test says the direct-DNS path is unsafe, skip the whole
    section — emit a single UNKNOWN row explaining why."""
    tls = {"ok": True, "protocol": "TLSv1.3",
           "cert": {"subject_cn": "example.com", "issuer_cn": "Test CA",
                    "not_before": _iso(_past(30)),
                    "not_after": _iso(_future(90)),
                    "san": ["example.com"]}}
    hsts = {"ok": True, "present": True, "max_age": 31536000,
            "include_subdomains": True, "preload": False}
    _stub_probes(monkeypatch, tls=tls, hsts=hsts)
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {"safe_for_direct_dns": False}
    c._tls_posture(rep, "example.com")
    section_findings = [f for f in rep.findings
                        if f.section == "TLS & HTTPS"]
    assert section_findings, "must emit a skip explanation"
    assert all(f.status == "UNKNOWN" for f in section_findings)
