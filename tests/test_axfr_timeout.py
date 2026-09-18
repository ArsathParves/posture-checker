"""Regression tests for D3 — AXFR timeout is a hardcoded 5s TIMEOUT and
timeout failures are lumped into a generic "tested: False, reason: <exc>"
bucket. On high-latency links this both slows the run and produces
false-alarm UNKNOWNs the operator cannot act on ("TCP/53 blocked" is only
one of several possible causes).

Fix:
  1. Expose the AXFR timeout as its own module constant (`AXFR_TIMEOUT`)
     so operators/tests can tune it independently of the other query
     timeouts.
  2. Classify `dns.exception.Timeout` explicitly as `reason="timeout"`
     (not the raw exception class name) so downstream can render a
     specific message.

CLAUDE.md rule 1 pin: the *conclusion* stays UNKNOWN — a timeout is not
"refused" (PASS) and it is not "open" (FAIL). The classification only
improves *why* the result is UNKNOWN, never *what* it says.
"""
from __future__ import annotations

from unittest.mock import patch

import dns.exception

import posture.dnsmod as dnsmod


def test_axfr_timeout_is_a_named_module_constant():
    """Operators tune AXFR patience separately from other DNS timeouts —
    a 5s cap that works for record lookups is too short for a full zone
    transfer over TCP on a high-latency link."""
    assert hasattr(dnsmod, "AXFR_TIMEOUT")
    assert isinstance(dnsmod.AXFR_TIMEOUT, (int, float))
    assert dnsmod.AXFR_TIMEOUT > 0


def test_axfr_uses_the_configured_timeout(monkeypatch):
    """The constant must actually flow into the dns.query.xfr call.
    Guards against 'added constant but forgot to wire it up'."""
    monkeypatch.setattr(dnsmod, "AXFR_TIMEOUT", 17.5)
    captured: dict = {}

    def fake_xfr(ip, domain, timeout=None, lifetime=None, **kwargs):
        captured["timeout"] = timeout
        captured["lifetime"] = lifetime
        raise dns.exception.Timeout()  # short-circuit — we only care about kwargs

    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    with patch("dns.query.xfr", side_effect=fake_xfr):
        dnsmod.axfr_open_check("example.com", ns_map)

    assert captured["timeout"] == 17.5, "AXFR_TIMEOUT must flow into dns.query.xfr(timeout=)"


def test_timeout_is_classified_specifically_not_as_generic_error():
    """Before the fix a Timeout produced {reason: 'Timeout'} (the class
    name) alongside every other exception; operators cannot tell whether
    TCP/53 is blocked, the peer is slow, or something else broke. Pin
    the classification to a stable string."""
    def fake_xfr(ip, domain, timeout=None, lifetime=None, **kwargs):
        raise dns.exception.Timeout()

    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    with patch("dns.query.xfr", side_effect=fake_xfr):
        out = dnsmod.axfr_open_check("example.com", ns_map)

    host_result = out["per_ns"]["ns1.example."]
    assert host_result["tested"] is False
    assert host_result["reason"] == "timeout"
    # Conclusion untouched: never leak a false PASS from a timeout.
    assert out["any_open"] is False


def test_refused_state_is_not_reclassified_as_timeout():
    """Regression guard: only Timeout is remapped to 'timeout'. A real
    TransferError refusal is still 'refused' (contributes to PASS)."""
    import dns.xfr as _xfr

    def fake_xfr(ip, domain, timeout=None, lifetime=None, **kwargs):
        raise _xfr.TransferError(1)

    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    with patch("dns.query.xfr", side_effect=fake_xfr):
        out = dnsmod.axfr_open_check("example.com", ns_map)

    host_result = out["per_ns"]["ns1.example."]
    assert host_result["tested"] is True
    assert host_result["open"] is False
    assert host_result["reason"] == "refused"


def test_checks_surface_names_timeout_in_unknown_message():
    """When AXFR could not be tested because *every* NS timed out, the
    downstream finding must name 'timeout' specifically. A generic
    'could not test' hides the actionable signal (slow link vs. blocked
    port vs. malformed peer)."""
    from posture import checks
    from posture.core import Report

    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {"safe_for_per_ns_checks": True}
    rep.data["ns_map"] = {
        "ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []},
        "ns2.example.": {"ipv4": ["192.0.2.2"], "ipv6": []},
    }

    def fake_xfr(ip, domain, timeout=None, lifetime=None, **kwargs):
        raise dns.exception.Timeout()

    # short-circuit open_resolver_check so the security section only exercises AXFR
    def fake_open_resolver(_ns_map):
        return {"any_open": False, "per_ns": {}}

    with patch("dns.query.xfr", side_effect=fake_xfr), \
         patch.object(dnsmod, "open_resolver_check", side_effect=fake_open_resolver):
        checks._security(rep, "example.com")

    axfr_findings = [f for f in rep.findings if "Zone transfer" in f.label]
    assert axfr_findings, "expected an AXFR finding"
    f = axfr_findings[0]
    assert f.status == "UNKNOWN"
    assert "timeout" in f.detail.lower(), \
        f"expected 'timeout' in the UNKNOWN detail, got: {f.detail!r}"
