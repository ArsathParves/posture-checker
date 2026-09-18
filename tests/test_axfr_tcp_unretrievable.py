"""Regression tests for D6 — AXFR path lacked the TxtUnretrievable symmetry.

For SPF/DKIM/DMARC (N2), a truncated TXT with TCP/53 blocked raises
`TxtUnretrievable` and downstream reports UNKNOWN with a specific
"TCP/53 unavailable on this network path" reason (correct per
CLAUDE.md rule 1: `unretrievable` never collapses into `absent`/`broken`).

AXFR runs over TCP exclusively. When the environment self-test flagged
`tcp53_direct=False`, the old code still issued a real AXFR attempt,
which produced a generic timeout/reset per NS. The downstream UNKNOWN
copy said "TCP/53 may be blocked" as speculation, not confirmation, so
operators could not distinguish "test never had a chance" from "we tried
and the server misbehaved".

Fix: when `env["tcp53_direct"] is False`, `_security` marks AXFR as
untestable up front, with a specific detail naming the TCP/53 pre-flight.
No probes are issued (nothing they return could be trusted). The
open-resolver check runs regardless — it only needs UDP.
"""
from __future__ import annotations

from unittest.mock import patch

import posture.dnsmod as dnsmod


def test_axfr_short_circuits_when_tcp53_is_blocked():
    """No AXFR probes may be issued when the env self-test says TCP/53
    is unavailable — the result cannot be trusted either way."""
    from posture import checks
    from posture.core import Report

    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {"safe_for_per_ns_checks": True, "tcp53_direct": False}
    rep.data["ns_map"] = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}

    def fake_open_resolver(_ns_map):
        return {"any_open": False, "per_ns": {}}

    with patch.object(dnsmod, "axfr_open_check") as mock_axfr, \
         patch.object(dnsmod, "open_resolver_check", side_effect=fake_open_resolver):
        checks._security(rep, "example.com")

    assert not mock_axfr.called, "AXFR must not be probed when TCP/53 is unavailable"


def test_axfr_untestable_yields_unknown_with_specific_detail():
    """The finding must name TCP/53 explicitly (parity with the TXT
    `TRUNCATED_NO_TCP` finding text). Generic "could not test" hides
    the actionable signal."""
    from posture import checks
    from posture.core import Report

    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {"safe_for_per_ns_checks": True, "tcp53_direct": False}
    rep.data["ns_map"] = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}

    def fake_open_resolver(_ns_map):
        return {"any_open": False, "per_ns": {}}

    with patch.object(dnsmod, "open_resolver_check", side_effect=fake_open_resolver):
        checks._security(rep, "example.com")

    findings = [f for f in rep.findings if "AXFR" in f.label]
    assert findings, "expected an AXFR finding"
    f = findings[0]
    assert f.status == "UNKNOWN"
    detail = f.detail.lower()
    assert "tcp/53" in detail or "tcp 53" in detail, \
        f"expected TCP/53 named in AXFR untestable detail; got: {f.detail!r}"
    assert "untestable" in detail or "unavailable" in detail or "blocked" in detail, \
        f"expected explicit unretrievable phrasing; got: {f.detail!r}"


def test_axfr_still_runs_when_tcp53_is_available():
    """Regression guard — the short-circuit must be narrowly scoped to
    the `tcp53_direct=False` case. When TCP/53 is fine, AXFR runs as
    before."""
    from posture import checks
    from posture.core import Report

    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {"safe_for_per_ns_checks": True, "tcp53_direct": True}
    rep.data["ns_map"] = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}

    def fake_open_resolver(_ns_map):
        return {"any_open": False, "per_ns": {}}

    with patch.object(dnsmod, "axfr_open_check", return_value={"any_open": False,
                                                                "per_ns": {"ns1.example.":
                                                                    {"tested": True, "open": False, "reason": "refused"}}}) as mock_axfr, \
         patch.object(dnsmod, "open_resolver_check", side_effect=fake_open_resolver):
        checks._security(rep, "example.com")

    assert mock_axfr.called, "AXFR must still run when TCP/53 is available"


def test_open_resolver_still_runs_when_only_tcp53_is_blocked():
    """Open-resolver detection uses UDP; a TCP/53 block must NOT suppress it."""
    from posture import checks
    from posture.core import Report

    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {"safe_for_per_ns_checks": True, "tcp53_direct": False}
    rep.data["ns_map"] = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}

    called = [0]
    def fake_open_resolver(_ns_map):
        called[0] += 1
        return {"any_open": False,
                "per_ns": {"ns1.example.": {"tested": True, "open": False,
                                            "ra_flag": False, "answered_foreign": False,
                                            "partial_recursion": False,
                                            "subnet_variance": False}}}

    with patch.object(dnsmod, "open_resolver_check", side_effect=fake_open_resolver):
        checks._security(rep, "example.com")

    assert called[0] == 1, "open-resolver check must still run when only TCP/53 is blocked"
