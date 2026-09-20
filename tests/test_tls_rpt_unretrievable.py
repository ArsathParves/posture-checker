"""Regression tests for the TLS-RPT half of C2's follow-up.

The MTA-STS side of evaluate_mta_sts already handles TxtUnretrievable
correctly (see tests/test_mta_sts.py). The TLS-RPT lookup does NOT:

    def evaluate_mta_sts(domain):
        try:
            sts_records = _txt_records(f"_mta-sts.{domain}")
        except TxtUnretrievable:
            return {"mta_sts": None, "tls_rpt": None, "unretrievable": True}
        txts = [t for t in sts_records if t.lower().startswith("v=stsv1")]
        tlsrpt = [t for t in _txt_records(f"_smtp._tls.{domain}")   # <-- can raise
                  if t.lower().startswith("v=tlsrptv1")]
        return {"mta_sts": bool(txts), "tls_rpt": bool(tlsrpt)}

If ``_smtp._tls.<domain>`` is truncated / TCP/53 is blocked, the inner
lookup raises TxtUnretrievable and the whole call blows up — the caller
loses even the MTA-STS answer that was already computed.

If instead the exception were swallowed and ``bool(tlsrpt)`` were computed
as False, that's a CLAUDE.md **rule-1** violation: reporting "TLS-RPT
absent" for a domain that in fact publishes one, purely because the
lookup was truncated.

Fix contract:
  - MTA-STS retrievable + TLS-RPT retrievable  → both booleans
  - MTA-STS retrievable + TLS-RPT unretrievable → ``mta_sts`` is bool,
    ``tls_rpt`` is None, and result carries a ``tls_rpt_unretrievable``
    marker so checks.py can render TLS-RPT as UNKNOWN, not WARN/absent.
  - MTA-STS unretrievable → existing behaviour preserved (both None,
    ``unretrievable`` flag set).

The orchestrator side (checks.py::_email_auth) must consult the marker
and skip the TLS-RPT finding when it is set, exactly as it already
skips both when MTA-STS is unretrievable.
"""
from __future__ import annotations

from unittest.mock import patch

import posture.emailauth as ea


class _StubResolver:
    """Return supplied records for named TXT queries; raise
    TxtUnretrievable for names in the ``unretrievable`` set. Modelled on
    dnspython's answer shape used by ``_txt_records`` callers."""

    def __init__(self, retrievable: dict[str, list[str]],
                 unretrievable: set[str]):
        self.retrievable = retrievable
        self.unretrievable = unretrievable

    def __call__(self, name: str) -> list[str]:
        if name in self.unretrievable:
            raise ea.TxtUnretrievable(f"simulated truncation on {name}")
        return self.retrievable.get(name, [])


def test_tls_rpt_unretrievable_does_not_break_the_mta_sts_answer():
    """When _smtp._tls.<domain> is unretrievable but _mta-sts.<domain>
    is fine, evaluate_mta_sts must NOT propagate TxtUnretrievable — the
    MTA-STS finding is real and must survive."""
    stub = _StubResolver(
        retrievable={"_mta-sts.example.com": ["v=STSv1; id=20240101T000000"]},
        unretrievable={"_smtp._tls.example.com"},
    )
    with patch.object(ea, "_txt_records", side_effect=stub):
        result = ea.evaluate_mta_sts("example.com")
    assert result["mta_sts"] is True, (
        f"MTA-STS answer must survive a TLS-RPT lookup failure; got {result}"
    )


def test_tls_rpt_unretrievable_marks_tls_rpt_as_unknown_not_false():
    """CLAUDE.md rule 1: unretrievable != absent. When the TLS-RPT
    lookup can't be completed, ``tls_rpt`` must be None (unknown), not
    False (absent). A False here would render "TLS-RPT absent" for a
    domain whose TLS-RPT record we simply couldn't read."""
    stub = _StubResolver(
        retrievable={"_mta-sts.example.com": ["v=STSv1; id=20240101T000000"]},
        unretrievable={"_smtp._tls.example.com"},
    )
    with patch.object(ea, "_txt_records", side_effect=stub):
        result = ea.evaluate_mta_sts("example.com")
    assert result["tls_rpt"] is None, (
        f"TLS-RPT must be None (unknown) when the lookup was unretrievable; "
        f"got {result}"
    )


def test_tls_rpt_unretrievable_sets_marker():
    """The result must carry a ``tls_rpt_unretrievable`` marker so the
    orchestrator can distinguish this case from an all-retrievable
    lookup with no record present."""
    stub = _StubResolver(
        retrievable={"_mta-sts.example.com": ["v=STSv1; id=20240101T000000"]},
        unretrievable={"_smtp._tls.example.com"},
    )
    with patch.object(ea, "_txt_records", side_effect=stub):
        result = ea.evaluate_mta_sts("example.com")
    assert result.get("tls_rpt_unretrievable") is True, (
        f"result must carry tls_rpt_unretrievable=True marker; got {result}"
    )


def test_both_retrievable_leaves_no_unretrievable_markers():
    """Sanity: when both lookups succeed, neither the whole-record
    ``unretrievable`` flag nor the TLS-RPT-specific marker should be set."""
    stub = _StubResolver(
        retrievable={
            "_mta-sts.example.com": ["v=STSv1; id=20240101T000000"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:a@example.com"],
        },
        unretrievable=set(),
    )
    with patch.object(ea, "_txt_records", side_effect=stub):
        result = ea.evaluate_mta_sts("example.com")
    assert result["mta_sts"] is True
    assert result["tls_rpt"] is True
    assert not result.get("unretrievable")
    assert not result.get("tls_rpt_unretrievable")


def test_orchestrator_renders_tls_rpt_as_unknown_when_unretrievable():
    """Rule-1 boundary at the orchestrator layer: when
    evaluate_mta_sts returns ``tls_rpt=None`` + the unretrievable
    marker, the TLS-RPT finding must be emitted as UNKNOWN, not as
    WARN/absent. MTA-STS finding must still be emitted normally.

    Exercises ``checks._emit_mta_sts_findings`` — the small helper
    that renders the MTA-STS/TLS-RPT block from an evaluate_mta_sts
    result. Extracted from ``_email`` so the emit layer is testable
    without stubbing SPF/DKIM/DMARC lookups (unrelated code paths
    that would otherwise need mocks just to reach this branch)."""
    from posture.core import Report
    from posture import checks

    rep = Report(domain_input="example.com", domain="example.com")

    fake_sts = {
        "mta_sts": True,
        "tls_rpt": None,
        "tls_rpt_unretrievable": True,
    }
    checks._emit_mta_sts_findings(rep, "Email authentication", fake_sts)

    labels = {(f.label, f.status) for f in rep.findings}
    assert ("MTA-STS", "PASS") in labels, (
        f"MTA-STS should still emit PASS; got findings={rep.findings}"
    )
    tls_rpt_findings = [f for f in rep.findings if f.label == "TLS-RPT"]
    assert tls_rpt_findings, (
        f"TLS-RPT finding must be emitted (as UNKNOWN, not skipped); "
        f"got {rep.findings}"
    )
    assert tls_rpt_findings[0].status == "UNKNOWN", (
        f"TLS-RPT must render as UNKNOWN when the lookup was "
        f"unretrievable, not WARN; got status={tls_rpt_findings[0].status}"
    )


def test_orchestrator_renders_tls_rpt_normally_when_retrievable():
    """Sanity: the helper must still render TLS-RPT as PASS/WARN when
    the lookup was fine — no regression on the common path."""
    from posture.core import Report
    from posture import checks

    for present, expected_status in [(True, "PASS"), (False, "WARN")]:
        rep = Report(domain_input="example.com", domain="example.com")
        sts = {"mta_sts": True, "tls_rpt": present}
        checks._emit_mta_sts_findings(rep, "Email authentication", sts)
        tls_rpt = [f for f in rep.findings if f.label == "TLS-RPT"]
        assert tls_rpt and tls_rpt[0].status == expected_status, (
            f"TLS-RPT present={present} should emit {expected_status}; "
            f"got {[(f.label, f.status) for f in rep.findings]}"
        )
