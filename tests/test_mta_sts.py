"""Regression tests for C2 — evaluate_mta_sts issued two identical DNS
queries per invocation.

Original shape::

    def evaluate_mta_sts(domain):
        try:
            _probe = _txt_records(f"_mta-sts.{domain}")     # call #1 (probe)
        except TxtUnretrievable:
            return {"mta_sts": None, ..., "unretrievable": True}
        txts = [t for t in _txt_records(f"_mta-sts.{domain}")  # call #2 (real)
                if t.lower().startswith("v=stsv1")]
        ...

The probe existed to distinguish "unretrievable" (truncated / TCP-blocked)
from "absent" — a CLAUDE.md rule-1 requirement. But the second call re-
queries the same name; a flaky resolver can return records on the first
call and TxtUnretrievable on the second (or vice versa), producing an
inconsistent finding in a single run.

Fix: call once, reuse the returned list. TLS-RPT is a different name
(``_smtp._tls.<domain>``) so it stays a separate lookup — that is not the
bug this test targets. (A follow-up will add TxtUnretrievable handling
to the TLS-RPT lookup so it also does not collapse into a false absent.)
"""
from __future__ import annotations

from unittest.mock import patch

import posture.emailauth as ea


def test_mta_sts_queries_the_sts_name_once():
    """The MTA-STS host record ``_mta-sts.<domain>`` must be queried
    exactly once per evaluate_mta_sts call, not twice."""
    calls: list[str] = []

    def fake_txt(name: str):
        calls.append(name)
        # Return something that clearly isn't an STS record so the
        # branches downstream do not raise.
        return []

    with patch.object(ea, "_txt_records", side_effect=fake_txt):
        ea.evaluate_mta_sts("example.com")

    sts_calls = [c for c in calls if c == "_mta-sts.example.com"]
    assert len(sts_calls) == 1, (
        f"expected _mta-sts.example.com queried once; got {len(sts_calls)}: {calls}"
    )


def test_mta_sts_reports_present_when_stsv1_record_returned():
    """Sanity check that the single-call refactor still parses a real
    STS record correctly."""
    def fake_txt(name: str):
        if name == "_mta-sts.example.com":
            return ["v=STSv1; id=20240101T000000"]
        return []

    with patch.object(ea, "_txt_records", side_effect=fake_txt):
        result = ea.evaluate_mta_sts("example.com")
    assert result["mta_sts"] is True


def test_mta_sts_reports_absent_when_no_stsv1_record():
    def fake_txt(name: str):
        return []  # nothing for either name

    with patch.object(ea, "_txt_records", side_effect=fake_txt):
        result = ea.evaluate_mta_sts("example.com")
    assert result["mta_sts"] is False


def test_mta_sts_unretrievable_preserved():
    """CLAUDE.md rule 1: unretrievable != absent. If _txt_records raises
    TxtUnretrievable for the STS name, the result must carry the
    unretrievable marker rather than reporting mta_sts=False."""
    def fake_txt(name: str):
        raise ea.TxtUnretrievable("simulated truncation")

    with patch.object(ea, "_txt_records", side_effect=fake_txt):
        result = ea.evaluate_mta_sts("example.com")
    assert result.get("unretrievable") is True
    assert result["mta_sts"] is None
