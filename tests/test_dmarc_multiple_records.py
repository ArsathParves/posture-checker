"""Regression tests for E5 — multiple _dmarc records silently pick first.

RFC 7489 §6.6.3:

  If the set of records returned in response to a query with the type
  code TXT includes more than one record with an "adkim" tag or a
  "aspf" tag or a "p" tag, [receivers] apply no DMARC-based decision.

Practical effect: a domain publishing two `v=DMARC1` records has NO
DMARC policy — validators skip the whole check. The v0.5 parser did
`rec = txts[0]`, silently picking the first record and reporting it
as if it were the authoritative policy. This is a rule-1 violation:
the finding said "DMARC p=reject" when the ground truth was "DMARC
does not apply to this domain."

Fix:
  - `evaluate_dmarc` returns `multiple=True` and `all_records=[...]`
    when >1 v=DMARC1 records are seen (mirrors the SPF behaviour on
    the same file at line 119).
  - `_email` in checks.py emits an explicit `FAIL` with label
    `DMARC` and detail "Multiple DMARC records" naming §6.6.3 in the
    `why` — the operator gets an actionable, RFC-cited finding.
  - The single-record happy path is unchanged.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from posture import checks, emailauth
from posture.core import Report


DUPLICATE_DMARC = [
    "v=DMARC1; p=reject; rua=mailto:reports@example.com",
    "v=DMARC1; p=quarantine",
]


# ------------------------------------------------ evaluate_dmarc contract

def test_evaluate_dmarc_flags_multiple_records():
    with patch.object(emailauth, "_txt_records", return_value=DUPLICATE_DMARC):
        out = emailauth.evaluate_dmarc("example.com")
    assert out.get("multiple") is True, (
        f"evaluate_dmarc must flag multiple records; got {out!r}"
    )
    assert out.get("all_records") == DUPLICATE_DMARC, (
        f"all_records must preserve every v=DMARC1 record for the "
        f"finding to enumerate them; got {out.get('all_records')!r}"
    )


def test_evaluate_dmarc_single_record_is_unchanged():
    """Regression guard: the happy path (one v=DMARC1) must still
    return `multiple` unset / False and the parsed tags."""
    single = ["v=DMARC1; p=reject; rua=mailto:reports@example.com"]
    with patch.object(emailauth, "_txt_records", return_value=single):
        out = emailauth.evaluate_dmarc("example.com")
    assert out["present"] is True
    assert out.get("multiple") in (False, None), (
        f"single-record case must not set multiple; got {out!r}"
    )
    assert out.get("policy") == "reject"


def test_evaluate_dmarc_ignores_non_dmarc_txt_records():
    """Records that don't start with v=DMARC1 aren't DMARC records —
    they can co-exist with a single legitimate DMARC record and
    must NOT trigger the multiple-records path."""
    mixed = [
        "v=spf1 -all",   # SPF record accidentally under _dmarc.<domain>
        "v=DMARC1; p=reject",
    ]
    with patch.object(emailauth, "_txt_records", return_value=mixed):
        out = emailauth.evaluate_dmarc("example.com")
    assert out.get("multiple") in (False, None)
    assert out.get("policy") == "reject"


# ------------------------------------------------ finding emission

def _run_email_with_dmarc(monkeypatch, dmarc_out: dict) -> Report:
    """Drive `_email` through the DMARC branch with a synthetic result.

    Pre-populates `rep.data["records"]` so `_email`'s has_mx gate lets
    execution reach the DMARC branch. Neutralises SPF/DKIM/MTA-STS
    with empty stubs so their findings don't clutter the assertions."""
    from posture import checks as c

    monkeypatch.setattr(c.emailauth, "evaluate_dmarc",
                        lambda d: dmarc_out)
    monkeypatch.setattr(c.emailauth, "evaluate_spf",
                        lambda d: {"present": False})
    monkeypatch.setattr(c.emailauth, "evaluate_dkim",
                        lambda d, selectors: {"found": False, "probed": 0,
                                              "selectors": []})
    monkeypatch.setattr(c.emailauth, "evaluate_mta_sts",
                        lambda d: {"mta_sts": False, "tls_rpt": False})

    rep = Report(domain_input="example.com", domain="example.com")
    # Simulate a mail-operating domain so `_email` doesn't take the
    # "skipped — no MX no A" early return.
    rep.data["records"] = {
        "MX": {"records": [(10, "mail.example.com")]},
        "A": {"records": ["203.0.113.1"]},
        "AAAA": {"records": []},
    }
    c._email(rep, "example.com", None)
    return rep


def test_multiple_dmarc_emits_fail(monkeypatch):
    """The load-bearing test for E5: a domain with two DMARC records
    must generate a FAIL, not a PASS/WARN based on txts[0]."""
    rep = _run_email_with_dmarc(monkeypatch, {
        "present": True, "record": DUPLICATE_DMARC[0],
        "policy": "reject", "strength": "strong",
        "multiple": True, "all_records": DUPLICATE_DMARC,
        "rua": None, "ruf": None, "pct": "100",
        "alignment_dkim": "r", "alignment_spf": "r",
    })
    dmarc_findings = [f for f in rep.findings
                      if f.section == "Email authentication"
                      and "DMARC" in f.label]
    fails = [f for f in dmarc_findings if f.status == "FAIL"]
    assert fails, (
        f"multiple DMARC records must emit a FAIL; got findings: "
        f"{[(f.label, f.status, f.detail) for f in dmarc_findings]}"
    )
    fail = fails[0]
    assert "multiple" in fail.detail.lower() or "multiple" in fail.why.lower(), (
        f"FAIL text must name 'multiple' DMARC records; "
        f"got detail={fail.detail!r}, why={fail.why!r}"
    )
    assert "7489" in fail.why or "no dmarc" in fail.why.lower() or \
           "receivers apply no" in fail.why.lower(), (
        f"FAIL must explain that validators skip DMARC on multi-record "
        f"domains; why={fail.why!r}"
    )


def test_multiple_dmarc_does_not_also_emit_policy_pass(monkeypatch):
    """Belt-and-braces: when multiple records exist we must NOT also
    emit a normal DMARC-policy finding parsed from txts[0]. That's the
    exact false-signal the fix exists to prevent — a PASS row for a
    p=reject policy that validators are actually ignoring."""
    rep = _run_email_with_dmarc(monkeypatch, {
        "present": True, "record": DUPLICATE_DMARC[0],
        "policy": "reject", "strength": "strong",
        "multiple": True, "all_records": DUPLICATE_DMARC,
        "rua": None, "ruf": None, "pct": "100",
        "alignment_dkim": "r", "alignment_spf": "r",
    })
    passes = [f for f in rep.findings
              if f.section == "Email authentication"
              and f.label == "DMARC policy"
              and f.status == "PASS"]
    assert not passes, (
        f"multiple-records case must NOT ALSO emit a PASS 'DMARC policy' "
        f"finding — validators ignore both records, so no policy is in "
        f"force. Got: {[(f.label, f.status, f.detail) for f in passes]}"
    )
