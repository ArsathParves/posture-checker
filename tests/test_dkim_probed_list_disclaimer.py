"""BIAS-7 — DKIM "no selectors found" must surface the probed list.

The pre-BIAS-7 emit read simply ``Not found under N common selectors``
with a why line noting DKIM selectors aren't DNS-discoverable. That's
the correct rule-1 posture (UNKNOWN, not FAIL), but the reader is
left with an opaque N — they can't tell:

  - whether their ESP's selector was in the tried set,
  - which selectors WERE tried (so they can spot-check),
  - what the escape hatch is (--dkim-selector for a custom name).

Result in practice: pre-sales engineer looks at "Not found under 26
common selectors" for an Indian BFSI customer using Netcore or ZeptoMail,
concludes DKIM is misconfigured, and the WARN turns into a false lead.

BIAS-7 fix: emit UNKNOWN with the probed-list head + a count of the
rest, and a why line naming --dkim-selector as the follow-up. The
list is the ground-truth evidence that supports the UNKNOWN verdict;
without it, an UNKNOWN is indistinguishable from a hand-wave.

Two invariants this test locks:

1. ``evaluate_dkim`` returns ``probed_selectors`` as a list. Callers
   (checks._email) rely on it; the CLI --json output may render it.
   Missing the key silently degrades the disclaimer back to opaque.
2. The ``DKIM`` UNKNOWN emit contains AT LEAST the first few probed
   selectors verbatim in its detail string, AND its why mentions
   ``--dkim-selector`` as the escape hatch. Wording-flexible on the
   why (locked as a substring) so future copy-edits don't regress
   the invariant.
"""
from __future__ import annotations

from unittest.mock import patch

import posture.emailauth as ea
from posture import checks
from posture.core import Report


# --------------------------------------------------------------------- primitive

def test_evaluate_dkim_returns_probed_selectors_list():
    """The probed-selector list travels in the return dict as
    ``probed_selectors``. Downstream renderers need the actual names,
    not just a count, so a follow-up run with --dkim-selector can
    verify a real custom selector was NOT already tried."""
    with patch.object(ea, "_txt_records", side_effect=lambda name: []):
        result = ea.evaluate_dkim("example.com")

    assert "probed_selectors" in result, (
        "evaluate_dkim must return the probed-selector list under "
        "'probed_selectors' so the caller can render an evidence-"
        "backed UNKNOWN disclaimer instead of an opaque count"
    )
    probed = result["probed_selectors"]
    assert isinstance(probed, list) and len(probed) > 0, (
        f"probed_selectors must be a non-empty list; got {probed!r}"
    )
    # Every entry is a string (a selector label).
    assert all(isinstance(s, str) for s in probed), (
        f"probed_selectors must be strings; got types "
        f"{sorted({type(s).__name__ for s in probed})}"
    )


def test_evaluate_dkim_probed_selectors_includes_extras():
    """User-supplied extras via --dkim-selector must appear in the
    probed list — otherwise the CLI escape hatch is invisible in the
    output."""
    with patch.object(ea, "_txt_records", side_effect=lambda name: []):
        result = ea.evaluate_dkim("example.com",
                                   extra_selectors=["netcore-esp",
                                                    "zeptomail-1"])
    probed = result.get("probed_selectors") or []
    assert "netcore-esp" in probed, (
        "extra selector 'netcore-esp' missing from probed_selectors — "
        f"got {probed[:10]}..."
    )
    assert "zeptomail-1" in probed, (
        "extra selector 'zeptomail-1' missing from probed_selectors"
    )


# --------------------------------------------------------------------- emit

def _run_email_dkim_only(monkeypatch, dkim_result: dict) -> Report:
    """Drive `_email` far enough to emit the DKIM finding, then stop.
    Stubs SPF/DMARC/MTA-STS out so the DKIM branch is isolated."""
    rep = Report(domain_input="example.test", domain="example.test",
                 punycode="example.test")
    rep.data["records"] = {"MX": {"records": ["10 mx.example.test"]},
                            "A": {"records": ["203.0.113.1"]},
                            "AAAA": {"records": []}}
    rep.data["environment"] = {"safe_for_per_ns_checks": True,
                                "safe_for_direct_dns": True}
    # Stub every emailauth call except the DKIM branch we want to exercise.
    monkeypatch.setattr(checks.emailauth, "evaluate_spf",
                        lambda d: {"present": True, "record": "v=spf1 -all",
                                   "multiple": False, "lookup_count": 0,
                                   "all_strength": "hardfail",
                                   "all_qualifier": "-all"})
    monkeypatch.setattr(checks.emailauth, "evaluate_dkim",
                        lambda d, sel=None: dkim_result)
    monkeypatch.setattr(checks.emailauth, "evaluate_dmarc",
                        lambda d: {"present": True, "policy": "reject",
                                    "pct": 100, "strength": "strong",
                                    "rua": None, "ruf": None,
                                    "subdomain_policy": None,
                                    "alignment_dkim": "r",
                                    "alignment_spf": "r"})
    monkeypatch.setattr(checks.emailauth, "evaluate_mta_sts",
                        lambda d: {"mta_sts": False, "tls_rpt": False})
    checks._email(rep, "example.test", None)
    return rep


def test_dkim_not_found_emit_names_probed_selectors(monkeypatch):
    """The DKIM UNKNOWN branch — the ONE the pre-sales SE reads on
    every no-DKIM-selectors-published Indian BFSI zone — must include
    the head of the probed list in the detail. Without it, an SE
    cannot verify their guess about the customer's ESP selector."""
    dkim = {
        "found": False, "selectors": [], "revoked": [],
        "probed": 4, "probed_selectors": ["default", "selector1",
                                            "google", "netcore"],
        "wildcard": False,
        "label": "Not found under common selectors",
    }
    rep = _run_email_dkim_only(monkeypatch, dkim)
    dkim_findings = [f for f in rep.findings if f.label == "DKIM"]
    assert len(dkim_findings) == 1, (
        f"expected 1 DKIM finding; got {len(dkim_findings)}: "
        f"{[f.detail for f in dkim_findings]}"
    )
    f = dkim_findings[0]
    assert f.status == "UNKNOWN", (
        f"DKIM 'not found' MUST emit UNKNOWN (rule 1); got {f.status!r}. "
        f"detail={f.detail!r}"
    )
    # Every probed selector must appear in the detail so the reader
    # can spot-check their ESP's selector was tried.
    for sel in ["default", "selector1", "google", "netcore"]:
        assert sel in f.detail, (
            f"probed selector {sel!r} missing from DKIM UNKNOWN "
            f"detail: {f.detail!r}"
        )


def test_dkim_not_found_why_names_the_cli_escape_hatch(monkeypatch):
    """The why line must name ``--dkim-selector`` — otherwise a reader
    has no discoverable next step. This is the same reasoning as the
    environment-notes surfacing (L1): the tool computed useful info,
    it MUST show the reader how to act on it."""
    dkim = {
        "found": False, "selectors": [], "revoked": [],
        "probed": 3, "probed_selectors": ["default", "s1", "s2"],
        "wildcard": False,
        "label": "Not found under common selectors",
    }
    rep = _run_email_dkim_only(monkeypatch, dkim)
    f = [x for x in rep.findings if x.label == "DKIM"][0]
    assert "--dkim-selector" in f.why, (
        f"DKIM UNKNOWN why-line must mention `--dkim-selector` as the "
        f"escape hatch; got {f.why!r}"
    )
    # Rule-1 reminder must still be present — the disclaimer is what
    # keeps UNKNOWN from being read as FAIL.
    assert "does NOT prove" in f.why or "not prove DKIM is absent" in f.why, (
        f"DKIM UNKNOWN why-line must retain the rule-1 disclaimer "
        f"('not-discoverable does not prove absence'); got {f.why!r}"
    )


def test_dkim_long_probed_list_truncates_with_count(monkeypatch):
    """A probed list of 30+ selectors would blow the terminal detail
    column. Truncate to the head with a ``(…and N more)`` tail so the
    total is still visible without wrapping four lines of table."""
    long_list = [f"sel{i}" for i in range(30)]
    dkim = {
        "found": False, "selectors": [], "revoked": [],
        "probed": len(long_list), "probed_selectors": long_list,
        "wildcard": False,
        "label": "Not found under common selectors",
    }
    rep = _run_email_dkim_only(monkeypatch, dkim)
    f = [x for x in rep.findings if x.label == "DKIM"][0]
    # First few must appear; last few must not appear (they're the truncated tail).
    assert "sel0" in f.detail and "sel1" in f.detail
    assert "sel29" not in f.detail, (
        f"tail selector 'sel29' unexpectedly present — truncation "
        f"failed: {f.detail!r}"
    )
    # Truncation summary must be present, naming how many more were tried.
    assert "and 22 more" in f.detail or "…and 22 more" in f.detail, (
        f"truncation summary '(…and 22 more)' missing from detail: "
        f"{f.detail!r}"
    )
