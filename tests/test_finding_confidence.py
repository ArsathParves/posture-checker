"""T5 — per-finding confidence field.

A DNS/DNSSEC/registration check draws on evidence of varying quality:

  - `high`   — authoritative-server read, multi-vantage consensus,
               well-validated cryptographic computation
               (DS→DNSKEY chain).
  - `medium` — single-resolver answer, cached response, or a single-
               probe result that agrees with the tool's expectation.
  - `low`    — indirect / inferred signal (e.g. "MTA-STS policy fetch
               timed out, but the TXT record is present"), or a
               partial-probe result.
  - `""`     — default; caller did not set a confidence claim.

An honest tool separates itself from a confident-but-wrong one by
saying so. T5 adds the FIELD; migration of specific emit sites to
declare `confidence=` is follow-up work (same shape as T2's
mechanism-first / migration-later pattern).

Confidence does NOT influence grading in either direction. It is a
UI/reporting signal only. If it fed into grading, callers would be
tempted to downgrade a broken finding to `low` to soften the report,
which is the exact opposite of the intent.
"""
from __future__ import annotations

from posture import checks as c
from posture.core import Report, Finding


# --------------------------------------------------------------------- dataclass field

def test_finding_has_confidence_default_empty():
    """Backward compatibility: every pre-T5 `Finding(...)` construction
    still works. The default is empty (not `"high"` — implicit high-
    confidence would silently mask uncertainty)."""
    f = Finding("Security posture", "test", "PASS", "detail")
    assert f.confidence == ""


def test_finding_accepts_confidence():
    f = Finding("Security posture", "test", "PASS", "detail",
                confidence="high")
    assert f.confidence == "high"


def test_report_add_accepts_confidence_kwarg():
    """rep.add must forward `confidence` to the Finding. Load-bearing:
    every migrated caller declares confidence at the emit site — a
    global label-to-confidence map would drift out of sync."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("DNSSEC", "Chain validates", "PASS",
            "DS matches DNSKEY, RRSIG verifies", "",
            confidence="high")
    assert len(rep.findings) == 1
    assert rep.findings[0].confidence == "high"


def test_report_add_defaults_confidence_to_empty():
    """Existing callers pass no `confidence` — result must be `""`,
    not `None` and not `"high"`. This is the regression test that
    prevents a well-meaning future refactor from setting a non-empty
    default."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Core records", "IPv4 (A)", "PASS", "93.184.216.34")
    assert rep.findings[0].confidence == ""


# --------------------------------------------------------------------- serialisation

def test_f2d_includes_confidence():
    """`_f2d` (the wire-format serialiser used by both CLI and web) MUST
    surface confidence. Without this, the UI cannot show it and the
    field is invisible outside the Python object model."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Nameserver posture", "Cross-resolver consensus", "PASS",
            "3/3 resolvers agree", "",
            confidence="high")
    d = c._f2d(rep.findings[0])
    assert d.get("confidence") == "high"


def test_report_to_dict_includes_confidence():
    """End-to-end: the JSON dict returned by `_report_to_dict` (what
    web/server.py serves to the browser and CLI `--json` emits) MUST
    carry confidence per finding."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("DNSSEC", "Chain validates", "PASS", "verified", "",
            confidence="high")
    rep.add("Email authentication", "MTA-STS policy", "WARN",
            "policy fetch timed out; TXT present", "",
            confidence="low")
    d = c._report_to_dict(rep)
    confidences = [f["confidence"] for f in d["findings"]]
    assert confidences == ["high", "low"]


# --------------------------------------------------------------------- grading orthogonality

def test_confidence_does_not_affect_grading():
    """Regression backstop: `confidence` must NOT change grading in
    either direction. Grades are driven by status + hardening +
    severity only. If confidence fed into grading, callers would be
    tempted to downgrade a broken finding to `low` to soften the
    report."""
    # Baseline: 9 PASSes → A.
    rep = Report(domain_input="example.com", domain="example.com")
    for i in range(9):
        rep.add("Nameserver posture", f"check-{i}", "PASS", "")
    baseline = c.grade(rep)
    baseline_band = baseline["sections"]["Nameserver posture"][0]

    # Same 9 PASSes but every finding declares `confidence=low`.
    rep2 = Report(domain_input="example.com", domain="example.com")
    for i in range(9):
        rep2.add("Nameserver posture", f"check-{i}", "PASS", "",
                 confidence="low")
    with_low = c.grade(rep2)

    assert with_low["sections"]["Nameserver posture"][0] == baseline_band, (
        f"declaring low confidence must not degrade a PASS section — "
        f"baseline={baseline_band}, low-confidence={with_low['sections']['Nameserver posture'][0]}"
    )


def test_confidence_default_preserves_backward_compat_grading():
    """A `Finding` constructed with the pre-T5 signature (positional
    args, no confidence kwarg) grades identically to one with an
    explicit `confidence=""`."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Core records", "IPv4 (A)", "PASS", "93.184.216.34")
    rep.add("Core records", "IPv6 (AAAA)", "WARN", "missing")
    result = c.grade(rep)
    assert "Core records" in result["sections"]
