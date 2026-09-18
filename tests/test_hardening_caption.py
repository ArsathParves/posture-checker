"""Regression tests for L2 — the grade model treats deliberate non-
adoption of optional hardening features (DNSSEC unsigned by choice,
no CAA, no MTA-STS, no TLS-RPT) as a hardening-bucket penalty rather
than a correctness FAIL. That is by design — google.com must not
grade a D just because it declined DNSSEC — but the header only ever
rendered two letters ("Correctness: A · Hardening: C") and never
named *which* optional features accounted for the gap.

The user sees the worse letter, reads it as "broken", and lands on
the wrong mental model. The fix names the specific hardening
features not adopted, so "Hardening: C" is decodable ("no MTA-STS,
no TLS-RPT") rather than opaque.

Contract:
  - `grade()` returns a new field `hardening_gaps: list[str]` — the
    check labels of hardening findings that scored WARN/FAIL (i.e.
    the un-adopted features). A PASS hardening finding does not
    appear. Order is stable so downstream renderers don't re-shuffle.
  - Field is always present (empty list on a fully-adopted domain).
  - CLI header appends a legend line naming those labels when the
    list is non-empty AND correctness_grade differs from
    hardening_grade (i.e. the gap is worth explaining). No legend
    on a homogeneous grade — the case doesn't need explanation.
  - Web JSON output exposes `hardening_gaps` unchanged so a UI can
    render it too (deferred to a separate web task).
"""
from __future__ import annotations

from posture.checks import grade
from posture.core import Finding, Report


def _report(findings):
    rep = Report(domain_input="example.com", domain="example.com",
                 punycode="example.com")
    for f in findings:
        rep.findings.append(f)
    return rep


def test_grade_output_exposes_hardening_gaps_list():
    """The field must exist even on a clean report so callers can
    treat it as a stable schema key rather than an optional field
    that appears only sometimes."""
    rep = _report([Finding("Core records", "A record", "PASS", "203.0.113.1")])
    g = grade(rep)
    assert "hardening_gaps" in g, (
        f"grade() must expose a `hardening_gaps` list even when empty. "
        f"Got keys: {sorted(g.keys())}"
    )
    assert isinstance(g["hardening_gaps"], list)
    assert g["hardening_gaps"] == []


def test_hardening_gaps_lists_only_unadopted_hardening_findings():
    """A hardening PASS is *credit* (adopted). Only WARN/FAIL
    hardening findings represent gaps — those are what the user needs
    to see to make sense of a lower hardening grade."""
    rep = _report([
        Finding("DNSSEC", "DNSSEC status", "FAIL", "Not configured", "", hardening=True),
        Finding("Security posture", "CAA record", "PASS", "present", "", hardening=True),
        Finding("Email authentication", "MTA-STS", "WARN", "not published", "", hardening=True),
        Finding("Email authentication", "TLS-RPT", "WARN", "not published", "", hardening=True),
        # A non-hardening WARN must NOT appear
        Finding("Core records", "A record", "WARN", "no A", "", hardening=False),
        # A hardening PASS must NOT appear
        Finding("Security posture", "AAAA record (IPv6)", "PASS", "…", "", hardening=True),
    ])
    g = grade(rep)
    assert g["hardening_gaps"] == [
        "DNSSEC status", "MTA-STS", "TLS-RPT",
    ], (
        f"hardening_gaps must list only WARN/FAIL hardening findings, "
        f"in emit order. Got {g['hardening_gaps']}"
    )


def test_hardening_gaps_empty_when_all_hardening_findings_pass():
    """Guard the empty-list default: a domain that has adopted every
    optional feature should not have a phantom empty entry."""
    rep = _report([
        Finding("DNSSEC", "DNSSEC status", "PASS", "validating", "", hardening=True),
        Finding("Security posture", "CAA record", "PASS", "present", "", hardening=True),
        Finding("Email authentication", "MTA-STS", "PASS", "published", "", hardening=True),
    ])
    g = grade(rep)
    assert g["hardening_gaps"] == []


def test_cli_header_names_the_hardening_gaps_when_grades_diverge():
    """The CLI header currently shows "Correctness: A · Hardening: C"
    with no context. This test pins that when the two sub-grades
    differ AND hardening_gaps is non-empty, the header text names the
    specific missing features so the user can decode the letter."""
    from io import StringIO
    from rich.console import Console

    from posture import cli

    rep = _report([
        Finding("Core records", "A record", "PASS", "203.0.113.1", ""),
        Finding("Core records", "MX record", "PASS", "…", ""),
        # 5 hardening features: 2 adopted, 3 not — enough to produce
        # a hardening C without any correctness FAIL.
        Finding("Security posture", "CAA record", "PASS", "present", "", hardening=True),
        Finding("Security posture", "AAAA record (IPv6)", "PASS", "…", "", hardening=True),
        Finding("DNSSEC", "DNSSEC status", "FAIL", "Not configured", "", hardening=True),
        Finding("Email authentication", "MTA-STS", "WARN", "not published", "", hardening=True),
        Finding("Email authentication", "TLS-RPT", "WARN", "not published", "", hardening=True),
    ])

    buf = StringIO()
    cli.console = Console(file=buf, force_terminal=False, width=200)
    cli.render(rep, show_info=False)
    text = buf.getvalue()

    # Header must call out at least the DNSSEC label (the deliberate-
    # non-adoption case the audit specifically named)
    assert "DNSSEC status" in text, (
        f"CLI header must name the specific hardening features not "
        f"adopted so 'Hardening: C' is decodable. Header text: {text!r}"
    )
    # And the legend anchor phrase — an operator scanning the header
    # for "why is my hardening grade low" should hit a labelled line
    assert "Hardening" in text and (
        "not adopted" in text.lower() or "missing" in text.lower()
        or "optional" in text.lower()
    ), (
        f"CLI header must include a labelled explanation of the "
        f"hardening gap. Header text: {text!r}"
    )


def test_no_hardening_legend_when_grades_match():
    """When correctness and hardening are the same letter, the legend
    is noise — no gap to explain. This keeps the common case quiet."""
    from io import StringIO
    from rich.console import Console

    from posture import cli

    rep = _report([
        Finding("Core records", "A record", "PASS", "203.0.113.1", ""),
        Finding("DNSSEC", "DNSSEC status", "PASS", "validating", "", hardening=True),
        Finding("Security posture", "CAA record", "PASS", "present", "", hardening=True),
    ])

    buf = StringIO()
    cli.console = Console(file=buf, force_terminal=False, width=200)
    cli.render(rep, show_info=False)
    text = buf.getvalue()

    # No legend line — the two grades agree, no explanation is warranted
    assert "not adopted" not in text.lower(), (
        f"When correctness_grade == hardening_grade, the header must "
        f"NOT render the hardening-gap legend (noise). Text: {text!r}"
    )
