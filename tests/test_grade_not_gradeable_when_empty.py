"""B6 — a fully-degraded run still emits a confident letter grade.

If every check returns UNKNOWN or the run bailed before any finding was
scored, `_grade_set` correctly returns `"—"` for the correctness and
hardening buckets, but `overall` falls through to the worst/avg
computation. `bands` is empty; `max(..., default=0)` yields `0` →
`overall_idx = 0` → **"A"**. The header renders "Overall posture: A"
next to "provisional", giving the illusion that the tool assessed the
domain and rated it fine, when in fact the tool got no data at all.

CLAUDE.md rule 1: the three states (not-applicable / unretrievable /
broken) must never collapse. Reporting "A" for a run with zero scored
findings collapses "unretrievable across every section" into "posture
looks great." A meaningless grade rendered identically to a real one
is exactly the failure mode rule 1 exists to prevent.

Fix: when there is nothing to grade — every scored bucket is empty —
`overall` MUST be `"—"` ("Not gradeable"), not a letter. The
`provisional` flag stays True as a compatibility contract for
downstream renderers that already treated it as "this is soft".

Renderers (`posture/cli.py`, `web/static/app.js`) already handle the
`"—"` band elsewhere (`GRADE_COLOR["—"] = "dim"`, correctness/hardening
already suppressed when their letter is `"—"`); overall now joins that
set of legitimate non-letter values.
"""
from __future__ import annotations

from posture.core import Report
from posture.checks import grade


def _empty_report(domain="degraded.example.com") -> Report:
    """A Report with no findings — models the fully-degraded run where
    every section bailed to UNKNOWN before adding a scored finding, and
    even UNKNOWN emit was skipped (e.g. run_streaming bailed on NXDOMAIN
    before section fan-out). Zero findings is the load-bearing state
    for this bug."""
    return Report(domain_input=domain, domain=domain, punycode=domain)


def _unknown_only_report(domain="degraded.example.com") -> Report:
    """A Report where every finding is UNKNOWN (network path broken but
    the check attempted anyway). UNKNOWN has `is_scored = False` — same
    zero-scored-findings state as the empty case, but exercises the
    UNKNOWN-listing side of `provisional`."""
    rep = Report(domain_input=domain, domain=domain, punycode=domain)
    for sec in ("Registration & delegation", "Nameserver operator",
                "DNS resolution", "DNSSEC", "Email authentication"):
        rep.add(sec, f"probe {sec}", "UNKNOWN", "could not retrieve")
    return rep


# --------------------------------------------------------------------- overall

def test_empty_report_overall_is_not_gradeable():
    """The load-bearing assertion: zero scored findings must produce
    the "Not gradeable" band (`"—"`), never a letter. This is the
    concrete B6 acceptance criterion."""
    rep = _empty_report()
    g = grade(rep)
    assert g["overall"] == "—", (
        f"empty report must not produce a letter grade; got "
        f"overall={g['overall']!r} — likely the worst/avg fallback "
        f"is landing on 'A' via `default=0` on max([])"
    )


def test_unknown_only_report_overall_is_not_gradeable():
    """UNKNOWN findings are unscored (`is_scored=False`); a report full
    of UNKNOWNs has zero scored findings and must also grade as
    'Not gradeable'. This is the operational failure mode: DNS
    interception makes every section UNKNOWN and the user reads 'A'."""
    rep = _unknown_only_report()
    g = grade(rep)
    assert g["overall"] == "—"
    assert g["provisional"] is True, (
        "provisional must still be True when there are unresolved "
        "sections — the ungradeable state is 'no data', which is "
        "definitionally soft"
    )


def test_empty_report_correctness_and_hardening_stay_dash():
    """Sub-grades are already correct for the empty case; guard against
    a fix that overreaches and mutates them."""
    rep = _empty_report()
    g = grade(rep)
    assert g["correctness_grade"] == "—"
    assert g["hardening_grade"] == "—"


# --------------------------------------------------------------------- regression backstops

def test_report_with_one_pass_still_grades_A():
    """The fix must NOT push borderline cases toward '—'. A single
    scored PASS is enough to grade — the "no data" case is strictly
    zero-scored, not "some data but not much"."""
    rep = Report(domain_input="ok.example.com", domain="ok.example.com",
                 punycode="ok.example.com")
    rep.add("Registration & delegation", "Domain resolves", "PASS", "resolves")
    g = grade(rep)
    assert g["overall"] == "A", (
        f"single-PASS report must still grade A; got {g['overall']!r}"
    )


def test_report_with_only_info_findings_is_not_gradeable():
    """INFO findings are unscored (`is_scored=False` per core.py). A
    report of only INFO rows carries no gradable signal — must also
    fall to '—', not fall through to 'A'."""
    rep = Report(domain_input="info.example.com", domain="info.example.com",
                 punycode="info.example.com")
    rep.add("Input", "Normalisation", "INFO", "punycode: idn.example.com")
    rep.add("Input", "Note", "INFO", "no MX — email auth skipped")
    g = grade(rep)
    assert g["overall"] == "—", (
        f"INFO-only report has zero scored findings; must not grade "
        f"as a letter. got overall={g['overall']!r}"
    )


def test_cli_header_renders_not_gradeable_phrase(capsys):
    """The acceptance criterion phrases it as "Not gradeable" — a
    user-facing string, not an em-dash. Guard the CLI header text so a
    future renderer refactor can't silently regress back to the raw
    "—". Uses the CLI's own render path against a synthetic empty
    report."""
    from posture import cli

    rep = _empty_report()
    # `render` prints via a module-level rich Console. Capture stdout.
    cli.render(rep, show_info=True, as_json=False, strict=False)
    out = capsys.readouterr().out
    assert "Not gradeable" in out, (
        f"CLI header must render the phrase 'Not gradeable' for a "
        f"fully-degraded run, not the raw '—'. Output was:\n{out}"
    )


def test_report_with_one_fail_still_grades_a_letter():
    """A single FAIL must still surface as a letter (F under strict
    signal), not '—'. Guard against a fix that treats "one finding"
    as "not enough data"."""
    rep = Report(domain_input="broken.example.com", domain="broken.example.com",
                 punycode="broken.example.com")
    rep.add("Registration & delegation", "Domain resolves", "FAIL",
            "SERVFAIL from all resolvers")
    g = grade(rep)
    assert g["overall"] in ("D", "F"), (
        f"single-FAIL report must produce a letter grade (D or F); "
        f"got {g['overall']!r}"
    )
