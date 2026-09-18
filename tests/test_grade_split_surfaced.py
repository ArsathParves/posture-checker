"""Regression tests for G1 — the correctness/hardening 80/20 split had no
UI surface. `grade()` computed both sub-grades internally but only the
"Overall" letter was rendered. A user seeing `Overall: B` could not tell
whether correctness was A and hardening D (adopt DNSSEC, done) or
correctness was D and hardening A (a real misconfiguration masked by full
hardening adoption). These two situations demand very different operator
actions.

Pins two invariants:

  (1) `grade(rep)` returns both `correctness_grade` and `hardening_grade`
      as top-level keys, always — a "—" placeholder when a category has no
      scored findings, never absent. Callers (CLI text renderer, web SSE
      payload, JSON output, downstream reports) must be able to rely on
      the keys existing.

  (2) The CLI header renders BOTH sub-grades when both are present. A
      change that dropped one of them from the header would be a G1
      regression regardless of whether the numeric `overall` is still
      correct — the whole point is that operators can see the split.

The web path is covered indirectly: `posture.checks.run_streaming` emits
`{"event":"complete", "grades": grade(rep)}` (checks.py:187), so pinning
`grade()`'s return shape pins the SSE payload shape. The web renderer
(`web/static/app.js:179-183`) reads `grades.correctness_grade` and
`grades.hardening_grade` by name — dropping them from `grade()` would
break the web UI too.
"""
from __future__ import annotations

import io

from rich.console import Console

from posture import cli as cli_mod
from posture.checks import grade
from posture.core import Finding, Report


def _mixed_report() -> Report:
    """A report with BOTH correctness findings (Nameserver count, SPF)
    and a hardening-absence finding (DNSSEC not_configured). Grading
    should produce distinct letters for correctness vs hardening."""
    rep = Report(domain_input="example.com", domain="example.com",
                 punycode="example.com")
    rep.findings = [
        Finding("Nameservers", "Nameserver count", "PASS", "4 nameservers"),
        Finding("Email auth", "SPF", "PASS", "v=spf1 -all"),
        # hardening=True: DNSSEC state=not_configured is deliberate non-adoption,
        # not misconfiguration. Post-G2 the emit site (_dnssec) sets this itself.
        Finding("DNSSEC", "DNSSEC status", "FAIL",
                "Zone not signed — DS/DNSKEY absent", hardening=True),
    ]
    rep.data["dnssec"] = {"state": "not_configured"}
    return rep


# ---------------------------- grade() shape ------------------------------

def test_grade_return_includes_correctness_and_hardening_keys():
    """Both sub-grade keys must be present on the returned dict — this is
    the contract the CLI, JSON output, and web SSE payload all depend on."""
    rep = _mixed_report()
    g = grade(rep)
    assert "correctness_grade" in g, \
        f"grade() must expose 'correctness_grade'; got keys: {sorted(g)}"
    assert "hardening_grade" in g, \
        f"grade() must expose 'hardening_grade'; got keys: {sorted(g)}"


def test_grade_sub_grades_are_distinct_when_categories_disagree():
    """The whole reason for the split: a report with clean correctness but
    unadopted hardening (DNSSEC absent) must show A/B correctness and a
    lower hardening — not one letter that hides both."""
    rep = _mixed_report()
    g = grade(rep)
    # Correctness findings: 2 PASS (Nameserver count, SPF). DNSSEC absent
    # is treated as hardening absence per HARDENING_ABSENCE.
    # Correctness: 2/2 PASS → A. Hardening: 0/1 → F.
    assert g["correctness_grade"] == "A", \
        f"expected correctness=A with two PASS + only-hardening-absent DNSSEC; got {g['correctness_grade']}"
    assert g["hardening_grade"] == "F", \
        f"expected hardening=F with DNSSEC state=not_configured and no other hardening; got {g['hardening_grade']}"
    assert g["correctness_grade"] != g["hardening_grade"], \
        "the whole point of G1 is that sub-grades can differ; they must not always collapse"


def test_grade_sub_grade_keys_present_even_when_no_hardening_findings():
    """Backward-compat guard: when there are no hardening-absence
    findings at all, `hardening_grade` should still exist as `"—"`, not
    be absent from the dict."""
    rep = Report(domain_input="example.com", domain="example.com",
                 punycode="example.com")
    rep.findings = [
        Finding("Nameservers", "Nameserver count", "PASS", "4 nameservers"),
    ]
    g = grade(rep)
    assert "hardening_grade" in g
    assert g["hardening_grade"] == "—"


# ---------------------------- CLI rendering ------------------------------

def _render_to_string(rep: Report) -> str:
    """Capture the CLI's rich-rendered header/panels as a plain string
    the tests can grep."""
    buf = io.StringIO()
    captured = Console(file=buf, width=200, force_terminal=False, color_system=None)
    orig = cli_mod.console
    cli_mod.console = captured
    try:
        cli_mod.render(rep, show_info=True, as_json=False)
    finally:
        cli_mod.console = orig
    return buf.getvalue()


def test_cli_header_shows_both_sub_grades():
    """The CLI header panel must label BOTH sub-grades explicitly. A user
    reading the terminal output should see 'Correctness' and 'Hardening'
    beside their letters, not just an unqualified 'Overall'."""
    rep = _mixed_report()
    out = _render_to_string(rep)
    assert "Correctness" in out, \
        f"CLI header must name the correctness sub-grade; not found in:\n{out}"
    assert "Hardening" in out, \
        f"CLI header must name the hardening sub-grade; not found in:\n{out}"


def test_cli_json_output_includes_both_sub_grades():
    """`--json` output is the machine-readable contract. The `grades`
    block must expose both sub-grades so downstream consumers (CI
    scripts, monitoring, dashboards) can act on the split."""
    import json

    rep = _mixed_report()
    buf = io.StringIO()

    import contextlib
    with contextlib.redirect_stdout(buf):
        cli_mod.render(rep, show_info=True, as_json=True)

    payload = json.loads(buf.getvalue())
    assert "grades" in payload
    assert "correctness_grade" in payload["grades"], \
        f"--json grades must include correctness_grade; got: {sorted(payload['grades'])}"
    assert "hardening_grade" in payload["grades"], \
        f"--json grades must include hardening_grade; got: {sorted(payload['grades'])}"
