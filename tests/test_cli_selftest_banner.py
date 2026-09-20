"""Regression tests for L1 — the environment self-test result is
computed on every run but the specific notes ("UDP/53 is intercepted",
"TCP/53 is blocked") never reach the CLI header. A user seeing
"(provisional)" in yellow next to the grade has to guess **why** the
grade is provisional and, given how easy the small yellow marker is
to miss on a busy terminal, may miss the state entirely.

CLAUDE.md rule 5:

    Respect the environment self-test. If selftest.check_environment()
    reports the network path is untrustworthy, checks that depend on
    direct nameserver access MUST be suppressed and reported UNKNOWN.
    **Never produce a confident finding on an untrustworthy path.**

The tool honours the first half already (suppression + UNKNOWN inside
sections) but not the header — the user does not see a first-class
"your network was interfering" signal alongside the grade.

Fix contract (this test suite):

  (1) When `rep.data["environment"]["notes"]` is non-empty, the CLI
      renders those notes under the header as a "Self-test warnings"
      block. The specific note text is preserved verbatim so the user
      has an actionable diagnostic ("UDP/53 is intercepted:..." tells
      them the failure is at the network, not the domain).

  (2) When the environment is clean (empty notes), no banner appears —
      the vast majority of runs are on clean networks and mustn't be
      spammed with an empty warning.

  (3) The `(provisional)` yellow marker stays where it is; the banner
      is additive, not a replacement. Belt-and-braces against the
      audit's concern that the marker alone can be missed.
"""
from __future__ import annotations

import io

from rich.console import Console

from posture import cli as cli_mod
from posture.core import Finding, Report


def _render_to_string(rep: Report) -> str:
    """Rich-rendered header/panels captured as plain text. Mirrors the
    helper used by tests/test_grade_split_surfaced.py — same width, no
    colour codes to grep around."""
    buf = io.StringIO()
    captured = Console(file=buf, width=200, force_terminal=False,
                       color_system=None)
    orig = cli_mod.console
    cli_mod.console = captured
    try:
        cli_mod.render(rep, show_info=True, as_json=False)
    finally:
        cli_mod.console = orig
    return buf.getvalue()


def _report_with_env(notes: list[str], *, safe: bool = True) -> Report:
    """Report with a minimal PASS finding + supplied env notes so the
    render path exercises the header banner. The finding is present so
    the report is non-empty and produces a grade (otherwise the header
    surface is trivial and the test can't distinguish clean vs. noisy
    rendering)."""
    rep = Report(domain_input="example.com", domain="example.com",
                 punycode="example.com")
    rep.findings = [
        Finding("Nameserver posture", "Nameserver count", "PASS",
                "4 nameservers"),
    ]
    rep.data["environment"] = {
        "udp53_direct": True,
        "tcp53_direct": not any("TCP/53" in n for n in notes),
        "intercepted": any("intercepted" in n for n in notes),
        "aa_flag_trustworthy": True,
        "safe_for_per_ns_checks": safe,
        "notes": list(notes),
    }
    return rep


def test_banner_shows_env_notes_when_interception_detected():
    """The whole point of L1: when the self-test found DNS interception,
    the CLI must surface that specific reason next to the grade so the
    user knows the *network* is why the grade is provisional, not the
    domain."""
    note = ("UDP/53 is intercepted: 3/3 unrouted addresses returned "
            "DNS answers. Per-nameserver results cannot be trusted in "
            "this environment.")
    rep = _report_with_env([note], safe=False)
    rep.degraded.append("per-nameserver probing (environment)")

    out = _render_to_string(rep)
    assert "intercepted" in out.lower(), (
        f"CLI header must surface the env note about interception "
        f"verbatim (or at least the word 'intercepted'); not found in:\n{out}"
    )


def test_banner_shows_tcp53_blocked_note():
    """A second common env failure: TCP/53 is blocked. Users need to
    see this specific reason because the remediation differs from
    interception — a firewall rule, not a resolver override."""
    note = ("TCP/53 is blocked — truncated/large responses cannot be "
            "retried over TCP.")
    rep = _report_with_env([note], safe=True)
    out = _render_to_string(rep)
    assert "TCP/53" in out, (
        f"CLI header must name the specific TCP/53 blockage; "
        f"not found in:\n{out}"
    )


def test_banner_labels_the_block_so_users_know_what_it_is():
    """The banner must be self-describing — a random line of text
    prefixed with '⚠' would leave a user asking 'what is this'. Look
    for a self-test label so the user immediately understands the
    provenance."""
    rep = _report_with_env(
        ["UDP/53 is intercepted: probes returned answers"], safe=False,
    )
    out = _render_to_string(rep)
    assert "self-test" in out.lower(), (
        f"Env-notes banner must label itself with 'self-test' so users "
        f"know the source of the warning; not found in:\n{out}"
    )


def test_no_banner_when_environment_is_clean():
    """Regression guard: the banner is additive and must appear only
    when there's something to say. On a clean-network run — the common
    case — the header stays quiet."""
    rep = _report_with_env([], safe=True)
    out = _render_to_string(rep)
    # 'self-test' should not appear as a warning label; the word may
    # legitimately appear in other contexts, so gate on the label the
    # implementation uses.
    assert "self-test warning" not in out.lower(), (
        f"Clean environment must NOT emit a self-test banner; got:\n{out}"
    )
    assert "intercepted" not in out.lower(), (
        f"Clean environment must NOT surface interception copy; got:\n{out}"
    )


def test_provisional_marker_still_present_alongside_banner():
    """Belt-and-braces: the banner is additive to '(provisional)', not
    a replacement. Users grep-ing for either signal should find both."""
    rep = _report_with_env(
        ["UDP/53 is intercepted: probes returned answers"], safe=False,
    )
    # Adding a degraded entry ensures grade() marks provisional=True.
    rep.degraded.append("per-nameserver probing (environment)")
    out = _render_to_string(rep)
    assert "provisional" in out.lower(), (
        f"(provisional) marker must remain visible when a banner is "
        f"also shown; not found in:\n{out}"
    )
