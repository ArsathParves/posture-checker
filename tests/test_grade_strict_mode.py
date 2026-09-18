"""Regression tests for G4 — `grade()` had no strict mode.

Context: pre-production audits (a new domain about to go live, a
regulated environment about to certify) need a stricter scoring
model than day-2 operations. A `WARN` finding — "SPF has ~all
soft-fail" or "SOA has a very high TTL" — is usually acceptable in
production but should FAIL a go-live gate. Previously the grading
model only knew PASS/WARN/FAIL and used a fixed threshold; the only
way to fail a WARN-only report was to eyeball the section table.

Fix: `grade(rep, strict=False)` gains an opt-in `strict` mode.
Under strict:
  - Every scored WARN is treated as a FAIL for both `has_fail`
    detection AND numerical scoring (severity 0 instead of 1).
  - Hardening WARN/FAIL routing is preserved (WARNs promoted to
    FAIL still stay in the hardening bucket if they were hardening
    findings — strict tightens severity, not classification).
  - `provisional` is unaffected; UNKNOWN is still UNKNOWN.
  - Default is False — normal-mode reports are byte-identical to
    pre-G4 output.

Surface: CLI `--strict` flag. Web layer is intentionally out of
scope; a downstream ticket can expose it as a query parameter once
we know how operator dashboards want to consume the pair.
"""
from __future__ import annotations

import io
import sys

from posture.checks import grade
from posture.core import Finding, Report


def _report_with_only_warns() -> Report:
    """A report with only PASS + WARN findings — no genuine FAILs.
    Normal mode grades this above C; strict must drop it into the
    D/F band because every WARN is now a FAIL."""
    rep = Report(domain_input="staging.example", domain="staging.example")
    rep.findings = [
        Finding("Nameservers", "Nameserver count", "PASS", "4 NS"),
        Finding("Nameservers", "Nameserver reachability", "PASS", "4/4"),
        Finding("SOA & zone hygiene", "SOA REFRESH", "WARN",
                "REFRESH is 172800s (very high)"),
        Finding("Email authentication", "SPF 'all' qualifier", "WARN",
                "~all (soft fail)"),
    ]
    return rep


# ---------------------------- default behaviour --------------------------

def test_grade_default_is_not_strict():
    """Backward-compat guardrail: existing callers of `grade(rep)` must
    keep the pre-G4 behaviour. `strict=False` is the default."""
    rep = _report_with_only_warns()
    g_default = grade(rep)
    g_explicit = grade(rep, strict=False)
    assert g_default == g_explicit, (
        "grade(rep) and grade(rep, strict=False) must return byte-identical "
        "dicts — strict must not activate implicitly"
    )


def test_grade_strict_is_opt_in():
    """`strict=True` MUST tighten the grade, not just relabel it. If a
    report grades B in default mode with WARNs present, strict mode
    should produce a strictly worse letter (never A, and never the
    same letter — the whole point is that WARNs now count as FAIL)."""
    rep = _report_with_only_warns()
    normal = grade(rep)["overall"]
    strict = grade(rep, strict=True)["overall"]
    order = ["A", "B", "C", "D", "F"]
    assert order.index(strict) > order.index(normal), (
        f"strict mode must worsen overall grade when WARNs are present; "
        f"normal={normal!r} strict={strict!r}"
    )


# ---------------------------- strict semantics ---------------------------

def test_strict_treats_warns_as_fails_for_has_fail_detection():
    """`_band()` bumps a report into D/F when `has_fail` is set. Under
    strict, WARN must trip that path — otherwise a WARN-only report
    could still receive an A on the strict grade because pct is high."""
    rep = _report_with_only_warns()
    strict = grade(rep, strict=True)
    # 2 PASS (2pts each) + 2 promoted-to-FAIL WARN (0pts each) = 4/8 = 0.5
    # With has_fail=True and pct < 0.75, band() returns D.
    assert strict["overall"] in ("D", "F"), (
        f"WARN-only report under strict must drop to D or F "
        f"(pct=0.5 with has_fail=True); got {strict['overall']!r}"
    )


def test_strict_preserves_hardening_classification():
    """Strict mode tightens severity, NOT classification. A WARN
    finding that was hardening=True must stay in the hardening bucket
    after promotion to FAIL — otherwise strict mode could accidentally
    reclassify optional-feature absence as a correctness FAIL, which
    is exactly the false-D failure mode HARDENING_ABSENCE fixed."""
    rep = Report(domain_input="staging.example", domain="staging.example")
    rep.findings = [
        Finding("Nameservers", "Nameserver count", "PASS", "4"),
        # A hardening WARN — CAA absent. In normal mode: hardening only.
        # In strict mode: still hardening only (promoted to FAIL there).
        Finding("Core records", "CAA record", "WARN", "none", hardening=True),
    ]
    strict = grade(rep, strict=True)
    # Correctness should remain A — the single PASS is 2/2 → A. A regression
    # here would mean CAA WARN leaked into the correctness bucket.
    assert strict["correctness_grade"] == "A", (
        f"strict must not reclassify hardening WARNs into correctness; "
        f"correctness_grade={strict['correctness_grade']!r}"
    )
    # Hardening should be F — 1 hardening-eligible WARN promoted to FAIL,
    # score 0/2 → F.
    assert strict["hardening_grade"] == "F", (
        f"strict must promote hardening WARN to FAIL within its bucket; "
        f"hardening_grade={strict['hardening_grade']!r}"
    )


def test_strict_leaves_all_pass_reports_at_A():
    """Regression guard: a clean all-PASS report must still grade A
    under strict. Strict only tightens WARN handling; it must not
    invent failures where none exist."""
    rep = Report(domain_input="prod.example", domain="prod.example")
    rep.findings = [
        Finding("Nameservers", "Nameserver count", "PASS", "4"),
        Finding("Core records", "A record", "PASS", "1"),
        Finding("Email authentication", "SPF", "PASS", "-all"),
    ]
    assert grade(rep, strict=True)["overall"] == "A", \
        "clean report must grade A under strict — strict tightens WARN, not PASS"


# ---------------------------- CLI surface --------------------------------

def test_cli_accepts_strict_flag():
    """The CLI must expose `--strict` so operators can invoke strict
    mode without editing code. Argparse should accept the flag."""
    from posture import cli as cli_mod

    ap = cli_mod._build_parser()  # helper we're introducing
    ns = ap.parse_args(["example.com", "--strict"])
    assert ns.strict is True, "expected --strict to set args.strict True"

    ns2 = ap.parse_args(["example.com"])
    assert ns2.strict is False, "strict must default to False (opt-in only)"
