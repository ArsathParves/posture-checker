"""BIAS-5 — every modernity finding emit site must carry ``hardening``.

CLAUDE.md's grade model splits findings into two buckets: `correctness`
(genuine misconfigurations that drag overall grade) and `hardening`
(optional protocol features whose absence should NOT punish a domain
that chose not to adopt them — google.com is the pinned canonical
example, unsigned by choice yet must grade A overall).

The classification lives with the emit site — a `Finding(...,
hardening=True)` at the call site tells `grade()` "route this into
the hardening bucket". Miss the flag on any *one* emit branch and
that scenario silently regresses into the correctness bucket, which
is exactly the failure mode this test catches:

  - google-shape zone with NSEC3-compliant zone-walking exposure PASS
    used to leak into correctness because the PASS branch omitted the
    flag. Fixed as part of BIAS-5.
  - HSTS PASS / low-max-age WARN / HTTP-failed UNKNOWN all used to
    omit the flag while the "no HSTS header" WARN carried it. The
    grader would credit non-adoption to hardening but treat adoption
    as correctness — an asymmetric bias that penalised operators who
    HAD deployed HSTS with a short max-age.
  - CDS/CDNSKEY PASS + UNKNOWN, DMARC ext-dest PASS/UNKNOWN/FAIL, and
    the zone-walking UNKNOWN path — same pattern.

The rule: for every emit site whose label matches a modernity feature
(a list-let of them, kept in sync with the emit sites), the call MUST
pass `hardening=True` (or `hardening=<expr>` for the state-conditional
DNSSEC case where the emit site itself decides based on state).

Explicit exceptions are documented inline. Currently:
  - `Zone-walking exposure` WARN for NSEC (not NSEC3) is deliberately
    `hardening=False` — NSEC walkability is a real, exploitable
    disclosure (RFC 4034 §4), not merely a hardening-adoption gap.
    See test_nsec_zone_walking.py which locks that intent.
"""
from __future__ import annotations

import ast
from pathlib import Path


# --------------------------------------------------------------------- fixture

CHECKS_SRC = Path(__file__).resolve().parents[1] / "posture" / "checks.py"


# Labels whose emit is a *modernity / hardening-adoption* finding. Every
# emit at these labels must carry a `hardening` kwarg — either
# `hardening=True` (the usual case) or `hardening=<expr>` for the
# state-conditional DNSSEC case (`hardening=is_hardening`). A missing
# flag is a bias: adoption doesn't credit hardening, or non-adoption
# leaks into correctness.
MODERNITY_LABELS = {
    "IPv6 (AAAA) on nameservers",
    "DNS cookie support",
    "AAAA record (IPv6)",
    "CAA record",
    "CAA issuers (non-wildcard)",
    "CAA issuers (wildcard)",
    "CAA no-issue lockdown",
    "CAA iodef reporting",
    "CAA malformed record",
    "DNSSEC status",
    "Algorithm strength",
    "Cross-resolver DNSKEY consensus",
    "Zone-walking exposure",
    "Automated DS rollover",
    "DMARC alignment (DKIM)",
    "DMARC alignment (SPF)",
    "DMARC reporting",
    "MTA-STS",
    "TLS-RPT",
    "HSTS",
    "CAA / cert issuer alignment",
    "Multi-vantage A view",
}

# Emit sites deliberately marked `hardening=False`. Documented here so
# a reader can see the exception is an explicit design call, not a
# missed flag. Keyed by (label, status_literal). The AST-walker treats
# these as satisfied when it sees `hardening=False` on a call with the
# matching label + status.
EXPLICIT_NON_HARDENING = {
    # NSEC (not NSEC3): real zone-enumeration disclosure per RFC 4034 §4.
    # Not a hardening-adoption gap; locked by test_nsec_zone_walking.py.
    ("Zone-walking exposure", "WARN"),
}


# --------------------------------------------------------------------- walker

def _label_from_call(call: ast.Call) -> str | None:
    """Return the second positional arg (the label) of a rep.add(...)
    call, IF it's a plain string literal. F-string / variable labels
    (e.g. ``f\"DMARC {tag} verification: {domain}\"``) are handled
    separately."""
    if len(call.args) < 2:
        return None
    node = call.args[1]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _status_from_call(call: ast.Call) -> str | None:
    """Return the third positional arg (the status) if a string literal."""
    if len(call.args) < 3:
        return None
    node = call.args[2]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _has_hardening_kwarg(call: ast.Call) -> tuple[bool, ast.AST | None]:
    """Return (present, value_node). value_node lets us distinguish
    ``hardening=True`` from ``hardening=False`` or a dynamic expression."""
    for kw in call.keywords:
        if kw.arg == "hardening":
            return (True, kw.value)
    return (False, None)


def _collect_rep_add_calls(tree: ast.AST) -> list[ast.Call]:
    """Every ``rep.add(...)`` call in the module."""
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (isinstance(func, ast.Attribute)
                and func.attr == "add"
                and isinstance(func.value, ast.Name)
                and func.value.id == "rep"):
            calls.append(node)
    return calls


def _rep_add_calls_in_function(tree: ast.AST, fname: str) -> list[ast.Call]:
    """Every rep.add call inside the top-level function named ``fname``."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == fname:
            calls: list[ast.Call] = []
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                f = sub.func
                if (isinstance(f, ast.Attribute)
                        and f.attr == "add"
                        and isinstance(f.value, ast.Name)
                        and f.value.id == "rep"):
                    calls.append(sub)
            return calls
    raise AssertionError(f"function {fname!r} not found in checks.py")


# --------------------------------------------------------------------- tests

def test_every_modernity_emit_site_has_hardening_flag():
    """Walk the AST of checks.py; every rep.add(...) whose label is in
    MODERNITY_LABELS must carry a `hardening` kwarg. Deliberate
    exceptions (documented in EXPLICIT_NON_HARDENING) may pass
    hardening=False.

    A failure here means a modernity feature was emitted without the
    flag — the grader will drop that adoption/absence into the
    correctness bucket, which is the exact mechanism the google.com
    unsigned-zone guardrail was built to prevent."""
    src = CHECKS_SRC.read_text()
    tree = ast.parse(src)
    calls = _collect_rep_add_calls(tree)
    assert calls, "no rep.add calls found in checks.py — parser or path is wrong"

    misses: list[tuple[int, str, str]] = []
    for call in calls:
        label = _label_from_call(call)
        if label is None or label not in MODERNITY_LABELS:
            continue
        status = _status_from_call(call) or "?"
        present, val = _has_hardening_kwarg(call)
        if not present:
            misses.append((call.lineno, label, status))
            continue
        if isinstance(val, ast.Constant) and val.value is False:
            if (label, status) not in EXPLICIT_NON_HARDENING:
                misses.append((call.lineno, label,
                               f"{status} hardening=False (undocumented)"))

    assert not misses, (
        "BIAS-5: modernity findings missing hardening flag — a domain "
        "that adopts these features must be credited to the hardening "
        "bucket, and a domain that hasn't adopted them must not have "
        "the finding drag correctness. Sites missing the flag:\n"
        + "\n".join(f"  checks.py:{ln} — {lbl!r} ({st})"
                    for ln, lbl, st in misses)
    )


def test_dmarc_ext_dest_verification_all_paths_flag_hardening():
    """The DMARC rua/ruf external-destination verification block emits
    four branches (WARN parse_error, UNKNOWN unretrievable, PASS
    verified, FAIL unverified) via a computed f-string label. Locking
    the AST-level fact that every rep.add on this block passes
    hardening=True — belt-and-braces against a future refactor that
    might reshape one branch without touching the others."""
    src = CHECKS_SRC.read_text()
    tree = ast.parse(src)
    email_calls = _rep_add_calls_in_function(tree, "_email")

    ext_dest_calls = [
        c for c in email_calls
        if len(c.args) >= 2
        and isinstance(c.args[1], ast.Name)
        and c.args[1].id == "label"
    ]
    assert len(ext_dest_calls) == 4, (
        f"expected 4 DMARC ext-dest emit branches (WARN/UNKNOWN/PASS/"
        f"FAIL); found {len(ext_dest_calls)}. If a branch was removed "
        f"intentionally, update this test with the new count."
    )
    for call in ext_dest_calls:
        present, val = _has_hardening_kwarg(call)
        assert present and isinstance(val, ast.Constant) and val.value is True, (
            f"checks.py:{call.lineno} — DMARC ext-dest verification emit "
            f"must pass hardening=True; got present={present}, "
            f"value={ast.dump(val) if val else None}"
        )


def test_dnssec_status_has_conditional_hardening_kwarg():
    """DNSSEC state routing is state-conditional: not_configured,
    validating, unknown → hardening=True (adoption or deliberate
    non-adoption is a hardening-bucket signal). broken and incomplete
    → hardening=False (genuine misconfiguration → correctness bucket).

    The emit site passes ``hardening=is_hardening`` (a Name node) —
    verify the kwarg is present and its value is NOT a literal (which
    would defeat the state-conditional routing). This is the exact
    mechanism test_grading_google_unsigned.py depends on."""
    src = CHECKS_SRC.read_text()
    tree = ast.parse(src)
    for call in _collect_rep_add_calls(tree):
        if _label_from_call(call) != "DNSSEC status":
            continue
        present, val = _has_hardening_kwarg(call)
        assert present, (
            f"checks.py:{call.lineno} — DNSSEC status emit MUST pass "
            f"hardening=<is_hardening>; a missing kwarg would route "
            f"the unsigned-by-choice case into correctness and "
            f"re-open the google.com D-grade bug."
        )
        assert not isinstance(val, ast.Constant), (
            f"checks.py:{call.lineno} — DNSSEC status hardening kwarg "
            f"must be state-conditional (a variable / expression), "
            f"not a bare True/False constant. Bare True would drag a "
            f"genuinely broken chain out of correctness; bare False "
            f"would drag unsigned-by-choice into correctness."
        )
        return  # exactly one emit site; done
    raise AssertionError("no `DNSSEC status` emit site found in checks.py")


def test_modernity_labels_are_actually_emitted():
    """Belt-and-braces: every label in MODERNITY_LABELS is at least
    one emit site's literal label. Prevents the modernity list from
    silently rotting after a rename in checks.py — a stale label in
    the list would leave the coverage assertion weaker than it looks
    (the walker would just skip nonexistent labels)."""
    src = CHECKS_SRC.read_text()
    tree = ast.parse(src)
    seen = {_label_from_call(c) for c in _collect_rep_add_calls(tree)}
    missing = MODERNITY_LABELS - seen
    assert not missing, (
        f"MODERNITY_LABELS references labels not emitted anywhere in "
        f"checks.py: {sorted(missing)}. Either the label was renamed "
        f"(update this test) or the emit was deleted (drop from the "
        f"list). A stale entry silently weakens the coverage assertion."
    )
