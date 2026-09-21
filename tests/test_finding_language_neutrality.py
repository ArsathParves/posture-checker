"""BIAS-8 — findings describe the audited domain, not address the reader.

CLAUDE.md rule 2:
    Verify against real ground truth. Never assume, never reason from
    memory about what a domain's DNS looks like.

The findings emitted by ``rep.add(section, label, status, detail, why,
...)`` describe **the audited domain as observed**, not the operator
running the tool. When an SE audits a customer's domain, second-person
"your zone" text collapses two roles into one:

  - "your zone" reads as instruction to the reader (the SE)
  - but the fact being described is a property of the customer's zone

Descriptive prose — "the zone uses NSEC" instead of "your zone uses
NSEC" — keeps the audit voice consistent and lets the same finding
render correctly whether the reader is the operator, an SE, or a
downstream automated consumer of the --json output. Directive text
belongs in ``cli.REMEDIATION`` where the audience IS the operator
being asked to take action.

Ownership tokens banned in emit-site detail/why:
  your zone, your nameserver(s), your delegation, your record(s),
  your policy, your SOA, your CAA, your SPF, your DMARC, your DKIM,
  your MX, your key, your signer

Not banned:
  - "your DKIM selector name" — imperative call-to-action inside a
    UNKNOWN disclaimer ("re-run with --dkim-selector your-name-here").
    That's directive text, and the field would be less useful without
    it. The banned tokens above are the ones that describe the
    AUDIT SUBJECT — where the tool must stay descriptive.
"""
from __future__ import annotations

import ast
from pathlib import Path


CHECKS_SRC = Path(__file__).resolve().parents[1] / "posture" / "checks.py"
EMAIL_SRC = Path(__file__).resolve().parents[1] / "posture" / "emailauth.py"
DNS_SRC = Path(__file__).resolve().parents[1] / "posture" / "dnsmod.py"


# Ownership tokens that describe the AUDIT SUBJECT and must be
# rendered descriptively. Lowercased; matched as substrings so
# "your zone's" and "your zones" both trip.
_BANNED_OWNERSHIP_TOKENS = (
    "your zone",
    "your nameserver",
    "your delegation",
    "your record",
    "your policy",
    "your soa",
    "your caa",
    "your spf",
    "your dmarc",
    "your dkim",
    "your mx",
    "your key",
    "your signer",
    "your ns ",
)


def _text_of(node: ast.AST) -> str:
    """Return the literal string of `node`, resolving simple f-strings
    to their static substring parts. Non-literal parts (Name /
    Subscript / Call) contribute nothing — the token check is on
    author-written text only."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
        return "".join(parts)
    return ""


def _rep_add_texts(tree: ast.AST):
    """Yield (lineno, arg_index, text) for every literal string
    argument of every rep.add(...) call in `tree`. Skips arg 0 (the
    section) and arg 1 (the label) — those are matched exactly by
    the emit contract and are read by the grader; the neutrality
    concern is on the human-readable detail / why fields (args 3, 4)."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr == "add"
                and isinstance(f.value, ast.Name) and f.value.id == "rep"):
            continue
        for i, arg in enumerate(node.args):
            if i < 3:  # section, label, status — not free-form text
                continue
            text = _text_of(arg)
            if text:
                yield node.lineno, i, text


def _scan(path: Path):
    tree = ast.parse(path.read_text())
    offenders: list[tuple[str, int, int, str, str]] = []
    for lineno, arg_i, text in _rep_add_texts(tree):
        lower = text.lower()
        for tok in _BANNED_OWNERSHIP_TOKENS:
            if tok in lower:
                offenders.append((path.name, lineno, arg_i, tok, text[:120]))
    return offenders


def test_checks_py_findings_avoid_ownership_language():
    """``posture/checks.py`` is where 95% of findings emit. Any second-
    person ownership token here would render on every domain audit."""
    offenders = _scan(CHECKS_SRC)
    assert not offenders, (
        "BIAS-8: findings must describe the audited domain "
        "descriptively — 'the zone', 'the delegation', 'the "
        "nameservers' — not address the reader ('your zone', 'your "
        "nameservers'). The reader may be a solutions engineer "
        "auditing a customer's zone, not the operator; imperative "
        "language collapses the two roles. If a directive is genuinely "
        "needed, move it into cli.REMEDIATION where the audience IS "
        "the operator. Offenders:\n"
        + "\n".join(
            f"  {name}:{ln} arg{a} — banned token {tok!r} in {txt!r}"
            for name, ln, a, tok, txt in offenders
        )
    )


def test_emailauth_findings_avoid_ownership_language():
    """emailauth.py has few direct rep.add sites, but any labels /
    detail strings that flow through must comply."""
    offenders = _scan(EMAIL_SRC)
    assert not offenders, (
        "emailauth.py contains banned ownership tokens; see "
        "checks.py test message for the neutrality rationale.\n"
        + "\n".join(
            f"  {name}:{ln} arg{a} — banned token {tok!r} in {txt!r}"
            for name, ln, a, tok, txt in offenders
        )
    )


def test_dnsmod_findings_avoid_ownership_language():
    """dnsmod.py is DNS wire only, no direct emits — but keep the
    guard in case a future refactor introduces one."""
    offenders = _scan(DNS_SRC)
    assert not offenders, (
        "dnsmod.py contains banned ownership tokens; see "
        "checks.py test message for the neutrality rationale.\n"
        + "\n".join(
            f"  {name}:{ln} arg{a} — banned token {tok!r} in {txt!r}"
            for name, ln, a, tok, txt in offenders
        )
    )


def test_scanner_actually_would_flag_a_regression():
    """Belt-and-braces: the scanner would fire on a known-bad string.
    Without this, someone refactoring the scanner could turn it into
    a no-op and the offenders-list would stay empty regardless. A
    scanner that never fails is a scanner that never protects."""
    fake_source = (
        "def f():\n"
        "    class R: pass\n"
        "    rep = R()\n"
        "    rep.add('S', 'L', 'PASS', 'your zone is signed', 'ok')\n"
    )
    tree = ast.parse(fake_source)
    hits: list = []
    for _, _, text in _rep_add_texts(tree):
        lower = text.lower()
        for tok in _BANNED_OWNERSHIP_TOKENS:
            if tok in lower:
                hits.append((tok, text))
    assert hits, (
        "BIAS-8 scanner failed to detect a known-bad string "
        "('your zone is signed'). The AST walker or token list has "
        "regressed — the enforcement tests above have no teeth."
    )
