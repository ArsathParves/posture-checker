"""B36 — remediation guidance is vendor-neutral at the data-model level.

CLAUDE.md rule 7:
    Findings describe what is true about the domain. Remediation
    guidance should state the general fix first ("sign your zone at
    your current DNS provider"); the VergeCloud capability is
    secondary context, not the primary recommendation.

Before B36 the remediation table stored a single string per finding
label, and every string opened with "VergeCloud ADNS ...". Enforcing
neutrality one word at a time is fragile — the next person to add a
finding writes another vendor-first line and no test flags it.

B36 restructures at the data-model level: each remediation is a
`Remediation` dataclass with a REQUIRED `general` field (the RFC- /
protocol-agnostic fix) and an OPTIONAL `vendor` field (the VergeCloud
rider, secondary context only). The renderer emits `general` first
and (if present) `vendor` as a dim secondary line. The invariants
below are structural — they catch a regression at import time, not
at read time.

Vendor names that trigger the neutrality check. Kept small: expanding
this list too aggressively would flag legitimate ADNS-comparison text
in future. Add here only names that are unambiguously VergeCloud
brand tokens.
"""
from __future__ import annotations

import io
import re
from dataclasses import fields, is_dataclass

import pytest
from rich.console import Console


def _flatten(text: str) -> str:
    """Rich wraps table cells and inserts box-drawing borders between
    wrapped lines. To assert on the logical text, strip everything
    that isn't printable ASCII then collapse whitespace."""
    stripped = re.sub(r"[^\x20-\x7e\n]", " ", text)
    return re.sub(r"\s+", " ", stripped)


def _capture_render(rep):
    """Render `rep` into a StringIO-backed Rich Console and return
    the flattened text. The CLI's module-level `console` captures
    `sys.stdout` at import time, so pytest's `capsys` misses its
    output whenever another test has swapped stdout in-place. Owning
    the Console for the render duration avoids that leak."""
    from posture import cli as _cli
    buf = io.StringIO()
    original = _cli.console
    _cli.console = Console(file=buf, width=200, force_terminal=False,
                           color_system=None)
    try:
        _cli.render(rep, show_info=False)
    finally:
        _cli.console = original
    return _flatten(buf.getvalue())

from posture import cli
from posture import core

_VENDOR_TOKENS = ("vergecloud", "verge cloud", "adns")


def _is_vendor_led(s: str) -> bool:
    """True if the leading clause of `s` is a vendor sales line
    ("VergeCloud ADNS supports ..."). We look at the first 40 chars —
    long enough to catch "VergeCloud ADNS" but short enough not to
    trip on a legitimate "if migrating to VergeCloud, ..." rider."""
    head = s.lower().lstrip()[:40]
    return any(tok in head for tok in _VENDOR_TOKENS)


# --------------------------------------------------------------------- data model

def test_remediation_dataclass_exists():
    """`Remediation` lives in `posture.core` — same module as the
    Finding dataclass — so both the CLI and any future web renderer
    read from a single source of truth. This is the load-bearing
    piece of the neutrality mandate: if `Remediation` is not a
    dataclass with a required `general` field, someone can still
    write `REMEDIATION = {"...": "VergeCloud does X"}` and skip the
    contract entirely."""
    assert hasattr(core, "Remediation"), (
        "posture.core.Remediation must exist — the vendor-neutrality "
        "contract lives on the type, not on ad-hoc strings"
    )
    R = core.Remediation
    assert is_dataclass(R), "Remediation must be a dataclass"
    fnames = {f.name for f in fields(R)}
    assert "general" in fnames, (
        f"Remediation must have a `general` field; got {fnames!r}"
    )
    assert "vendor" in fnames, (
        f"Remediation must have a `vendor` field (may default to ''); "
        f"got {fnames!r}"
    )


def test_remediation_general_is_required():
    """`general` MUST be positional / required — a missing general
    fix is the exact regression this refactor prevents."""
    with pytest.raises(TypeError):
        core.Remediation()  # no args — should fail


def test_remediation_vendor_defaults_to_empty():
    """`vendor` is a secondary rider, not a primary field. Its
    default must be empty so a caller can create a general-only
    remediation without ceremony."""
    r = core.Remediation(general="fix at your DNS provider")
    assert r.vendor == "", (
        f"Remediation.vendor should default to ''; got {r.vendor!r}"
    )


# --------------------------------------------------------------------- table

def test_every_remediation_entry_is_a_dataclass():
    """The CLI's `REMEDIATION` dict is the concrete surface where the
    neutrality contract is either honoured or violated. Every value
    must be a `Remediation` instance — plain strings would silently
    bypass the general-first rule."""
    for label, entry in cli.REMEDIATION.items():
        assert isinstance(entry, core.Remediation), (
            f"REMEDIATION[{label!r}] must be a Remediation instance; "
            f"got {type(entry).__name__} — a raw string bypasses the "
            f"vendor-neutrality contract"
        )


def test_every_remediation_general_is_non_empty():
    """A Remediation with empty `general` is a bug — the vendor-only
    fallback is precisely what rule 7 forbids."""
    for label, entry in cli.REMEDIATION.items():
        assert entry.general and entry.general.strip(), (
            f"REMEDIATION[{label!r}].general is empty — every finding "
            f"must offer a vendor-neutral fix"
        )


def test_no_remediation_leads_with_vendor_name():
    """The general fix must NOT open with a VergeCloud sales line.
    'VergeCloud ADNS lets you publish CAA policy' at the head of the
    general string is exactly the pre-B36 mistake."""
    offenders = []
    for label, entry in cli.REMEDIATION.items():
        if _is_vendor_led(entry.general):
            offenders.append((label, entry.general[:80]))
    assert not offenders, (
        f"General-fix text must not open with a vendor name; "
        f"offenders: {offenders!r}"
    )


def test_vendor_riders_are_vendor_led():
    """Symmetric assertion: if a vendor rider is present, it SHOULD
    lead with the vendor name — that's what makes it identifiably a
    vendor-specific augmentation rather than a general fix in
    disguise. Otherwise the reader can't tell the two apart in the
    rendered output."""
    for label, entry in cli.REMEDIATION.items():
        if entry.vendor.strip():
            assert _is_vendor_led(entry.vendor), (
                f"REMEDIATION[{label!r}].vendor should identify the "
                f"vendor by name (leading with 'VergeCloud' or "
                f"'ADNS'); got {entry.vendor[:80]!r}"
            )


# --------------------------------------------------------------------- rendering

def test_render_emits_general_before_vendor():
    """The rendered output is the piece the user actually reads. The
    general fix must appear first; the vendor rider comes after,
    visually secondary. A test on the type isn't enough — the
    renderer could still emit vendor-first if we didn't lock it."""
    from posture.core import Finding, Report

    # Pick a label we KNOW has both general + vendor text.
    label = "DNSSEC status"
    entry = cli.REMEDIATION[label]
    assert entry.general and entry.vendor, (
        "test fixture assumes DNSSEC status carries both fields"
    )

    rep = Report(domain_input="example.com", domain="example.com")
    rep.findings.append(Finding(
        section="DNSSEC & delegation", label=label, status="FAIL",
        detail="broken", why="Chain fails to validate."))
    rep.data["environment"] = {"safe_for_direct_dns": True}

    out = _capture_render(rep)

    # Both must appear; general precedes vendor.
    gen_head = _flatten(entry.general[:40])
    ven_head = _flatten(entry.vendor[:30])
    gen_pos = out.find(gen_head)
    ven_pos = out.find(ven_head)
    assert gen_pos != -1, (
        f"general remediation not rendered; head={gen_head!r}"
    )
    assert ven_pos != -1, (
        f"vendor rider not rendered; head={ven_head!r}"
    )
    assert gen_pos < ven_pos, (
        f"general (@{gen_pos}) must render before vendor (@{ven_pos})"
    )


def test_render_general_only_when_no_vendor():
    """When a Remediation has no vendor rider, only the general text
    is emitted — no dangling 'Vendor solution:' label with empty
    contents."""
    from posture.core import Finding, Remediation, Report

    label = "__test_general_only__"
    cli.REMEDIATION[label] = Remediation(
        general="Do the general RFC-recommended thing.")
    try:
        rep = Report(domain_input="example.com", domain="example.com")
        rep.findings.append(Finding(
            section="DNSSEC & delegation", label=label, status="WARN",
            detail="synthetic", why=""))
        rep.data["environment"] = {"safe_for_direct_dns": True}
        out = _capture_render(rep)
        assert "Do the general RFC-recommended thing." in out
        # No vendor scaffold when vendor is absent.
        tail = out.split(label, 1)[-1][:400]
        assert "VergeCloud" not in tail, (
            f"vendor scaffold appeared with empty vendor field; "
            f"tail after label: {tail!r}"
        )
    finally:
        del cli.REMEDIATION[label]
