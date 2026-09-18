"""Regression tests for E7 — Unicode normalisation of RDAP vCard fn.

Two problems the v0.5 `_extract_vcard_fn` had:

1. **NFC/NFD drift.** An RDAP registry can serialise the same visible
   name in NFC (`Café`, `é` as U+00E9) or NFD (`Cafe` + combining
   acute U+0301). Byte-identical *and* logically-identical are not
   the same thing under Unicode, and downstream code that dedupes
   registrar names, compares against a whitelist, or hashes for a
   cache key will treat the two forms as different values.

2. **Whitespace / control characters.** RDAP payloads in the wild
   sometimes ship an FN value with CRLF or leading whitespace
   (mostly Indian NIXI registrars). The v0.5 code returned it raw,
   which propagates control chars into terminal renderings and
   HTML output.

Fix: NFC-normalise + `str.strip()`. The audit item N8/N14 already
pinned that malformed vCards must not raise; E7 pins that the
returned string is a canonical, safe-to-render form.

Ground truth: `unicodedata.normalize("NFC", "Cafe\u0301")` == `"Café"`
(len 4) — the combining acute collapses into the pre-composed é.
"""
from __future__ import annotations

from posture.core import _extract_vcard_fn


def _vcard(fn_value):
    """Build a minimal vCard array with just an fn component. Matches
    the shape RDAP endpoints emit: `["vcard", [["version",…], ["fn", {}, "text", <value>], …]]`."""
    return [
        "vcard",
        [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", fn_value],
        ],
    ]


def test_nfd_input_is_normalised_to_nfc():
    """The load-bearing test. NFD (`Cafe` + U+0301) and NFC (`Café`)
    represent the same visible string but differ byte-for-byte.
    The extractor must collapse them so a registrar dedupe check
    never sees two 'different' Café values."""
    nfd = "Cafe\u0301 Solutions GmbH"  # 20 code points
    nfc = "Café Solutions GmbH"        # 19 code points
    assert len(nfd) == 20 and len(nfc) == 19  # sanity on the fixture

    out = _extract_vcard_fn(_vcard(nfd))
    assert out == nfc, (
        f"NFD input must be normalised to NFC; got {out!r} (len {len(out)})"
    )


def test_nfc_input_is_unchanged():
    """The idempotency pin: NFC input is already normalised and must
    round-trip exactly. A regression that double-normalises or picks
    NFD would break this."""
    nfc = "Café Solutions GmbH"
    out = _extract_vcard_fn(_vcard(nfc))
    assert out == nfc


def test_leading_trailing_whitespace_is_stripped():
    """RDAP payloads occasionally embed CRLF or padding. Stripping
    keeps findings and terminal output clean and prevents an operator
    from seeing a name row that appears to be blank."""
    out = _extract_vcard_fn(_vcard("  Registrar Inc.\r\n  "))
    assert out == "Registrar Inc."


def test_devanagari_passes_through_cleanly():
    """BFSI focus per CLAUDE.md — Indian registrars can publish an FN
    in Devanagari. The result must be preserved verbatim (already NFC)
    and not mangled by an over-eager normaliser or a stripper that
    treats every non-ASCII char as suspect."""
    dev = "भारतीय स्टेट बैंक"
    out = _extract_vcard_fn(_vcard(dev))
    assert out == dev


def test_whitespace_only_value_returns_none():
    """A value that is entirely whitespace has no useful meaning —
    returning it would surface an empty registrar row. None here lets
    the caller fall back to `entity.handle` (see core.py:264)."""
    out = _extract_vcard_fn(_vcard("   \r\n\t  "))
    assert out is None


def test_non_string_value_does_not_raise():
    """Belt-and-braces on N8/N14: some vCard emitters ship a JSON
    array or dict at item[3]. Must return None gracefully, never
    call .strip() on a list or crash the whole check."""
    out = _extract_vcard_fn([
        "vcard",
        [
            ["fn", {}, "text", ["structured", "name", "parts"]],
        ],
    ])
    assert out is None
