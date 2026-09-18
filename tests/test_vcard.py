"""Regression tests for posture.core._extract_vcard_fn (N8, N14).

vCard structure per RFC 6350 is a nested list; earlier code assumed a fixed
index and crashed on registrars that returned a differently-shaped array.
_extract_vcard_fn must return the FN text or None without raising.
"""
from __future__ import annotations

from posture.core import _extract_vcard_fn


def _wrap(components: list) -> list:
    """RDAP vcardArray looks like ["vcard", [ ...components... ]]."""
    return ["vcard", components]


def test_returns_fn_from_well_formed_vcard():
    vcard = _wrap([
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Example Registrar, Inc."],
    ])
    assert _extract_vcard_fn(vcard) == "Example Registrar, Inc."


def test_returns_none_when_fn_missing():
    vcard = _wrap([
        ["version", {}, "text", "4.0"],
    ])
    assert _extract_vcard_fn(vcard) is None


def test_none_input_does_not_raise():
    assert _extract_vcard_fn(None) is None


def test_empty_input_does_not_raise():
    assert _extract_vcard_fn([]) is None
    assert _extract_vcard_fn(["vcard"]) is None


def test_malformed_short_item_ignored():
    vcard = _wrap([
        ["fn"],
        ["fn", {}, "text", "Second Wins?"],
    ])
    assert _extract_vcard_fn(vcard) == "Second Wins?"


def test_non_list_components_do_not_raise():
    vcard = _wrap(["not-a-list", None, 42])
    assert _extract_vcard_fn(vcard) is None
