"""Regression tests for web.server._validate_domain — the API boundary
guard that catches bad input before it reaches DNS/RDAP.

Also verifies the input rejection contract stays aligned with
normalize_domain, so the CLI and web layer can't diverge on what counts
as a valid domain.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from web.server import _validate_domain


def test_accepts_plain_domain():
    assert _validate_domain("example.com") == "example.com"


def test_lowercases_and_returns_punycode():
    puny = _validate_domain("ExAmPlE.CoM")
    assert puny == "example.com"


def test_idn_returns_xn_form():
    puny = _validate_domain("münchen.de")
    assert puny.startswith("xn--")


def test_url_input_rejected():
    with pytest.raises(HTTPException) as exc:
        _validate_domain("https://example.com/")
    assert exc.value.status_code == 400


def test_path_only_input_rejected():
    with pytest.raises(HTTPException):
        _validate_domain("example.com/path")


def test_email_style_input_rejected():
    with pytest.raises(HTTPException):
        _validate_domain("user@example.com")


def test_ipv4_rejected():
    with pytest.raises(HTTPException):
        _validate_domain("192.0.2.1")


def test_localhost_rejected():
    with pytest.raises(HTTPException):
        _validate_domain("localhost")
