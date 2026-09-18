"""Regression tests for _dkim_key_state (RFC 6376 §3.6.1).

An empty p= tag is a REVOKED key, not a missing record.
example.com publishes exactly this — the tool must never report
'DKIM absent' when the truth is 'DKIM key revoked'.
"""
from __future__ import annotations

from posture.emailauth import _dkim_key_state


def test_valid_key_returns_valid():
    rec = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ..."
    assert _dkim_key_state(rec) == "valid"


def test_empty_p_tag_returns_revoked():
    """example.com wildcard publishes exactly this shape."""
    rec = "v=DKIM1; p="
    assert _dkim_key_state(rec) == "revoked"


def test_empty_p_with_whitespace_returns_revoked():
    rec = "v=DKIM1; p=   "
    assert _dkim_key_state(rec) == "revoked"


def test_non_dkim_text_returns_not_dkim():
    assert _dkim_key_state("v=spf1 -all") == "not_dkim"
    assert _dkim_key_state("random text") == "not_dkim"


def test_dkim_marker_without_p_returns_malformed():
    rec = "v=DKIM1; k=rsa"
    # No p= tag at all -> parser should not claim it's valid
    assert _dkim_key_state(rec) != "valid"


def test_case_insensitive_dkim_marker():
    rec = "V=dkim1; p=abc"
    assert _dkim_key_state(rec) == "valid"
