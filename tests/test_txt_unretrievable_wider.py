"""Regression tests for FP4 — `_txt_records` collapsed SERVFAIL,
TIMEOUT, and other transport failures into "no records" (i.e. the
empty-list path). Only `TRUNCATED_NO_TCP` correctly triggered
`TxtUnretrievable`.

Downstream in `emailauth`, SPF / DMARC / MTA-STS / TLS-RPT / DKIM
all interpret an empty TXT list as "record not published" — a
straight rule-1 collapse: `unretrievable` → `broken` on the tool's
most user-visible finding class.

Real trigger paths this catches:
  - Public resolver rate-limits the tool → `NoNameservers` inside
    `_query_uncached` → `{"ok": False, "error": "SERVFAIL"}`.
  - Corporate network drops UDP/53 answer packets after retries →
    `dns.exception.Timeout` → `{"ok": False, "error": "TIMEOUT"}`.
  - Any other transport-level `Exception` bubbles as
    `{"ok": False, "error": "<ExceptionName>"}` (generic bucket).

Fix contract:
  - Any `ok: False` return from `query()` except `NXDOMAIN` raises
    `TxtUnretrievable` with a note naming the underlying error.
  - `NXDOMAIN` is the ONE legitimate absence signal — the domain
    genuinely does not exist — and returns [] so higher-level code
    can distinguish "no such domain" from "domain exists, unknown".
  - Empty-answer (`NoAnswer` → `{"ok": True, "records": []}`) is
    still returned as [] (genuine absence).
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from posture.emailauth import TxtUnretrievable, _txt_records


def _stub_query(result):
    """Return a `patch` context manager that stubs
    `posture.emailauth.query` to always return `result`."""
    return patch("posture.emailauth.query", side_effect=lambda *a, **kw: result)


def test_servfail_raises_txt_unretrievable():
    """A resolver-side SERVFAIL (rate limit, upstream chain broken)
    is NOT evidence that the TXT record is absent — it is evidence
    that we could not answer the question. Must raise, not return []."""
    with _stub_query({"ok": False, "error": "SERVFAIL"}):
        with pytest.raises(TxtUnretrievable) as ei:
            _txt_records("example.com")
        assert "SERVFAIL" in str(ei.value), (
            f"TxtUnretrievable note must name the underlying error so "
            f"the operator can diagnose. Got note={ei.value!r}"
        )


def test_timeout_raises_txt_unretrievable():
    """UDP/53 packet loss / network path failure. Same reasoning as
    SERVFAIL — collapse into 'absent' is a rule-1 violation."""
    with _stub_query({"ok": False, "error": "TIMEOUT"}):
        with pytest.raises(TxtUnretrievable):
            _txt_records("example.com")


def test_generic_transport_error_raises_txt_unretrievable():
    """Any non-NXDOMAIN, non-NoAnswer failure must raise. The generic
    exception bucket (`error: "<ExceptionName>"`) covers rare cases
    like DNSException subclasses we didn't enumerate — they all
    represent 'could not retrieve', never 'confirmed absent'."""
    with _stub_query({"ok": False, "error": "ConnectionResetError"}):
        with pytest.raises(TxtUnretrievable):
            _txt_records("example.com")


def test_truncated_no_tcp_still_raises():
    """Regression guard for the pre-FP4 branch that already worked
    correctly. The fix must not remove it."""
    with _stub_query({"ok": False, "error": "TRUNCATED_NO_TCP",
                      "note": "Response exceeded UDP limits"}):
        with pytest.raises(TxtUnretrievable):
            _txt_records("example.com")


def test_nxdomain_still_returns_empty_list():
    """NXDOMAIN is the one legitimate absence signal — the domain
    genuinely does not exist. Must return [] so the caller can
    interpret it as 'record not published on a non-existent domain',
    NOT raise (which would break the flow for legitimately absent
    domains under NXDOMAIN)."""
    with _stub_query({"ok": False, "error": "NXDOMAIN"}):
        out = _txt_records("nonexistent.example")
        assert out == []


def test_noanswer_returns_empty_list():
    """A confirmed NoAnswer response (domain exists, no TXT records
    at that name) still returns []. This is the genuine 'record
    absent' path — retaining it is what makes the raise-on-transport-
    failure fix safe (we still have a way to say 'confirmed empty')."""
    with _stub_query({"ok": True, "records": [], "ttl": None}):
        out = _txt_records("example.com")
        assert out == []


def test_normal_answer_still_returns_records():
    """Sanity: non-error paths continue to return the joined TXT
    values. Guarantees the fix doesn't break the common success case."""
    with _stub_query({"ok": True,
                      "records": ['"v=spf1 include:_spf.example.com ~all"'],
                      "ttl": 300}):
        out = _txt_records("example.com")
        assert out == ["v=spf1 include:_spf.example.com ~all"]
