"""Regression tests for S4 — ReDoS surface in `web.server.DOMAIN_RE`.

The v0.5 baseline validator was::

    DOMAIN_RE = re.compile(
        r"^(?=.{1,253}$)([a-zA-Z0-9\\u00a0-\\uffff]"
        r"(?:[a-zA-Z0-9\\u00a0-\\uffff-]{0,61}[a-zA-Z0-9\\u00a0-\\uffff])?\\.)+"
        r"[a-zA-Z\\u00a0-\\uffff]{2,63}\\.?$"
    )

The outer `(...)+` around a variable-length label pattern is the shape
Python's `re` module can regress on for adversarial input. Even though
CPython's engine is safer than PCRE, the audit's line is that the API
boundary should not depend on regex-engine implementation details for
its worst-case runtime.

The input `_validate_domain` receives has already been through
`normalize_domain`, which runs it through the `idna` codec — so at the
guard's callsite the string is guaranteed to be **ASCII punycode**
(labels prefixed with `xn--` for the IDN case, plain ASCII otherwise).
A regex is overkill: label-by-label string checks are linear in input
length by construction.

Contract:

  (1) `_validate_domain` accepts everything the v0.5 regex accepted
      (regression coverage in the existing test_web_validation.py; not
      re-covered here).

  (2) A `_is_valid_domain(punycode)` helper exists and runs in linear
      time — no backtracking. Verified by a wall-clock ceiling on a
      pathological input that would push a poorly-written regex into
      quadratic/exponential time.

  (3) All the classical bad shapes still fail: empty labels
      (`a..b`), leading/trailing hyphens (`-a.com`, `a-.com`), labels
      longer than 63 chars, total length > 253, TLD too short, TLD
      containing digits at position 0.
"""
from __future__ import annotations

import time

import pytest

from web.server import _is_valid_domain


# ------------------------------------------------------------- correctness

def test_accepts_plain_ascii_domain():
    assert _is_valid_domain("example.com") is True


def test_accepts_punycode_idn():
    assert _is_valid_domain("xn--mnchen-3ya.de") is True


def test_accepts_multi_label():
    assert _is_valid_domain("a.b.example.co.uk") is True


def test_rejects_empty_string():
    assert _is_valid_domain("") is False


def test_rejects_empty_label():
    assert _is_valid_domain("a..b") is False


def test_rejects_leading_hyphen_in_label():
    assert _is_valid_domain("-a.example.com") is False


def test_rejects_trailing_hyphen_in_label():
    assert _is_valid_domain("a-.example.com") is False


def test_rejects_label_longer_than_63_chars():
    long_label = "a" * 64
    assert _is_valid_domain(f"{long_label}.com") is False


def test_accepts_label_exactly_63_chars():
    label = "a" * 63
    assert _is_valid_domain(f"{label}.com") is True


def test_rejects_overall_length_over_253():
    # 63 * 4 + 3 dots = 255 — just over the limit
    long = ".".join(["a" * 63] * 4)
    assert _is_valid_domain(long) is False


def test_rejects_single_label_no_tld():
    assert _is_valid_domain("localhost") is False


def test_rejects_ipv4_dotted_quad():
    """The `_validate_domain` upstream layer catches this before the
    helper is called, but the helper itself should also reject
    all-numeric TLDs — a TLD of `1` is not RFC-1035-valid."""
    assert _is_valid_domain("192.0.2.1") is False


def test_rejects_tld_shorter_than_two_chars():
    assert _is_valid_domain("example.a") is False


def test_accepts_trailing_dot():
    """RFC 1035 permits an explicit trailing dot to indicate a fully
    qualified name. Some resolvers pass it through, some strip it.
    The helper should accept either form."""
    assert _is_valid_domain("example.com.") is True


# ------------------------------------------------------------- ReDoS-safety

def test_linear_time_on_pathological_input():
    """The classic backtracking-trap for a regex of shape
    `([...]+)+` is a long run of characters that all match the
    inner class followed by a single character that DOESN'T match
    the anchor. A well-behaved linear validator should reject the
    input in microseconds regardless of length.

    We use 5000 chars of `a` followed by a mismatch character. If
    the implementation is still a regex with the old shape, this
    would take exponential time and hit the 1s ceiling."""
    hostile = "a" * 5000 + "!"
    start = time.perf_counter()
    result = _is_valid_domain(hostile)
    elapsed = time.perf_counter() - start
    assert result is False, "hostile input must be rejected"
    assert elapsed < 0.5, (
        f"validator took {elapsed:.3f}s on 5001-char hostile input — "
        f"ReDoS-vulnerable shape suspected. Expected <0.5s."
    )


def test_linear_time_on_long_label_chain():
    """Second ReDoS variant: a long chain of valid-looking labels
    that just barely fails the overall-length constraint. This is
    the kind of input that pushes an anchored regex with a lookahead
    into worst-case backtracking."""
    # 100 labels of 3 chars + 99 dots = 399 chars — well over 253
    hostile = ".".join(["abc"] * 100)
    start = time.perf_counter()
    result = _is_valid_domain(hostile)
    elapsed = time.perf_counter() - start
    assert result is False
    assert elapsed < 0.5, (
        f"validator took {elapsed:.3f}s on 100-label hostile input — "
        f"ReDoS-vulnerable shape suspected."
    )
