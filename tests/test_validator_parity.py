"""Regression tests for L3 — the CLI and web entrypoints ran through
two different validators (`posture.core.normalize_domain` and
`web.server._validate_domain`) and there was no test that pinned them
to the same accept / reject verdict on the same input.

A divergence here is a two-headed bug: an operator hands a URL to the
CLI and it runs fine, but the web landing page rejects the same input
with a 400 (or vice versa). The two entrypoints are meant to be a
byte-for-byte identical check surface — the web layer is presentation
and access control only (see CLAUDE.md § "What this is"). Anything the
CLI accepts, the web must accept; anything the web rejects, the CLI
must also reject once the input reaches DNS.

The web wrapper additionally rejects URL-shaped input (`://`, `/`, `@`)
at the boundary rather than silently stripping the scheme, per
`_validate_domain`'s "don't transform user input" contract. That extra
strictness is intentional and the parity table encodes it explicitly.

Pinning this now catches:
  - a future author who tightens one validator without the other
  - a future refactor that consolidates the two but drops an edge case
  - the L3 audit item that the two disagreed on trailing dots / empty
    labels (empirically they don't today; the test freezes that).
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from posture.core import normalize_domain
from web.server import _validate_domain


def _core_accepts(raw: str) -> bool:
    try:
        normalize_domain(raw)
        return True
    except ValueError:
        return False


def _web_accepts(raw: str) -> bool:
    try:
        _validate_domain(raw)
        return True
    except HTTPException:
        return False


# (input, expected verdict for both validators)
# When the web layer diverges intentionally (URL-shaped input), the
# case is listed separately in URL_ONLY_WEB_REJECTS below.
COMMON_CASES = [
    # ---- accepted by both ----
    ("example.com",          True),
    ("example.com.",         True),   # trailing dot stripped
    ("WWW.example.com",      True),   # www stripped, apex checked
    ("example.co.uk",        True),   # multi-label TLD
    ("xn--p1ai",             False),  # single-label TLD-only (missing SLD)
    ("xn--80akhbyknj4f.xn--p1ai", True),  # punycode IDN
    (" example.com ",        True),   # whitespace stripped
    # ---- rejected by both ----
    ("example..com",         False),  # empty middle label
    (".example.com",         False),  # empty leading label
    ("example",              False),  # single label / no dot
    ("192.0.2.1",            False),  # IPv4 literal
    ("2001:db8::1",          False),  # IPv6 literal
    ("-example.com",         False),  # leading hyphen
    ("example-.com",         False),  # trailing hyphen
    ("a" * 64 + ".example.com",   False),  # 64-char label (>63)
    ("a" * 254,                    False),  # >253 octets total
    ("",                     False),  # empty
    (".",                    False),  # dot only
]

# Web is strictly the CLI's contract PLUS a boundary reject on URL-
# shaped input. `normalize_domain` still accepts these because the
# CLI historically ran unattended over textual input and had to be
# lenient. Documenting the intentional divergence keeps L3 honest.
URL_ONLY_WEB_REJECTS = [
    "http://example.com",
    "https://example.com/path",
    "example.com/path",
    "user@example.com",
]


@pytest.mark.parametrize("raw,expected", COMMON_CASES)
def test_validators_agree_on_common_shapes(raw, expected):
    """Both validators must return the same accept / reject verdict
    on inputs where the two are meant to be identical."""
    core = _core_accepts(raw)
    web = _web_accepts(raw)
    assert core == web == expected, (
        f"Validator divergence on {raw!r}: core={core}, web={web}, "
        f"expected both to be {expected}. Fixing one entrypoint without "
        f"the other creates a CLI-vs-web mismatch (CLAUDE.md § What this is: "
        f"the two surfaces are meant to be identical)."
    )


@pytest.mark.parametrize("raw", URL_ONLY_WEB_REJECTS)
def test_web_rejects_url_shaped_input_that_core_would_strip(raw):
    """The web layer rejects URL-shaped input at the boundary. The CLI
    historically strips scheme/path/@userinfo silently — this is the
    intentional divergence documented in `_validate_domain`. If a
    future refactor drops the boundary reject, the web would silently
    accept URLs and confuse users; this test freezes that behaviour."""
    assert _web_accepts(raw) is False, (
        f"{raw!r} looks like a URL — web layer must reject at the "
        f"boundary rather than silently strip. Currently accepted."
    )
    # And the CLI still accepts (its input contract is lenient):
    assert _core_accepts(raw) is True, (
        f"CLI normalize_domain historically strips scheme/path/@ and "
        f"accepts {raw!r}. If this ever tightens, the URL_ONLY_WEB_REJECTS "
        f"case moves into COMMON_CASES."
    )
