"""Regression tests for S2 — wide-open CORS.

`web.server` used to attach `CORSMiddleware(allow_origins=["*"], ...)`
unconditionally. The tool is meant to eventually run on `vergecloud.com`
as a lead-gen surface, and once auth or cookies are ever added,
`allow_origins=["*"]` is a credential-theft path (any origin can drive
XHR against the endpoints and read the response). Even without
credentials, `*` invites arbitrary embedding of the tool from unknown
origins — the API is not a public dataset endpoint.

Fix contract:

  (1) Default (env unset): no CORSMiddleware is attached — the API is
      **same-origin only**. This is the correct default for a tool that
      hasn't yet declared its cross-origin partners.

  (2) Opt-in via `POSTURE_ALLOWED_ORIGINS`: comma-separated explicit
      origin list. Never `*`. The middleware is attached with
      `allow_origins=<parsed list>` verbatim.

  (3) A stale `POSTURE_ALLOWED_ORIGINS="*"` value MUST be rejected
      (raise on startup). The whole point of S2 is banishing `*`; a
      bad env value must not silently fall back to it.

Tests exercise `web.server._build_app` (a small factory extracted from
module-level app construction) so each test gets a fresh app with a
controlled env state — patching the already-built module-level `app`
would leave middleware ordering ambiguous.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest


def _get_cors_middleware(app):
    """Return the CORSMiddleware entry from an app's user_middleware
    list, or None if not attached. Starlette stores middleware as
    `Middleware(cls, **options)` tuples on `app.user_middleware`."""
    from fastapi.middleware.cors import CORSMiddleware
    for m in app.user_middleware:
        if m.cls is CORSMiddleware:
            return m
    return None


def _build_fresh_app():
    """Import + rebuild the app with the current environment. Uses the
    factory `web.server._build_app` — see module docstring for why."""
    from web import server
    return server._build_app()


def test_default_no_cors_middleware_attached():
    """Without an explicit allow-list, the app is same-origin only.
    Attaching CORSMiddleware(allow_origins=[]) would still emit CORS
    machinery on preflight — the correct default is to skip the
    middleware entirely so cross-origin requests fail the browser's
    same-origin check with no ambiguity."""
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("POSTURE_ALLOWED_ORIGINS", None)
        app = _build_fresh_app()
    assert _get_cors_middleware(app) is None, (
        "Default app must have NO CORSMiddleware attached — same-origin only. "
        f"Found: {_get_cors_middleware(app)}"
    )


def test_wildcard_allow_origins_is_rejected():
    """The whole point of S2 is banishing `*`. If somebody sets the
    env var to `*` (either by mistake or by assuming it's the same
    knob as before), startup must fail loudly. Silent fall-through
    to `*` would re-open the bypass."""
    with patch.dict(os.environ, {"POSTURE_ALLOWED_ORIGINS": "*"}):
        with pytest.raises(ValueError, match=r"[Ww]ildcard|\*"):
            _build_fresh_app()


def test_wildcard_inside_a_list_is_rejected():
    """Belt-and-braces on the previous test: even if `*` is buried
    inside a comma-separated list it must still be rejected. A user
    doing 'https://vergecloud.com,*' should get a startup error, not
    a silent open door."""
    with patch.dict(
        os.environ,
        {"POSTURE_ALLOWED_ORIGINS": "https://vergecloud.com,*"},
    ):
        with pytest.raises(ValueError, match=r"[Ww]ildcard|\*"):
            _build_fresh_app()


def test_explicit_origins_are_attached_verbatim():
    """A valid comma-separated allow-list is parsed into a Python
    list and passed as `allow_origins` on the middleware. The
    ordering is preserved so operators debugging preflight failures
    can grep for the exact string they configured."""
    origins = "https://vergecloud.com,https://www.vergecloud.com"
    with patch.dict(os.environ, {"POSTURE_ALLOWED_ORIGINS": origins}):
        app = _build_fresh_app()
    mw = _get_cors_middleware(app)
    assert mw is not None, (
        "Explicit POSTURE_ALLOWED_ORIGINS must attach CORSMiddleware"
    )
    assert mw.kwargs.get("allow_origins") == [
        "https://vergecloud.com",
        "https://www.vergecloud.com",
    ], f"allow_origins mismatch: got {mw.kwargs.get('allow_origins')!r}"


def test_whitespace_around_origins_is_stripped():
    """Operators editing the env var by hand may leave whitespace
    after commas. Silently strip so `"a, b, c"` and `"a,b,c"` behave
    identically — a strict-parse would trip trivial typos."""
    with patch.dict(
        os.environ,
        {"POSTURE_ALLOWED_ORIGINS": " https://a.example , https://b.example "},
    ):
        app = _build_fresh_app()
    mw = _get_cors_middleware(app)
    assert mw.kwargs["allow_origins"] == [
        "https://a.example", "https://b.example",
    ]


def test_empty_env_value_is_treated_as_unset():
    """`POSTURE_ALLOWED_ORIGINS=""` (empty string) should be treated
    identically to the env var being unset — no CORS middleware.
    Otherwise a shell env-setting bug (`export POSTURE_ALLOWED_ORIGINS=`)
    would attach `CORSMiddleware(allow_origins=[])` and produce
    silently confusing preflight failures."""
    with patch.dict(os.environ, {"POSTURE_ALLOWED_ORIGINS": ""}):
        app = _build_fresh_app()
    assert _get_cors_middleware(app) is None
