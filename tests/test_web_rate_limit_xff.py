"""Regression tests for S3 — rate-limit bypass via X-Forwarded-For.

`slowapi.Limiter` keys on `request.client.host`, which is derived
from the ASGI `scope["client"]`. uvicorn's default is
`proxy_headers=True` with `forwarded_allow_ips="127.0.0.1"` — that is,
when the immediate TCP peer is 127.0.0.1, uvicorn overwrites
`scope["client"]` with the leftmost `X-Forwarded-For` value. On
same-host deployments (a reverse proxy on 127.0.0.1, or a client
looping back to test the tool) that turns XFF into a fully-controlled
rate-limit key: `curl -H "X-Forwarded-For: 1.2.3.4" ...` gets its own
per-IP quota. A crawler can rotate this header freely and bypass the
10-req/min limit.

The rate-limit key MUST be the actual socket peer regardless of what
`scope["client"]` says. Two ways to fix this:

  (1) tell uvicorn to never trust proxy headers (proxy_headers=False)
      — global fix at the process boundary.

  (2) key the limiter off the raw socket peer directly, ignoring
      whatever scope["client"] became after uvicorn's processing.

We do BOTH — belt-and-braces per CLAUDE.md rule 6 ("do not weaken
accuracy for convenience"). (1) covers the common `posture-web`
invocation; (2) survives an operator who overrides uvicorn args or
runs the app under a different ASGI server that doesn't respect the
same knob.

Opt-in escape hatch: `POSTURE_TRUST_PROXY=1` re-enables
`proxy_headers=True` — for the case where the tool sits behind a
real reverse proxy that already sanitises XFF from outside. The
rate-limit key still uses the socket peer, so even under opt-in the
XFF bypass does not open up.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest


def test_uvicorn_run_defaults_to_proxy_headers_false():
    """`posture-web` (web.server:main) must pass proxy_headers=False
    to uvicorn so scope['client'] is the true socket peer, not the
    leftmost X-Forwarded-For entry. Without this, a same-host client
    can rotate XFF and get a fresh rate-limit bucket per rotation."""
    import web.server as srv

    captured: dict = {}
    def fake_run(app_ref, **kwargs):
        captured["kwargs"] = kwargs

    with patch.object(srv, "__name__", "web.server"), \
         patch.dict(os.environ, {}, clear=False):
        os.environ.pop("POSTURE_TRUST_PROXY", None)
        with patch("uvicorn.run", fake_run):
            srv.main()

    assert captured["kwargs"].get("proxy_headers") is False, (
        f"web.server:main must pass proxy_headers=False by default so "
        f"X-Forwarded-For is ignored; got kwargs={captured['kwargs']}"
    )


def test_uvicorn_run_honours_posture_trust_proxy_opt_in():
    """Behind a real reverse proxy the operator can set
    POSTURE_TRUST_PROXY=1 to re-enable proxy_headers. The rate-limit
    key must NOT depend on this — it uses the socket peer regardless
    — but the escape hatch exists for X-Forwarded-For-driven logging
    / audit trails in downstream tooling."""
    import web.server as srv

    captured: dict = {}
    def fake_run(app_ref, **kwargs):
        captured["kwargs"] = kwargs

    with patch.dict(os.environ, {"POSTURE_TRUST_PROXY": "1"}), \
         patch("uvicorn.run", fake_run):
        srv.main()

    assert captured["kwargs"].get("proxy_headers") is True, (
        f"POSTURE_TRUST_PROXY=1 must flip proxy_headers on; "
        f"got kwargs={captured['kwargs']}"
    )


def test_rate_limit_key_uses_socket_peer_not_xff_header():
    """Behavioural pin at the limiter level. Build a fake Starlette
    Request whose `client.host` is the socket peer and whose headers
    carry an X-Forwarded-For different from the peer. The
    `_rate_limit_key` function used by the app's Limiter must return
    the socket peer, NOT the XFF header value.

    This test survives independent of uvicorn config — a future
    refactor that moves the app under hypercorn or gunicorn+worker
    still gets the same guarantee."""
    from web.server import _rate_limit_key

    class _FakeClient:
        def __init__(self, host: str):
            self.host = host

    class _FakeRequest:
        def __init__(self, peer: str, xff: str | None):
            self.client = _FakeClient(peer)
            self.headers = {"x-forwarded-for": xff} if xff else {}

    req = _FakeRequest(peer="203.0.113.1", xff="1.2.3.4, 5.6.7.8")
    key = _rate_limit_key(req)
    assert key == "203.0.113.1", (
        f"rate-limit key must be the socket peer, not the XFF header; "
        f"got {key!r}"
    )


def test_rate_limit_key_falls_back_to_loopback_when_client_absent():
    """Belt-and-braces: unit test the None-safety of the key function.
    slowapi's default returns 127.0.0.1 on absent client; ours must
    match that behaviour so no request escapes the rate-limit bucket
    entirely."""
    from web.server import _rate_limit_key

    class _FakeRequest:
        client = None
        headers: dict = {}

    key = _rate_limit_key(_FakeRequest())
    assert key == "127.0.0.1", (
        f"absent socket peer must key as 127.0.0.1 (matches slowapi "
        f"default); got {key!r}"
    )


def test_limiter_is_wired_to_the_socket_peer_key_func():
    """Contract: the app-level `limiter` object must use
    `_rate_limit_key`, not slowapi's `get_remote_address`. A future
    refactor that reverts to `get_remote_address` would silently
    reintroduce the bypass because `get_remote_address` reads
    `request.client.host` which uvicorn overwrites."""
    from web.server import limiter, _rate_limit_key

    assert limiter._key_func is _rate_limit_key, (
        f"limiter key_func must be _rate_limit_key (socket-peer only); "
        f"got {limiter._key_func}"
    )
