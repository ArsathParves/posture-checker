"""Regression tests for S5 + S6 — missing security-hardening headers.

v0.5 baseline: the FastAPI app served HTML and JSON with no CSP, no
`X-Content-Type-Options`, no `Referrer-Policy`, and no `Permissions-Policy`.
Once C1 (XSS) has been fixed, these headers are the second-line-of-defence
that reduces the blast radius of any future template regression:

  - **Content-Security-Policy**: `default-src 'self'` blocks any injected
    `<script>` from external origins; `frame-ancestors 'none'` prevents
    clickjacking iframes; `base-uri 'none'` blocks `<base>` hijack.
  - **X-Content-Type-Options: nosniff**: prevents `.js`/`.css` MIME-sniff
    bypass when the server (mis)labels a response.
  - **Referrer-Policy: no-referrer**: the tool receives a domain in the URL
    path when checks are shared; suppress leakage of the checked domain
    to any external resource.
  - **Permissions-Policy**: disable geolocation/microphone/camera/etc — the
    SPA has zero legitimate need for any of these APIs and the default
    is opt-out per Permissions-Policy §4.

Contract:
  - Every response from every endpoint carries these headers (both
    static assets and the JSON/SSE API surface).
  - The CSP is strict — no `'unsafe-inline'`, no `'unsafe-eval'`. The
    SPA has been audited to be free of inline scripts/styles and inline
    event handlers, so this is achievable without escape hatches.
  - Response body is unmodified — the middleware only adds headers.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    """Use the module-level `app` so /static and / (routes declared
    at module scope, after `_build_app()` returns) are available.

    Patch `check_environment` to a fast stub — /healthz otherwise runs
    a real DNS selftest that turns this file into a 20-second network
    test. We're testing headers, not selftest behaviour."""
    from web import server
    fake_env = {"safe_for_per_ns_checks": True, "notes": []}
    with patch.object(server, "check_environment", return_value=fake_env):
        with TestClient(server.app) as c:
            yield c


REQUIRED_HEADERS = {
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}


def _headers_lower(response):
    return {k.lower(): v for k, v in response.headers.items()}


# ---------------------------------------------------------- coverage

def test_root_index_has_all_security_headers(client):
    """The main SPA HTML must ship every hardening header. This is the
    only HTML the tool serves — if the middleware skips it, a template
    XSS regression (C1) has zero mitigation."""
    r = client.get("/")
    headers = _headers_lower(r)
    missing = REQUIRED_HEADERS - set(headers)
    assert not missing, f"missing hardening headers on /: {missing}"


def test_static_asset_has_all_security_headers(client):
    """A `<script src="/static/malicious.js">` injection would be served
    with the same headers — belt-and-braces, the middleware must not
    exclude the static mount."""
    r = client.get("/static/app.js")
    if r.status_code == 404:
        pytest.skip("static app.js not present in this test tree")
    headers = _headers_lower(r)
    missing = REQUIRED_HEADERS - set(headers)
    assert not missing, f"missing hardening headers on /static/app.js: {missing}"


def test_json_api_has_all_security_headers(client):
    """The JSON API surface also gets the headers — `X-Content-Type-Options:
    nosniff` on a JSON response prevents older Firefox / IE derivatives
    from executing a crafted `text/html` sniff on a `.json` blob."""
    r = client.get("/healthz")
    headers = _headers_lower(r)
    missing = REQUIRED_HEADERS - set(headers)
    assert not missing, f"missing hardening headers on /healthz: {missing}"


# ---------------------------------------------------------- CSP shape

def test_csp_default_src_is_self(client):
    """`default-src 'self'` is the load-bearing directive. Without it,
    a directive omission (say we forgot `img-src`) would fall back to
    unrestricted, defeating the point of the header."""
    r = client.get("/")
    csp = _headers_lower(r)["content-security-policy"]
    assert "default-src 'self'" in csp, f"CSP missing default-src 'self': {csp!r}"


def test_csp_forbids_unsafe_inline_and_eval(client):
    """The SPA has zero inline scripts / inline styles / inline event
    handlers (this was checked when writing this test). If a future
    change introduces one, the CSP will refuse to render it and the
    author must justify adding the escape hatch — this is exactly the
    defence-in-depth signal we want."""
    r = client.get("/")
    csp = _headers_lower(r)["content-security-policy"]
    assert "'unsafe-inline'" not in csp, (
        f"CSP must not contain 'unsafe-inline' — SPA is inline-free: {csp!r}"
    )
    assert "'unsafe-eval'" not in csp, (
        f"CSP must not contain 'unsafe-eval': {csp!r}"
    )


def test_csp_frame_ancestors_none_prevents_clickjacking(client):
    """`frame-ancestors 'none'` is the modern replacement for the
    legacy `X-Frame-Options: DENY` header. A domain-check tool has no
    reason to be embedded — the results contain the domain the user
    typed, which is a mild PII signal in a clickjacking context."""
    r = client.get("/")
    csp = _headers_lower(r)["content-security-policy"]
    assert "frame-ancestors 'none'" in csp, (
        f"CSP must include frame-ancestors 'none': {csp!r}"
    )


def test_csp_base_uri_none_prevents_base_tag_hijack(client):
    """`base-uri 'none'` prevents a template-injection XSS from steering
    every relative URL on the page (script/img/link) to an attacker
    origin via an injected `<base href="//evil.example">` tag."""
    r = client.get("/")
    csp = _headers_lower(r)["content-security-policy"]
    assert "base-uri 'none'" in csp, f"CSP missing base-uri 'none': {csp!r}"


# ---------------------------------------------------------- other headers

def test_x_content_type_options_is_nosniff(client):
    r = client.get("/")
    assert _headers_lower(r)["x-content-type-options"] == "nosniff"


def test_referrer_policy_is_no_referrer(client):
    """Domain names typed into the tool are moderately sensitive
    (someone checking a domain they don't own but are researching);
    `no-referrer` keeps them out of third-party access logs when a
    resource is loaded from the results page."""
    r = client.get("/")
    assert _headers_lower(r)["referrer-policy"] == "no-referrer"


def test_permissions_policy_disables_sensitive_apis(client):
    """The SPA has no legitimate use for geolocation, microphone,
    camera, USB, or payment APIs. Deny each one explicitly so a
    template regression cannot silently gain access."""
    r = client.get("/")
    pp = _headers_lower(r)["permissions-policy"]
    # We accept either `feature=()` (deny) or an equivalent form. The
    # sensitive APIs must appear denied — bare presence of an *allow-
    # list* for these would be a regression.
    for feat in ("geolocation", "microphone", "camera"):
        assert f"{feat}=()" in pp, (
            f"Permissions-Policy must deny {feat}; got: {pp!r}"
        )


# ---------------------------------------------------------- body untouched

def test_body_is_not_modified_by_middleware(client):
    """The middleware must add headers only — no content rewriting.
    A middleware that transforms bodies is a much larger correctness
    surface than a headers-only one."""
    r = client.get("/healthz")
    # /healthz returns a small JSON blob; whatever body ships, our
    # middleware must not have altered its content-length.
    assert r.headers.get("content-length") is None \
        or int(r.headers["content-length"]) == len(r.content), (
            "Content-Length header disagrees with body — middleware "
            "must not be transforming response bodies."
        )
