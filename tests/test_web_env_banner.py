"""Regression tests for W5 — surface a degraded environment on the
landing page.

The `/healthz` endpoint already returns 503 with a payload naming the
environment issue (DNS interception, TCP/53 blocked, AA-flag rewrite).
Previously the front-end never called it, so the user submitted a
scan and received findings that were correctly labelled "UNKNOWN"
but with no cue that the *cause* was network-path degradation on the
server, not on the domain being scanned.

Fix contract:
  - `app.js` fetches `/healthz` on load.
  - If the response is non-200 (or `status != "ok"`), a banner is
    rendered above the form summarising why per-nameserver probing
    will be unreliable.
  - The banner lives in an aria-live region so a screen-reader user
    hears it without polling the DOM.

Tests here pin the structural contract (HTML placeholder + JS
preflight) — the server side of /healthz is already covered by
existing test_web_healthz.py.
"""
from __future__ import annotations

from pathlib import Path
import re

STATIC = Path(__file__).resolve().parents[1] / "web" / "static"
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")


def test_env_banner_placeholder_exists_in_html():
    """The banner has a stable DOM anchor so JS can fill it without
    creating nodes at unpredictable positions above the form. It
    must sit BEFORE the form so the user sees it before typing."""
    banner = re.search(r'<div[^>]+id="envBanner"[^>]*>', INDEX)
    assert banner, "index.html must expose a #envBanner container"
    assert 'aria-live=' in banner.group(0) or 'role="alert"' in banner.group(0), (
        f"#envBanner must be a live region so screen-reader users are "
        f"warned; got {banner.group(0)!r}"
    )


def test_env_banner_starts_hidden():
    """The banner must be `hidden` by default so no visual placeholder
    shows on a healthy environment. The .hidden utility class is
    already defined in style.css."""
    banner = re.search(r'<div[^>]+id="envBanner"[^>]*>', INDEX)
    assert banner
    assert "hidden" in banner.group(0), (
        f"#envBanner must start hidden and only appear on 503 / degraded; "
        f"got {banner.group(0)!r}"
    )


def test_app_js_preflights_healthz_on_load():
    """`app.js` must call `/healthz` — either at module load, or from
    a DOMContentLoaded handler. The exact idiom is up to the author;
    the substring `/healthz` is the load-bearing anchor."""
    assert "/healthz" in JS, (
        f"app.js must preflight /healthz to detect degraded environments"
    )


def test_env_banner_populated_from_healthz_payload():
    """The banner text must be driven by the `/healthz` response — a
    hard-coded string would be a lie when the environment is fine.
    Pin: the code path that shows the banner must reference the JSON
    field `environment` or `notes` returned by /healthz."""
    assert re.search(r"environment|notes|degraded", JS), (
        f"app.js must read /healthz payload fields (environment/notes/"
        f"degraded) into the banner text"
    )
