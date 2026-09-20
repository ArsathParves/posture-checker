"""Regression tests for W2 / W3 / W4 — web-UI polish.

  W2 — SSE stream drop must surface a retry cue.
  W3 — section header must not overflow on <640px viewports.
  W4 — the palette is dark; declare `color-scheme: dark` so browser
       chrome (scrollbars, native form widgets) matches.

Structural pins against `web/static/{index.html,style.css,app.js}` —
same rationale as the accessibility tests: the surface is small and
regressions here are announced loudly by a failing string search.
"""
from __future__ import annotations

from pathlib import Path
import re

STATIC = Path(__file__).resolve().parents[1] / "web" / "static"
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")
CSS = (STATIC / "style.css").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")


# ---------------------------------------------------------------- W2
def test_sse_error_handler_offers_retry():
    """W2 — the current 'Stream error' branch re-enabled the submit
    button but gave no visual retry cue. The user just sees a half-
    populated table.

    Pin: the app must contain some form of retry surface in its error
    path. Accepted forms — a Retry button rendered on error, or an
    aria-labelled control referring to reconnect."""
    has_retry_id = re.search(r'id="retryBtn"', JS) or \
                   re.search(r'id="retryBtn"', INDEX)
    has_retry_word = re.search(r"\bretry\b", JS, re.IGNORECASE)
    assert has_retry_id or has_retry_word, (
        f"app.js must expose a retry surface for the SSE error path; "
        f"grep found neither id='retryBtn' nor the word 'retry'"
    )


def test_retry_button_wired_in_error_event():
    """W2 belt-and-braces: the retry surface must appear specifically
    in the SSE `error` handler, not just as a static button that's
    always visible. A permanently-visible retry would be confusing."""
    err_block = re.search(
        r'currentSource\.addEventListener\("error"[^)]*\)\s*=>\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
        JS, re.DOTALL,
    )
    assert err_block, "app.js must handle the SSE error event"
    body = err_block.group(1)
    assert re.search(r"retry", body, re.IGNORECASE), (
        f"the SSE error handler must reference a retry surface; "
        f"got body={body!r}"
    )


# ---------------------------------------------------------------- W3
def test_mobile_media_query_allows_section_head_to_wrap():
    """W3 — on narrow viewports the section-head's h2 and grade-pill
    were laid out with `justify-content: space-between` and no
    flex-wrap, so a long section title collided with the pill.
    Fix pin: some form of flex-wrap or column reflow must be present
    inside the mobile media query."""
    mq = re.search(r"@media\s*\(max-width:\s*640px\)\s*\{(.*?)\n\}", CSS, re.DOTALL)
    assert mq, "style.css must retain the mobile media query"
    body = mq.group(1)
    assert "section-head" in body or "flex-wrap" in body or \
           "flex-direction: column" in body, (
        f"mobile media query must reflow .section-head to prevent "
        f"the grade pill from overlapping the title; got body={body!r}"
    )


# ---------------------------------------------------------------- W4
def test_color_scheme_declared_dark():
    """W4 — `color-scheme: dark` on :root tells the browser to render
    native form controls and scrollbars in dark mode. Without it,
    Chromium ships a white scrollbar on this dark UI."""
    root = re.search(r":root\s*\{([^}]*)\}", CSS, re.DOTALL)
    assert root, "style.css must have a :root block"
    body = root.group(1)
    assert re.search(r"color-scheme:\s*dark", body), (
        f":root must declare `color-scheme: dark`; got body={body!r}"
    )
