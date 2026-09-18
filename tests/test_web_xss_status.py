"""Regression test for C1 — XSS via unescaped ``f.status`` in ``app.js``.

The web front-end renders each finding as::

    <span class="badge ${f.status}">${f.status}</span>

Both interpolations of ``f.status`` were raw. ``escapeHtml`` was applied to
``label``, ``detail`` and ``why`` — but not to ``status``, which is trusted
because it *should* be one of ``PASS|WARN|FAIL|INFO``. That is a producer-
side assumption; the browser is the trust boundary. A hostile or buggy
producer that emits ``status = 'x" onmouseover="alert(1)'`` breaks out of
the class attribute and gets JavaScript execution on ``vergecloud.com``.

The fix must:

  1. Never interpolate ``f.status`` directly into an HTML class attribute.
  2. Constrain the value to a fixed whitelist before use.
  3. Escape it (or whitelist-derive it) before use as text content.

These are source-level assertions because the repo has no JS test runner
yet — that's a Phase 6 concern. Source-level pinning is enough to catch
the exact regression: the vulnerable substring must not reappear.
"""
from __future__ import annotations

import re
from pathlib import Path


APP_JS = Path(__file__).resolve().parents[1] / "web" / "static" / "app.js"


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def test_app_js_exists():
    assert APP_JS.is_file(), f"expected {APP_JS} to exist"


def test_status_is_not_interpolated_bare_in_class_attribute():
    """The exact C1 vector: ``class="...${f.status}..."`` in a template
    literal. If this pattern reappears the XSS is back."""
    src = _src()
    pattern = re.compile(r'class\s*=\s*"[^"]*\$\{\s*f\.status\s*\}[^"]*"')
    hits = pattern.findall(src)
    assert not hits, (
        "XSS: bare ${f.status} interpolated into a class attribute. "
        f"Matches: {hits}"
    )


def test_status_whitelist_is_defined():
    """The fix requires a fixed whitelist of the four legal status values.
    Accept either a Set literal or an array literal — both work as the
    whitelist check. The exact identifier is not pinned, but the four
    canonical values must appear together in a single literal."""
    src = _src()
    # The four values, in any order, inside one Set/Array literal.
    literal_pattern = re.compile(
        r'(new\s+Set\s*\(\s*\[|\[)'          # opening
        r'(?=[^\]]*"PASS")'
        r'(?=[^\]]*"WARN")'
        r'(?=[^\]]*"FAIL")'
        r'(?=[^\]]*"INFO")'
        r'[^\]]*\]',
        re.DOTALL,
    )
    assert literal_pattern.search(src), (
        "Expected a whitelist literal containing PASS, WARN, FAIL, INFO "
        "so status values can be constrained before use in the DOM."
    )


def test_status_text_content_is_escaped_or_whitelist_derived():
    """The second interpolation on the same line (as text content) must
    also not be raw ``${f.status}``. Either escapeHtml() wraps it, or a
    whitelist-derived local (e.g. ``badgeCls``) is substituted."""
    src = _src()
    # Vulnerable text-content pattern inside <span class="badge ...">
    vuln = re.compile(
        r'<span\s+class="badge\s+[^"]*">\s*\$\{\s*f\.status\s*\}\s*</span>'
    )
    assert not vuln.search(src), (
        "f.status is still used raw as the badge text content. "
        "Wrap in escapeHtml() or substitute a whitelist-derived value."
    )
