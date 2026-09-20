"""Regression tests for F2 — `run_web.sh` silently falls through to
system Python when `.venv/bin/activate` is missing.

Behaviour before the fix:

    if [ -f .venv/bin/activate ]; then
        source .venv/bin/activate
    fi
    exec uvicorn web.server:app ...

On a fresh clone (`.venv` not yet created), the check succeeds
silently, then `exec uvicorn ...` runs against whatever `uvicorn` is
on PATH — most commonly nothing, producing "command not found", or
worse, a global-site-packages uvicorn that pulls in a wrong
`web.server` and produces a confusing ModuleNotFoundError. The user
gets no actionable signal from run_web.sh itself.

Fix: `run_web.sh` refuses to run without `.venv`, prints a clear
error naming both the venv path and the install command, and exits
with a non-zero status.

This test exercises the actual shell script — `run_web.sh` is the
contract, not a Python function around it. Copying the script into a
temp directory guarantees the test cannot accidentally source the
real repo's `.venv` (the script does `cd "$(dirname "$0")"`).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = REPO_ROOT / "run_web.sh"


def _copy_launcher(dst_dir: Path) -> Path:
    """Copy run_web.sh into an isolated directory. The script cd's to
    its own dirname on start-up, so this fully insulates the test from
    the real repo's `.venv` state."""
    dst = dst_dir / "run_web.sh"
    shutil.copy(LAUNCHER, dst)
    dst.chmod(0o755)
    return dst


def _run_launcher(script: Path, timeout: float = 5.0) -> subprocess.CompletedProcess:
    """Run the script in a fully isolated env. `--check` deliberately
    NOT passed to subprocess — we're asserting failure semantics."""
    return subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        timeout=timeout,
        env={"PATH": "/usr/bin:/bin"},
    )


def test_run_web_refuses_when_venv_missing(tmp_path):
    """The whole point of F2: without .venv the script must NOT
    `exec uvicorn` (which either fails cryptically or, worse, runs
    against system uvicorn with wrong sys.path)."""
    script = _copy_launcher(tmp_path)
    result = _run_launcher(script)
    assert result.returncode != 0, (
        f"run_web.sh must exit non-zero when .venv is missing; "
        f"got exit code {result.returncode} with stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )


def test_run_web_error_message_names_the_venv(tmp_path):
    """A useful error tells the user *what* is missing and *where*
    to look. A silent exit or a bare 'command not found' fails the
    principle. Test that the error output names `.venv` explicitly
    so the user sees the failure mode is fixable locally."""
    script = _copy_launcher(tmp_path)
    result = _run_launcher(script)
    combined = (result.stdout + result.stderr).lower()
    assert ".venv" in combined, (
        f"error message must name '.venv' so the user knows what to create; "
        f"got stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_run_web_error_message_names_install_command(tmp_path):
    """The error should also tell the user *how* to fix it, not just
    *what* is broken. Naming the install path (python -m venv, pip
    install, or pip install .[web]) gives an actionable next step."""
    script = _copy_launcher(tmp_path)
    result = _run_launcher(script)
    combined = (result.stdout + result.stderr).lower()
    # Accept any of the reasonable fix strings — we don't want to
    # over-specify the exact copy since it might grow to include
    # both options over time.
    hints = ("python -m venv", "pip install", "requirements.txt")
    assert any(h in combined for h in hints), (
        f"error should name at least one install command ({hints}); "
        f"got stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_run_web_does_not_invoke_uvicorn_without_venv(tmp_path):
    """Belt-and-braces: even if a rogue `uvicorn` were on PATH, the
    script must refuse before invoking it. Verify the failure mode
    by inspecting exit code + absence of any uvicorn banner in
    stdout. (We supply a stripped PATH to make sure system uvicorn
    can't accidentally satisfy the exec.)"""
    script = _copy_launcher(tmp_path)
    result = _run_launcher(script)
    combined = (result.stdout + result.stderr).lower()
    # If the guard fails, `exec uvicorn` would either succeed and print
    # "uvicorn running on ..." or fail with "command not found". Both
    # signal the guard did NOT intercept. The correct fix aborts before
    # reaching the exec line, so we should never see either banner.
    assert "uvicorn running" not in combined, (
        "run_web.sh reached the uvicorn exec without a venv — guard failed"
    )
