"""Regression tests for S8 — no first-run warning about probing infra.

The CLI makes live DNS, RDAP and AXFR queries against real third-party
infrastructure. It is legally fine (the domain owner could run these
themselves) but users invoking the tool for the first time should be
told, plainly, that outbound traffic is going to third parties. The
audit calls for a one-time banner on first invocation.

Contract:
  - First invocation: banner printed to **stderr** (not stdout, so
    `--json` output stays parseable). Banner names the categories of
    traffic — DNS, RDAP, AXFR — and points at a way to acknowledge
    without seeing it again.
  - Subsequent invocations: banner suppressed (ack file recorded).
  - `POSTURE_ACK_FIRST_RUN=1` env var: banner suppressed without
    writing the ack file, useful for CI and one-shot script runs.
  - Ack file lives under `~/.config/posture-checker/first-run.ack`
    (XDG-standard). If XDG_CONFIG_HOME is set, honour it.
  - Never printed on stdout — a `--json` consumer piping the output
    into `jq` would otherwise get a parse error from banner text.
"""
from __future__ import annotations

import io
import os
from pathlib import Path
from unittest.mock import patch

import pytest


def _run_cli(monkeypatch, argv, home: Path):
    """Invoke the CLI's `main` under an isolated $HOME.

    Mocks `run(...)` so no live network. Captures stdout + stderr.
    Returns (exit_code, stdout, stderr)."""
    from posture import cli
    from posture.core import Report

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.delenv("POSTURE_ACK_FIRST_RUN", raising=False)

    fake_rep = Report(domain_input="example.com", domain="example.com")

    stderr = io.StringIO()

    def fake_run(*a, **k):
        return fake_rep

    # Capture stderr — argparse and our banner both write there.
    with patch("posture.cli.run", fake_run), \
         patch("posture.cli.render", lambda *a, **k: None), \
         patch("sys.stderr", stderr):
        rc = cli.main(argv)

    return rc, stderr.getvalue()


# ---------------------------------------------------------- first run

def test_first_run_prints_banner_on_stderr(monkeypatch, tmp_path):
    rc, err = _run_cli(monkeypatch, ["example.com"], tmp_path)
    assert rc == 0
    combined = err.lower()
    # Must mention that the tool actively probes infra.
    assert "probe" in combined or "queries" in combined or "live" in combined, (
        f"first-run banner must indicate live probing; stderr was: {err!r}"
    )
    # Must name the traffic categories so the user knows what to expect.
    for kind in ("dns", "rdap"):
        assert kind in combined, (
            f"first-run banner must name '{kind}' traffic category; "
            f"stderr was: {err!r}"
        )


def test_first_run_creates_ack_file(monkeypatch, tmp_path):
    """After the banner is shown, the ack file must be written so a
    second invocation doesn't repeat the message."""
    _run_cli(monkeypatch, ["example.com"], tmp_path)
    ack = tmp_path / ".config" / "posture-checker" / "first-run.ack"
    assert ack.exists(), (
        f"ack file must be created at {ack} after first run; "
        f"tree: {list(tmp_path.rglob('*'))}"
    )


def test_json_output_is_not_polluted_by_banner(monkeypatch, tmp_path, capsys):
    """A `posture --json` consumer piping into `jq` must not have to
    strip banner text. Banner goes to stderr only."""
    from posture import cli
    from posture.core import Report

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.delenv("POSTURE_ACK_FIRST_RUN", raising=False)

    fake_rep = Report(domain_input="example.com", domain="example.com")
    with patch("posture.cli.run", return_value=fake_rep):
        cli.main(["example.com", "--json"])

    captured = capsys.readouterr()
    # Stdout must be JSON (or at least: must not contain the banner text).
    # We accept the possibility that _jsonable or grade() write something
    # to stdout; the strict requirement is banner-free.
    assert "probe" not in captured.out.lower(), (
        f"first-run banner leaked onto stdout; stdout was: {captured.out!r}"
    )
    assert "live queries" not in captured.out.lower()


# ---------------------------------------------------------- second run

def test_second_run_does_not_reprint_banner(monkeypatch, tmp_path):
    """Once the ack file exists, subsequent runs must be silent
    about the probe warning — an operator running the tool 100 times
    in a session should not have to filter out this text."""
    # Pre-create the ack file so this simulates a "second run".
    ack_dir = tmp_path / ".config" / "posture-checker"
    ack_dir.mkdir(parents=True)
    (ack_dir / "first-run.ack").write_text("acked\n")

    rc, err = _run_cli(monkeypatch, ["example.com"], tmp_path)
    assert rc == 0
    assert "probe" not in err.lower() and "live queries" not in err.lower(), (
        f"banner must not be reprinted on second run; stderr was: {err!r}"
    )


# ---------------------------------------------------------- env override

def test_env_var_suppresses_banner_without_writing_ack(monkeypatch, tmp_path):
    """CI and script use case: `POSTURE_ACK_FIRST_RUN=1 posture ...`
    suppresses the banner for the current invocation, but must NOT
    write an ack file — the operator running interactively later on
    the same machine should still see the banner."""
    from posture import cli
    from posture.core import Report

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("POSTURE_ACK_FIRST_RUN", "1")

    fake_rep = Report(domain_input="example.com", domain="example.com")
    stderr = io.StringIO()
    with patch("posture.cli.run", return_value=fake_rep), \
         patch("posture.cli.render", lambda *a, **k: None), \
         patch("sys.stderr", stderr):
        cli.main(["example.com"])

    err = stderr.getvalue()
    assert "probe" not in err.lower() and "live queries" not in err.lower(), (
        f"POSTURE_ACK_FIRST_RUN must suppress banner; stderr was: {err!r}"
    )
    ack = tmp_path / ".config" / "posture-checker" / "first-run.ack"
    assert not ack.exists(), (
        "env-var opt-out must NOT persist ack — interactive user on the "
        "same box should still get the banner"
    )
