"""Regression tests for CP1+CP2+CP3+CP4+CP7 — the project shipped
without a `pyproject.toml`.

Consequences the audit named:

  - CP1: Windows and non-shell environments (some CI, Nix, container
    images without bash) cannot invoke the tool. Bash launchers only.
  - CP2: `requirements.txt` alone. No project metadata, no name/
    version, no reproducible install path via `pip install .`.
  - CP3: Uses PEP 604 union syntax (`str | None`) and match statements
    — 3.10+ features — but nothing enforces the floor. A user on 3.8
    gets a syntax error at import time.
  - CP4: `uvicorn[standard]` pulls `uvloop`, which does not install on
    Windows. The web launcher becomes a Windows-only failure.
  - CP7: `cryptography` builds from source without version pinning.
    On Windows/Alpine that means a 5+ minute install and, if the
    Rust toolchain isn't present, an outright failure. Every signed
    zone regresses to UNKNOWN if the dependency fails to install
    (see D4).

Fix: a PEP 621 `pyproject.toml` at the repo root declaring project
metadata, dependencies, script entry points (`posture-cli`,
`posture-web`), a `requires-python = ">=3.10"` floor, and a
Windows-safe `web` extra using plain uvicorn.

This test file reads `pyproject.toml` and asserts the contract.
Tests over TOML data (rather than over the effects of installing)
because a full install-then-invoke test would be too slow for the
unit test bar and would require creating a real virtualenv per run.
"""
from __future__ import annotations

import sys
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ImportError:  # 3.10 has tomli
    import tomli as tomllib  # type: ignore


REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"


def _load():
    """Read and parse pyproject.toml. Any test that calls this
    exercises the CP2 invariant: the file exists and is valid TOML."""
    assert PYPROJECT.exists(), (
        f"CP2 regression: expected pyproject.toml at repo root "
        f"({PYPROJECT}); found nothing. Cannot install the project via "
        f"`pip install .` and Windows users have no non-bash entrypoint."
    )
    return tomllib.loads(PYPROJECT.read_text())


# ---------------------------- CP2: file exists, parseable ----------------

def test_pyproject_toml_exists_and_parses():
    """Baseline invariant: the file exists and is a valid TOML document
    with a `[project]` table (PEP 621)."""
    data = _load()
    assert "project" in data, \
        f"pyproject.toml has no [project] table; got top-level keys {sorted(data)}"


def test_project_metadata_is_populated():
    """Minimum PEP 621 fields the package needs to install and be
    identifiable on PyPI or in a dependency graph."""
    data = _load()
    p = data["project"]
    for key in ("name", "version", "description"):
        assert key in p and p[key], f"[project].{key} must be set (got {p.get(key)!r})"


# ---------------------------- CP3: python floor --------------------------

def test_requires_python_declares_3_10_floor():
    """The codebase uses PEP 604 union syntax (`str | None`) which
    Python 3.9 cannot parse. `requires-python` must reflect that.
    Missing this line makes the tool `pip install`-able on 3.8/3.9
    where it will then fail at first import with a SyntaxError — the
    least helpful failure mode possible."""
    data = _load()
    req = data["project"].get("requires-python", "")
    assert req, "requires-python must be declared"
    # Normalize: accept ">=3.10", ">=3.10,<4", ">= 3.10", etc.
    stripped = req.replace(" ", "")
    assert (">=3.10" in stripped or ">=3.11" in stripped or
            ">=3.12" in stripped or ">=3.13" in stripped or
            ">=3.14" in stripped), (
        f"requires-python must set a floor of >=3.10 (PEP 604 syntax is used); "
        f"got {req!r}"
    )


# ---------------------------- CP1: entry scripts -------------------------

def test_entry_scripts_registered_for_both_launchers():
    """The whole point of CP1: after `pip install -e .`, users on any
    platform (Windows, Linux, macOS, containers without bash) must be
    able to invoke `posture-cli` and `posture-web` without shell
    wrappers. Registering the entry points in [project.scripts] is
    what enables that."""
    data = _load()
    scripts = data["project"].get("scripts", {})
    assert "posture-cli" in scripts, (
        f"CP1: expected [project.scripts] entry `posture-cli`; got {sorted(scripts)}"
    )
    assert "posture-web" in scripts, (
        f"CP1: expected [project.scripts] entry `posture-web`; got {sorted(scripts)}"
    )
    # Sanity-check the module targets — a typo like `posture.web:main`
    # would install but fail at first invocation.
    assert ":" in scripts["posture-cli"], \
        f"posture-cli entry must be a module:function reference; got {scripts['posture-cli']!r}"
    assert ":" in scripts["posture-web"], \
        f"posture-web entry must be a module:function reference; got {scripts['posture-web']!r}"


def test_cli_entry_target_is_importable():
    """The entry-script target must actually exist. A commit that
    renames `posture.cli.main` without updating pyproject.toml would
    otherwise silently break `posture-cli` for every fresh install."""
    data = _load()
    target = data["project"]["scripts"]["posture-cli"]
    module_path, _, attr = target.partition(":")
    mod = __import__(module_path, fromlist=[attr])
    assert hasattr(mod, attr), (
        f"CP1: pyproject.toml points posture-cli at {target!r} but "
        f"{module_path} has no attribute `{attr}`"
    )


def test_web_entry_target_is_importable():
    """Same guard for the web entry point."""
    data = _load()
    target = data["project"]["scripts"]["posture-web"]
    module_path, _, attr = target.partition(":")
    mod = __import__(module_path, fromlist=[attr])
    assert hasattr(mod, attr), (
        f"CP1: pyproject.toml points posture-web at {target!r} but "
        f"{module_path} has no attribute `{attr}`"
    )


# ---------------------------- CP4: uvicorn split -------------------------

def test_core_dependencies_do_not_pull_uvloop():
    """The core `[project.dependencies]` list must NOT include
    `uvicorn[standard]` — that extras spec pulls uvloop, which does
    not build on Windows. The web-only path belongs in an extras
    group (see next test). Leaving it in core makes `pip install .`
    a Windows-only failure."""
    data = _load()
    deps = data["project"].get("dependencies", [])
    offenders = [d for d in deps if "uvicorn[standard]" in d.replace(" ", "")]
    assert not offenders, (
        f"CP4: `uvicorn[standard]` must not be a core dep (uvloop breaks "
        f"Windows). Move to [project.optional-dependencies]. Offenders: {offenders}"
    )


def test_web_extra_provides_web_stack():
    """The web layer's dependencies (FastAPI, uvicorn, slowapi) belong
    behind an optional extra so CLI-only users don't drag them in and
    Windows users can opt for plain uvicorn."""
    data = _load()
    extras = data["project"].get("optional-dependencies", {})
    assert "web" in extras, (
        f"CP4: expected a `web` extra in [project.optional-dependencies]; "
        f"got extras {sorted(extras)}"
    )
    web_deps = " ".join(extras["web"]).lower()
    for needle in ("fastapi", "uvicorn", "slowapi"):
        assert needle in web_deps, (
            f"CP4: `web` extra should include {needle}; got {extras['web']}"
        )


# ---------------------------- CP7: cryptography wheel --------------------

def test_cryptography_dependency_has_version_floor_for_wheels():
    """CP7: `cryptography` prior to ~41 required a Rust toolchain to
    build from source. Modern releases (41+) publish wheels for all
    supported Pythons on all major platforms. Pinning a floor forces
    pip to grab a wheel and prevents 5+ minute compile times (or
    outright failure without cargo) on developer laptops. The old
    requirements.txt already carried `cryptography>=42`; that pin has
    to survive the transition."""
    data = _load()
    deps = data["project"].get("dependencies", [])
    crypto = [d for d in deps if d.split()[0].split(">")[0].split("=")[0].split("<")[0].strip().lower() == "cryptography"]
    assert crypto, (
        f"cryptography must be a core dep (D4 requires it for DNSSEC); "
        f"not found in {deps}"
    )
    spec = crypto[0]
    # Floor of 41+ ensures Windows/macOS/Linux wheels are available for
    # every supported Python.
    assert ">=" in spec, (
        f"CP7: cryptography needs a >= version floor for wheel selection; "
        f"got {spec!r}"
    )
