"""Regression tests for CP5 — the tool had no Dockerfile.

Containers are the most reliable cross-platform path for both SE
laptop use and eventual deploy. Without one:

  - macOS/Windows/Linux each need their own local-env setup path.
  - The `cryptography` toolchain requirement (CP7) is a real
    obstacle on some Linux distros.
  - Deployment to any container platform (Kubernetes, ECS, Fly.io,
    Cloud Run) requires the deployer to author their own Dockerfile,
    getting the details subtly wrong (running as root, missing
    static files, port binding).

Fix: a Dockerfile at the repo root that:

  - uses a pinned python:3.X-slim base (small, reproducible)
  - installs the project via `pip install .[web]` (exercises the
    PEP 621 metadata added in CP2/CP4)
  - runs as a non-root user (defense in depth for anything that
    ever runs untrusted domain input)
  - exposes port 8000 (matches `run_web.sh`'s hardcoded port)
  - defaults CMD to `posture-web` so `docker run <image>` starts
    the web tool without additional args
  - copies web/static/* into the image so the SPA can be served

These are structural assertions over the Dockerfile text, not
`docker build` invocations — the CI target and dev-laptop bar don't
justify pulling docker into pytest. A build-and-run smoke test can
live in a downstream CI workflow (out of scope for this repo's
test suite).
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _load() -> str:
    assert DOCKERFILE.exists(), (
        f"CP5 regression: expected a Dockerfile at repo root "
        f"({DOCKERFILE}); none present. Container platform users "
        f"cannot deploy without authoring their own from scratch."
    )
    return DOCKERFILE.read_text()


def test_dockerfile_exists_and_readable():
    body = _load()
    assert body.strip(), "Dockerfile is empty"


def test_dockerfile_uses_python_slim_base():
    """`slim` shaves ~700 MB off the default python image and is the
    right default for tools that don't need a full toolchain at
    runtime. Locking to `python:` + `slim` catches accidental
    swaps to `python:3.12` (full) or `alpine` (which historically
    has cryptography wheel issues)."""
    body = _load()
    assert "python:" in body, f"expected `python:<ver>-slim` base; got:\n{body}"
    assert "-slim" in body, (
        f"expected a `-slim` base image (not full or alpine); Dockerfile:\n{body}"
    )


def test_dockerfile_pins_python_version_floor():
    """The base image tag must NOT be a floating tag like `python:slim`
    or `python:latest`. Reproducibility requires a pinned major.minor
    (3.10, 3.11, 3.12, 3.13, 3.14). Matches pyproject.toml
    `requires-python = ">=3.10"`."""
    body = _load()
    import re
    m = re.search(r"FROM\s+python:(\d+)\.(\d+)", body)
    assert m, (
        f"Dockerfile must pin a python:X.Y-slim base image; "
        f"floating tags like `python:slim` are non-reproducible. "
        f"Dockerfile:\n{body}"
    )
    major, minor = int(m.group(1)), int(m.group(2))
    assert (major, minor) >= (3, 10), (
        f"Dockerfile base image must be Python 3.10+ to match "
        f"pyproject.toml requires-python; got {major}.{minor}"
    )


def test_dockerfile_installs_via_pep621_metadata():
    """The Dockerfile must exercise the pyproject.toml install path —
    that's the entire point of CP1/CP2. A `pip install -r
    requirements.txt` here would bypass the entry-scripts and
    optional-deps split (CP4), making the container Windows/Alpine
    friendly by accident of language."""
    body = _load()
    assert "pip install" in body, f"Dockerfile must install with pip; got:\n{body}"
    # Either `pip install .[web]` or `pip install .[web,...]` or an -e variant.
    assert (".[web" in body or ".[web]" in body), (
        f"Dockerfile must install the `web` extra so uvicorn/fastapi/slowapi "
        f"are present at runtime; got:\n{body}"
    )


def test_dockerfile_runs_as_non_root():
    """Defense in depth: the tool takes arbitrary domain names from
    users and hits arbitrary third-party infrastructure. Running as
    root in a container isn't necessary and reduces the blast radius
    of any future container-escape or file-write bug."""
    body = _load()
    assert "USER " in body, (
        f"Dockerfile must include a USER directive so the process "
        f"drops privileges before serving traffic; got:\n{body}"
    )
    # A USER 0 or USER root would satisfy the grep but defeat the point.
    lines = [l.strip() for l in body.splitlines()
             if l.strip().startswith("USER ")]
    last = lines[-1] if lines else ""
    assert last and last != "USER root" and last != "USER 0", (
        f"final USER directive must not be root; got {last!r}"
    )


def test_dockerfile_exposes_web_port():
    """The web layer binds 127.0.0.1:8000 by default. In a container
    the bind address must be 0.0.0.0 (already handled if we use
    `posture-web` as CMD — TODO in the Dockerfile) but the EXPOSE
    directive telegraphs the port to deployers using `docker run -P`
    and to platforms like Fly.io / Cloud Run that read it."""
    body = _load()
    assert "EXPOSE 8000" in body, (
        f"Dockerfile must EXPOSE 8000 for the web tool; got:\n{body}"
    )


def test_dockerfile_default_cmd_starts_web_tool():
    """`docker run <image>` with no args should Just Work — spin up
    the web tool on port 8000. This is the most common `docker run`
    invocation and the friendliest default."""
    body = _load()
    # Accept either CMD ["posture-web"] JSON form or CMD posture-web shell form,
    # but require the entry-script name to appear in the final CMD/ENTRYPOINT.
    lines = [l.strip() for l in body.splitlines()
             if l.strip().startswith(("CMD", "ENTRYPOINT"))]
    joined = " ".join(lines).lower()
    assert "posture-web" in joined or "web.server" in joined, (
        f"Dockerfile default CMD/ENTRYPOINT must start the web tool; got:\n{lines}"
    )
