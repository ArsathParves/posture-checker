"""T3 — End-to-end TestClient coverage for `web/server.py` endpoints.

v0.5 baseline: only `_validate_domain` and specific slices of the web
layer (CORS parsing, security-header middleware, SSE timeout ceiling,
rate-limit key derivation, env-banner HTML placeholder, XSS in status
strings) had tests. The *endpoint behaviour itself* — the HTTP contracts
that `web/static/app.js` and any programmatic API consumer depend on —
was not pinned:

  - `/healthz` returning 200 clean vs 503 degraded (CLAUDE.md rule 5 —
    the deploy-time gate that stops us serving false findings on a
    corporate network with transparent DNS proxies).
  - `POST /api/check` — happy path (returns check_id + cached=False),
    validation rejection (400 on URL / path / IP), cache-hit branch
    (cached=True with the full `complete` payload embedded so a repeat
    visitor sees results without waiting).
  - `GET /api/check/{id}/result` — 404 unknown id, 200 with the
    `complete` event payload once the job is done, error-shape when
    the job failed.
  - `GET /api/check/{id}/stream` — 404 unknown id, happy-path SSE
    consumption emits every queued event plus `end` (SSE timeout is
    covered by `test_web_sse_timeout.py` — this file covers the
    normal-completion path).

These tests never hit real DNS. `run_streaming` and `check_environment`
are patched at the `web.server` module boundary so every test finishes
in milliseconds and stays inside the `not network` marker.

The fixtures snapshot and restore `JOBS` and `RESULT_CACHE` between
tests — the server module holds these as module-level dicts, and a
leaked entry between tests would cross-contaminate the cache-hit path.
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------- fixtures

@pytest.fixture()
def clean_env_client():
    """TestClient with `check_environment` stubbed to a clean env and
    `run_streaming` stubbed to emit a minimal happy-path event
    sequence. Isolates the server-side state so JOBS/RESULT_CACHE
    leaks between tests are impossible."""
    from web import server

    fake_env = {
        "safe_for_per_ns_checks": True,
        "udp53_direct": True,
        "tcp53_direct": True,
        "intercepted": False,
        "aa_flag_trustworthy": True,
        "notes": [],
    }

    def fake_run_streaming(domain, dkim_selectors=None, skip_asn=False):
        yield {"event": "started", "domain": domain, "punycode": domain,
               "checked_at": "2026-01-01T00:00:00Z"}
        yield {"event": "environment", "safe": True, "notes": []}
        yield {"event": "section", "name": "Registration & delegation",
               "findings": []}
        yield {"event": "complete",
               "report": {"domain": domain, "punycode": domain,
                          "sections": {}, "data": {}},
               "grades": {"overall": "A", "correctness": "A",
                          "hardening": "A"}}

    prior_jobs = dict(server.JOBS)
    prior_cache = list(server.RESULT_CACHE.items())
    server.JOBS.clear()
    server.RESULT_CACHE.clear()
    try:
        with patch.object(server, "check_environment", return_value=fake_env), \
             patch.object(server, "run_streaming", fake_run_streaming), \
             TestClient(server.app) as c:
            yield c, server
    finally:
        server.JOBS.clear()
        server.JOBS.update(prior_jobs)
        server.RESULT_CACHE.clear()
        for k, v in prior_cache:
            server.RESULT_CACHE[k] = v


@pytest.fixture()
def degraded_env_client():
    """TestClient with `check_environment` stubbed to a degraded env
    (DNS interception detected). /healthz must return 503 in this
    state — that's the CLAUDE.md rule-5 gate."""
    from web import server

    fake_env = {
        "safe_for_per_ns_checks": False,
        "udp53_direct": True,
        "tcp53_direct": True,
        "intercepted": True,
        "aa_flag_trustworthy": True,
        "notes": ["UDP/53 interception detected (3/3 blackhole IPs answered)"],
    }
    with patch.object(server, "check_environment", return_value=fake_env), \
         TestClient(server.app) as c:
        yield c


# ---------------------------------------------------------------- /healthz

def test_healthz_returns_200_when_environment_is_clean(clean_env_client):
    """CLAUDE.md rule 5: a clean network path must serve. The response
    body carries `status: ok` plus the environment payload — the web
    UI's env-banner code reads these fields to decide whether to warn."""
    c, _ = clean_env_client
    r = c.get("/healthz")
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["status"] == "ok"
    assert payload["environment"]["safe_for_per_ns_checks"] is True
    assert "cache_entries" in payload
    assert "in_flight_jobs" in payload


def test_healthz_returns_503_when_environment_is_degraded(degraded_env_client):
    """The load-bearing rule-5 assertion: when the network path is
    untrustworthy (DNS interception, TCP/53 blocked, AA-flag rewrite),
    /healthz MUST return 503 so a Kubernetes/haproxy healthcheck
    de-pools the pod before it serves false findings. A regression
    that flipped this to 200 would silently re-enable serving on a
    corporate network with a transparent DNS proxy — exactly the
    failure mode `selftest.check_environment` exists to prevent."""
    r = degraded_env_client.get("/healthz")
    assert r.status_code == 503, r.text
    payload = r.json()
    assert payload["status"] == "degraded"
    # The notes must be preserved verbatim — the front-end renders
    # them into the env banner.
    assert any("intercept" in n.lower() for n in payload["environment"]["notes"])


# ---------------------------------------------------------------- POST /api/check happy path

def test_post_api_check_happy_path_returns_check_id_and_cached_false(clean_env_client):
    """The submit endpoint returns a UUID-ish check_id and `cached: False`.
    This is what `web/static/app.js` reads to open the SSE stream —
    a rename or shape change here breaks the SPA silently."""
    c, _ = clean_env_client
    r = c.post("/api/check", json={"domain": "example.com"})
    assert r.status_code == 200, r.text
    payload = r.json()
    assert "check_id" in payload
    assert isinstance(payload["check_id"], str) and len(payload["check_id"]) >= 8
    assert payload["cached"] is False
    assert payload["domain"] == "example.com"


def test_post_api_check_cache_hit_returns_result_inline(clean_env_client):
    """Second submission of the same domain within TTL must skip the
    background worker entirely and return `cached: True` with the
    full `complete` event embedded as `result`. The SPA short-circuits
    to render immediately — a regression here would either re-run
    every check (wasting external DNS load) or return `cached: True`
    with no result (leaving the UI stuck)."""
    c, server = clean_env_client
    # First call kicks off the async worker; wait for completion by
    # calling /result which blocks until done.
    r1 = c.post("/api/check", json={"domain": "example.com"})
    check_id = r1.json()["check_id"]
    result = c.get(f"/api/check/{check_id}/result")
    assert result.status_code == 200
    assert result.json()["event"] == "complete"

    # Second POST must hit the cache.
    r2 = c.post("/api/check", json={"domain": "example.com"})
    assert r2.status_code == 200
    payload = r2.json()
    assert payload["cached"] is True, (
        f"second submit for cached domain must return cached=True; "
        f"got {payload!r}"
    )
    assert payload["result"] is not None, (
        "cached response must embed the complete event payload so the "
        "SPA can render without hitting /result"
    )
    assert payload["result"]["event"] == "complete"


# ---------------------------------------------------------------- POST /api/check validation

@pytest.mark.parametrize("bad_input,reason", [
    ("https://example.com/", "URL with scheme rejected at the boundary"),
    ("example.com/path", "path suffix rejected"),
    ("user@example.com", "email-shaped input rejected"),
    ("192.0.2.1", "IPv4 rejected — the tool checks names, not addresses"),
    ("localhost", "single-label input rejected"),
])
def test_post_api_check_rejects_bad_input(clean_env_client, bad_input, reason):
    """The API-edge validator (`_validate_domain`) mirrors
    `normalize_domain`'s rejection contract. If any of these leaked
    through to DNS, the tool would either produce a misleading finding
    or waste an external query on garbage."""
    c, _ = clean_env_client
    r = c.post("/api/check", json={"domain": bad_input})
    assert r.status_code == 400, (
        f"{reason} — expected 400, got {r.status_code}: {r.text}"
    )
    payload = r.json()
    assert "detail" in payload


def test_post_api_check_rejects_missing_domain_field(clean_env_client):
    """FastAPI/pydantic returns 422 for a body missing required fields.
    Pin that shape — the SPA relies on 4xx being an unambiguous
    'do not retry' signal."""
    c, _ = clean_env_client
    r = c.post("/api/check", json={})
    assert r.status_code == 422


def test_post_api_check_rejects_oversized_domain(clean_env_client):
    """`CheckRequest.domain` has `max_length=253`. Pydantic rejects
    the request before it reaches the validator. Prevents a client
    from staging a DoS via multi-KB payloads."""
    c, _ = clean_env_client
    r = c.post("/api/check", json={"domain": "a." * 200 + "com"})
    assert r.status_code == 422


# ---------------------------------------------------------------- GET /api/check/{id}/result

def test_get_result_unknown_check_id_returns_404(clean_env_client):
    """Unknown check_id must be 404, not 500 — the SPA's retry logic
    treats 4xx as terminal and 5xx as transient."""
    c, _ = clean_env_client
    r = c.get("/api/check/deadbeef00000000/result")
    assert r.status_code == 404
    assert "check_id not found" in r.json()["detail"]


def test_get_result_returns_complete_event_for_finished_job(clean_env_client):
    """The blocking /result endpoint must return the `complete` event
    that `run_streaming` yielded last. Same payload as the CLI's
    `run()` return — this is the byte-for-byte-identical contract
    that CLAUDE.md's module-map header calls out."""
    c, _ = clean_env_client
    r1 = c.post("/api/check", json={"domain": "vergecloud.com"})
    check_id = r1.json()["check_id"]

    r = c.get(f"/api/check/{check_id}/result")
    assert r.status_code == 200
    payload = r.json()
    assert payload["event"] == "complete"
    assert payload["report"]["domain"] == "vergecloud.com"
    assert payload["grades"]["overall"] == "A"


def test_get_result_error_shape_when_worker_failed(clean_env_client):
    """When the worker set `job.error` but never emitted `complete`,
    /result returns `{error, events}` at 200 — the SPA renders this
    as a soft failure with a retry button (rather than a hard error
    banner). Pin the shape so a refactor can't collapse it into 500."""
    c, server = clean_env_client
    # Build a done job with no `complete` event.
    job = server.Job(check_id="failed_job_xxxxxx", domain="broken.example",
                     dkim_selectors=[])
    job.events.append({"event": "started", "domain": "broken.example"})
    job.events.append({"event": "error", "type": "server",
                       "message": "RuntimeError: synthetic"})
    job.error = "RuntimeError: synthetic"
    job.done = True
    server.JOBS[job.check_id] = job

    r = c.get(f"/api/check/{job.check_id}/result")
    assert r.status_code == 200
    payload = r.json()
    assert "error" in payload
    assert "events" in payload
    assert payload["error"] == "RuntimeError: synthetic"


# ---------------------------------------------------------------- GET /api/check/{id}/stream

def test_get_stream_unknown_check_id_returns_404(clean_env_client):
    c, _ = clean_env_client
    r = c.get("/api/check/deadbeef00000000/stream")
    assert r.status_code == 404


def test_get_stream_happy_path_emits_all_events_and_end(clean_env_client):
    """A finished job's stream must replay every queued event and
    terminate with `event: end`. The SPA reads each `event:` line to
    route findings into their section, and treats `end` as the signal
    to stop listening. Missing `end` would leave the EventSource open
    forever."""
    c, server = clean_env_client
    # Pre-populate a done job (bypass the worker so we can control
    # exactly which events land on the stream).
    job = server.Job(check_id="stream_test_xxxxx", domain="example.com",
                     dkim_selectors=[])
    job.events.append({"event": "started", "domain": "example.com"})
    job.events.append({"event": "section", "name": "Registration & delegation",
                       "findings": []})
    job.events.append({"event": "complete",
                       "report": {"domain": "example.com"},
                       "grades": {"overall": "A"}})
    job._event_version = 3
    job.done = True
    job._wake.set()
    server.JOBS[job.check_id] = job

    with c.stream("GET", f"/api/check/{job.check_id}/stream") as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = "".join(resp.iter_text())

    # Every queued event must appear in the stream.
    assert "event: started" in body
    assert "event: section" in body
    assert "event: complete" in body
    # Terminator MUST be present — without it the browser EventSource
    # would keep the connection open past the last real frame.
    assert "event: end" in body

    # Payloads must be valid JSON (SSE `data:` lines).
    for line in body.splitlines():
        if line.startswith("data: ") and line[6:].strip() not in ("", "{}"):
            json.loads(line[6:])  # will raise if malformed


# ---------------------------------------------------------------- HTTP method contract

def test_post_api_check_rejects_get(clean_env_client):
    """The submit endpoint is POST-only — a GET would allow trivial
    CSRF from any browser context. Pin the 405."""
    c, _ = clean_env_client
    r = c.get("/api/check")
    assert r.status_code == 405


def test_result_endpoint_rejects_post(clean_env_client):
    """/result is GET-only. Pin the 405 so a refactor can't accidentally
    accept POST (which would open a shape-mismatch surface)."""
    c, _ = clean_env_client
    r = c.post("/api/check/anything/result", json={})
    assert r.status_code == 405
