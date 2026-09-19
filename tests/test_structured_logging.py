"""TD5 — Structured JSON logging with check_id correlation.

Prior to TD5 the web layer had no logging at all: uvicorn's default
access log was the only signal in production. On a public deployment
this is not enough to answer "what did this specific customer's check
do?" from log lines alone.

This test file pins the shape and content of the new structured log
records. Every assertion is against JSON parsed from `stderr` — the
contract is that records ARE JSON, not that they contain particular
substrings.
"""
from __future__ import annotations

import io
import json
import logging
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import web.server as server
from posture.logging import JsonFormatter, get_logger


# --------------------------------------------------------------------- formatter

def _emit_and_capture(logger: logging.Logger, *,
                      msg: str, extra: dict | None = None,
                      level: str = "info"):
    """Attach an isolated JSON handler, emit one record, return the
    parsed JSON line. Insulates the test from other handlers /
    formatters that may be attached to the same logger name."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    prior_level = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        getattr(logger, level)(msg, extra=extra or {})
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prior_level)
    line = buf.getvalue().strip()
    assert line, "no log record was emitted"
    return json.loads(line)


def test_json_formatter_emits_valid_json():
    """One log record → one parseable JSON object. The whole point
    of TD5 is that a log-aggregation layer can query these fields."""
    logger = logging.getLogger("posture.test.formatter_valid_json")
    record = _emit_and_capture(logger, msg="hello")
    assert record["msg"] == "hello"
    assert record["level"] == "INFO"
    assert record["logger"] == "posture.test.formatter_valid_json"
    assert "ts" in record


def test_extra_fields_are_top_level():
    """`logger.info(msg, extra={"check_id": "abc"})` must land
    `check_id` as a top-level JSON key — buried nesting defeats the
    log-aggregation queryability that motivates this change."""
    logger = logging.getLogger("posture.test.formatter_extra")
    record = _emit_and_capture(logger, msg="queued",
                               extra={"check_id": "abc123",
                                      "domain": "example.com"})
    assert record["check_id"] == "abc123"
    assert record["domain"] == "example.com"


def test_standard_log_fields_are_not_leaked():
    """LogRecord's own noise attributes (`pathname`, `lineno`,
    `funcName`, etc.) must not appear as top-level JSON keys — they
    would clutter log queries without adding signal."""
    logger = logging.getLogger("posture.test.formatter_no_leak")
    record = _emit_and_capture(logger, msg="hi")
    for noise in ("pathname", "lineno", "funcName", "created", "msecs"):
        assert noise not in record, (
            f"{noise!r} leaked into structured output"
        )


def test_ts_is_iso8601_utc():
    """Timestamp must be ISO 8601 with a timezone offset — a naive
    datetime here would silently render as the container's local
    time and misalign with everything else."""
    logger = logging.getLogger("posture.test.formatter_ts")
    record = _emit_and_capture(logger, msg="tick")
    # Presence of `T` and either `+00:00` or `Z` is sufficient.
    ts = record["ts"]
    assert "T" in ts
    assert ("+" in ts) or ts.endswith("Z"), f"ts is not TZ-aware: {ts!r}"


# --------------------------------------------------------------------- get_logger

def test_get_logger_is_idempotent():
    """Repeated calls with the same name must not stack handlers —
    otherwise every call in server startup would double-emit."""
    a = get_logger("posture.test.idempotent")
    before = len(a.handlers)
    b = get_logger("posture.test.idempotent")
    after = len(b.handlers)
    assert a is b
    assert after == before, (
        f"get_logger stacked handlers: {before} → {after}"
    )


def test_get_logger_does_not_propagate_to_root():
    """A tool that ends up under a systemd unit or a container
    platform frequently has a root logger also emitting to stderr;
    propagating our records would produce duplicates in that
    aggregator. `propagate=False` prevents this."""
    logger = get_logger("posture.test.no_propagate")
    assert logger.propagate is False


# --------------------------------------------------------------------- web integration

@pytest.fixture
def client_capturing_logs(monkeypatch):
    """TestClient with the web logger's stderr handler swapped for
    an in-memory buffer, `check_environment` patched to clean, and
    `run_streaming` patched to a benign synthetic sequence — so we
    can drive the check pipeline offline and assert on the JSON log
    lines it emits."""
    buf = io.StringIO()
    # Swap the module's `log` for one whose only handler writes to `buf`.
    isolated = logging.getLogger("posture.web.test_isolated")
    isolated.handlers.clear()
    isolated.setLevel(logging.INFO)
    isolated.propagate = False
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    isolated.addHandler(handler)
    monkeypatch.setattr(server, "log", isolated)

    monkeypatch.setattr(server, "check_environment", lambda: {
        "safe_for_per_ns_checks": True, "intercepted": False,
        "aa_flag_trustworthy": True, "udp53_direct": True,
        "tcp53_direct": True, "notes": [],
    })

    def fake_run_streaming(domain, dkim_selectors=None):
        yield {"event": "started", "domain": domain}
        yield {"event": "complete", "report": {"domain": domain, "findings": []},
               "grades": {"correctness_grade": "A", "hardening_grade": "A",
                          "overall": "A", "hardening_gaps": []}}

    monkeypatch.setattr(server, "run_streaming", fake_run_streaming)

    prior_jobs = server.JOBS.copy()
    prior_cache = server.RESULT_CACHE.copy()
    server.JOBS.clear()
    server.RESULT_CACHE.clear()
    # slowapi keeps rate-limit counters keyed by (peer, endpoint) in
    # a process-global MemoryStorage. TestClient's peer is always
    # `testclient`, so buckets are shared across every test in the
    # suite; the 5 POSTs this fixture issues can push a sibling test
    # over the 10/min limit and yield spurious 429s downstream. Reset
    # before and after — before because we may have inherited state.
    server.limiter.reset()
    try:
        with TestClient(server.app) as tc:
            yield tc, buf
    finally:
        server.JOBS.clear()
        server.JOBS.update(prior_jobs)
        server.RESULT_CACHE.clear()
        server.RESULT_CACHE.update(prior_cache)
        server.limiter.reset()


def _lines(buf: io.StringIO) -> list[dict]:
    """Parse every JSON line from the buffer."""
    return [json.loads(l) for l in buf.getvalue().splitlines() if l.strip()]


def test_post_check_emits_queued_log_with_check_id_and_domain(
        client_capturing_logs):
    """A POST /api/check that starts a fresh run must emit a
    `check queued` line carrying the check_id from the response
    body and the punycode domain — this is the correlation-ID
    anchor for every subsequent line."""
    tc, buf = client_capturing_logs
    resp = tc.post("/api/check", json={"domain": "example.com"})
    assert resp.status_code == 200
    check_id = resp.json()["check_id"]

    queued = [l for l in _lines(buf) if l["msg"] == "check queued"]
    assert queued, f"no `check queued` log emitted; saw {_lines(buf)!r}"
    line = queued[0]
    assert line["check_id"] == check_id
    assert line["domain"] == "example.com"
    assert line["level"] == "INFO"


def test_completed_log_carries_duration_and_event_count(
        client_capturing_logs):
    """The terminal `check completed` log must carry a duration and
    the number of events — this is the per-check performance signal
    that lets an ops team detect slow runs without instrumenting
    the CLI."""
    tc, buf = client_capturing_logs
    resp = tc.post("/api/check", json={"domain": "example.com"})
    check_id = resp.json()["check_id"]
    # Drain the SSE stream so the job runs to completion.
    with tc.stream("GET", f"/api/check/{check_id}/stream") as s:
        for _ in s.iter_lines():
            pass

    completed = [l for l in _lines(buf) if l["msg"] == "check completed"]
    assert completed, f"no `check completed` log; saw {_lines(buf)!r}"
    line = completed[0]
    assert line["check_id"] == check_id
    assert "duration_s" in line and isinstance(line["duration_s"], (int, float))
    assert line["events"] >= 1


def test_cache_hit_emits_served_from_cache_log(client_capturing_logs):
    """A repeat submit within TTL must emit a `check served from
    cache` line naming the reused check_id — otherwise you can't
    tell from the logs whether a run was actually executed or
    replayed."""
    tc, buf = client_capturing_logs
    r1 = tc.post("/api/check", json={"domain": "example.com"})
    first_id = r1.json()["check_id"]
    # Drain the SSE stream so the job completes and enters the cache.
    with tc.stream("GET", f"/api/check/{first_id}/stream") as s:
        for _ in s.iter_lines():
            pass
    r2 = tc.post("/api/check", json={"domain": "example.com"})
    assert r2.json()["cached"] is True

    cached = [l for l in _lines(buf) if l["msg"] == "check served from cache"]
    assert cached, f"no cache-hit log; saw {_lines(buf)!r}"
    assert cached[0]["check_id"] == first_id
    assert cached[0]["domain"] == "example.com"
