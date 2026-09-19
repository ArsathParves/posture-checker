"""TD6 — /metrics endpoint on the web tier.

Prometheus-format metrics served by FastAPI. Content-type is
`text/plain; version=0.0.4` per the Prometheus exposition spec —
a scraper won't parse `application/json` and won't parse
`text/plain` without at least `version=` in some setups.

The endpoint MUST be unauthenticated so a standard Prometheus
scrape config works — auth belongs at the network layer
(firewall / reverse-proxy allow-list). Metrics are aggregate
counters only; no per-domain labels, so scraping this endpoint
leaks nothing about who has been checked.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

import pytest

import web.server as server


@pytest.fixture
def client(monkeypatch):
    """TestClient with `check_environment` and `run_streaming`
    patched to a benign synthetic path — matches the pattern used
    by test_structured_logging.py so /metrics tests can drive
    end-to-end without live DNS."""
    monkeypatch.setattr(server, "check_environment", lambda: {
        "safe_for_per_ns_checks": True, "intercepted": False,
        "aa_flag_trustworthy": True, "udp53_direct": True,
        "tcp53_direct": True, "notes": [],
    })

    def fake_run_streaming(domain, dkim_selectors=None):
        yield {"event": "started", "domain": domain}
        yield {"event": "complete",
               "report": {"domain": domain, "findings": []},
               "grades": {"correctness_grade": "A", "hardening_grade": "A",
                          "overall": "A", "hardening_gaps": []}}

    monkeypatch.setattr(server, "run_streaming", fake_run_streaming)

    prior_jobs = server.JOBS.copy()
    prior_cache = server.RESULT_CACHE.copy()
    server.JOBS.clear()
    server.RESULT_CACHE.clear()
    server.limiter.reset()
    # Snapshot metric counter values so we can assert *deltas* rather
    # than absolute values (other tests in the same process may have
    # incremented them).
    from posture.metrics import METRICS
    snapshot = {
        name: (m.value() if hasattr(m, "value") else (m.count(), m.sum_value()))
        for name, m in METRICS._by_name.items()
    }
    try:
        with TestClient(server.app) as tc:
            yield tc, snapshot
    finally:
        server.JOBS.clear()
        server.JOBS.update(prior_jobs)
        server.RESULT_CACHE.clear()
        server.RESULT_CACHE.update(prior_cache)
        server.limiter.reset()


def test_metrics_endpoint_returns_prometheus_content_type(client):
    tc, _ = client
    resp = tc.get("/metrics")
    assert resp.status_code == 200
    ctype = resp.headers.get("content-type", "")
    assert ctype.startswith("text/plain"), (
        f"Prometheus scrapers require text/plain content-type; got {ctype!r}"
    )
    assert "version=0.0.4" in ctype, (
        f"content-type must declare Prometheus exposition version; got {ctype!r}"
    )


def test_metrics_endpoint_exposes_expected_metric_names(client):
    """A production ops team needs at minimum: total checks, cache
    hits, failures, rate-limit rejections, and a duration
    histogram. Missing any of these means the /metrics endpoint is
    decorative but not actionable."""
    tc, _ = client
    resp = tc.get("/metrics")
    body = resp.text
    expected = [
        "posture_checks_started_total",
        "posture_checks_completed_total",
        "posture_checks_failed_total",
        "posture_checks_cache_hits_total",
        "posture_rate_limit_rejected_total",
        "posture_check_duration_seconds",
    ]
    missing = [m for m in expected if m not in body]
    assert not missing, (
        f"/metrics missing required metric names: {missing}\n"
        f"body was:\n{body}"
    )


def test_started_counter_increments_on_new_check(client):
    """A fresh POST /api/check for a novel domain must bump the
    started counter by exactly 1 — proves the endpoint isn't
    static text but wired to real state."""
    tc, snapshot = client
    prior = snapshot.get("posture_checks_started_total", 0)
    resp = tc.post("/api/check", json={"domain": "example.com"})
    assert resp.status_code == 200

    from posture.metrics import METRICS
    after = METRICS._by_name["posture_checks_started_total"].value()
    assert after == prior + 1, (
        f"expected started counter to bump by 1; prior={prior}, after={after}"
    )


def test_cache_hit_counter_increments_on_repeat_submit(client):
    """Second POST for the same domain within TTL is a cache hit —
    must bump the cache_hits counter, not the started counter."""
    tc, snapshot = client
    from posture.metrics import METRICS
    prior_hits = snapshot.get("posture_checks_cache_hits_total", 0)
    prior_started = snapshot.get("posture_checks_started_total", 0)

    r1 = tc.post("/api/check", json={"domain": "example.com"})
    check_id = r1.json()["check_id"]
    with tc.stream("GET", f"/api/check/{check_id}/stream") as s:
        for _ in s.iter_lines():
            pass

    r2 = tc.post("/api/check", json={"domain": "example.com"})
    assert r2.json()["cached"] is True

    after_hits = METRICS._by_name["posture_checks_cache_hits_total"].value()
    after_started = METRICS._by_name["posture_checks_started_total"].value()
    assert after_hits == prior_hits + 1, (
        f"cache-hit counter should bump by 1; prior={prior_hits}, "
        f"after={after_hits}"
    )
    # First POST is a real run (started+1). Second is a cache hit
    # (must NOT bump started).
    assert after_started == prior_started + 1


def test_duration_histogram_records_completed_check(client):
    """A completed run must land an observation in the duration
    histogram — the value it lands is minute (fake_run_streaming
    yields two events synchronously) but the *count* must bump."""
    tc, snapshot = client
    from posture.metrics import METRICS
    prior_count = (snapshot.get("posture_check_duration_seconds",
                                (0, 0.0))[0])

    r1 = tc.post("/api/check", json={"domain": "example.com"})
    check_id = r1.json()["check_id"]
    with tc.stream("GET", f"/api/check/{check_id}/stream") as s:
        for _ in s.iter_lines():
            pass

    after_count = METRICS._by_name["posture_check_duration_seconds"].count()
    assert after_count == prior_count + 1
