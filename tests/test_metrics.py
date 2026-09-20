"""TD6 — thread-safe metrics primitives + Prometheus text rendering.

Unit-level tests for `posture/metrics.py`. The web-endpoint tests live
in `test_web_metrics_endpoint.py` — this file only covers the
counter / histogram primitives and the text-format output that a
Prometheus scraper will consume.

Prior to TD6 the tool had no counters at all. `check completed`
lines carry `duration_s` and could in principle be aggregated by a
log-processing layer, but that requires a log-aggregation layer to
exist. A `/metrics` endpoint gives an ops team a zero-config answer
to "checks/sec, failure rate, p95 latency" that works with any
Prometheus-compatible scraper (Prometheus, VictoriaMetrics, Grafana
Agent, OTel Collector).
"""
from __future__ import annotations

import re
import threading

import pytest

from posture.metrics import (
    Counter,
    Histogram,
    Registry,
    render_prometheus_text,
)


# --------------------------------------------------------------------- Counter

def test_counter_starts_at_zero():
    c = Counter("test_counter_zero", "help")
    assert c.value() == 0


def test_counter_inc_increments_by_one_by_default():
    c = Counter("test_counter_inc", "help")
    c.inc()
    c.inc()
    c.inc()
    assert c.value() == 3


def test_counter_inc_accepts_arbitrary_positive_amount():
    """Rate-limit rejections may be batched (multiple 429s from one
    scrape burst); support inc(n)."""
    c = Counter("test_counter_amount", "help")
    c.inc(5)
    c.inc(2)
    assert c.value() == 7


def test_counter_refuses_negative_inc():
    """Counters are monotonic non-decreasing per Prometheus semantics.
    A negative inc would produce a nonsensical rate() in PromQL — fail
    fast at the call site rather than silently emit garbage."""
    c = Counter("test_counter_neg", "help")
    with pytest.raises(ValueError):
        c.inc(-1)


def test_counter_is_thread_safe():
    """Two threads racing 10_000 increments each must produce exactly
    20_000 — otherwise a lost-update on the shared int would silently
    undercount every metric under real concurrent traffic."""
    c = Counter("test_counter_race", "help")

    def worker():
        for _ in range(10_000):
            c.inc()

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert c.value() == 20_000


# --------------------------------------------------------------------- Histogram

def test_histogram_records_observations_in_buckets():
    """Fixed default bucket boundaries so a Prometheus query can
    compute quantiles. An observation must fall into every bucket it
    is <= — that's how `histogram_quantile()` works."""
    h = Histogram("test_hist_buckets", "help",
                  buckets=(0.1, 0.5, 1.0, 5.0))
    h.observe(0.05)   # falls in every bucket
    h.observe(0.7)    # falls in 1.0, 5.0, +Inf
    h.observe(10.0)   # falls in +Inf only

    counts = h.bucket_counts()
    assert counts[0.1] == 1
    assert counts[0.5] == 1
    assert counts[1.0] == 2
    assert counts[5.0] == 2
    # +Inf accumulates every observation regardless of value.
    assert counts[float("inf")] == 3


def test_histogram_tracks_sum_and_count():
    """`_sum` + `_count` are what `rate(_sum) / rate(_count)` uses to
    compute a mean without needing every bucket."""
    h = Histogram("test_hist_sum", "help", buckets=(1.0,))
    h.observe(0.5)
    h.observe(2.0)
    h.observe(3.0)
    assert h.count() == 3
    assert h.sum_value() == pytest.approx(5.5)


def test_histogram_is_thread_safe():
    """As with the counter — under concurrent traffic, lost updates
    on the sum or count would silently drop observations."""
    h = Histogram("test_hist_race", "help", buckets=(1.0,))

    def worker():
        for _ in range(5_000):
            h.observe(0.5)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert h.count() == 10_000


# --------------------------------------------------------------------- Registry + text format

def test_registry_renders_counter_in_prometheus_text_format():
    """A Prometheus scraper expects `# HELP`, `# TYPE`, then the
    metric line. Missing HELP/TYPE breaks metadata in Grafana; missing
    the value line breaks scraping entirely."""
    reg = Registry()
    c = Counter("posture_checks_started_total",
                "Total number of check runs started.", registry=reg)
    c.inc(3)

    text = render_prometheus_text(reg)
    assert "# HELP posture_checks_started_total Total number of check runs started." in text
    assert "# TYPE posture_checks_started_total counter" in text
    assert re.search(r"^posture_checks_started_total 3(\.0)?$", text, re.MULTILINE), (
        f"missing metric value line; got:\n{text}"
    )


def test_registry_renders_histogram_with_bucket_labels_and_sum_count():
    """Prometheus histogram exposition format: one _bucket line per
    boundary with `le="<value>"` label, plus _sum and _count. The
    `+Inf` bucket is required — Prometheus rejects histograms without
    it."""
    reg = Registry()
    h = Histogram("posture_check_duration_seconds",
                  "Wall time per completed check, in seconds.",
                  buckets=(0.5, 1.0, 5.0), registry=reg)
    h.observe(0.3)
    h.observe(2.0)

    text = render_prometheus_text(reg)
    assert '# TYPE posture_check_duration_seconds histogram' in text
    # bucket lines
    assert 'posture_check_duration_seconds_bucket{le="0.5"} 1' in text
    assert 'posture_check_duration_seconds_bucket{le="1.0"} 1' in text
    assert 'posture_check_duration_seconds_bucket{le="5.0"} 2' in text
    assert 'posture_check_duration_seconds_bucket{le="+Inf"} 2' in text
    # sum + count
    assert re.search(r"^posture_check_duration_seconds_sum 2\.3\d*$", text,
                     re.MULTILINE)
    assert re.search(r"^posture_check_duration_seconds_count 2$", text,
                     re.MULTILINE)


def test_registry_rejects_duplicate_metric_names():
    """Two metrics with the same name would collide in the scraper's
    time-series database. Fail at registration time so a copy/paste
    error surfaces in tests, not in production dashboards."""
    reg = Registry()
    Counter("posture_dup", "help", registry=reg)
    with pytest.raises(ValueError, match="already registered"):
        Counter("posture_dup", "help", registry=reg)
