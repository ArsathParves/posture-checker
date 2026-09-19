"""Prometheus-compatible metrics primitives.

TD6 fix — the tool had no counters. `check completed` log lines
carry `duration_s` and could in principle be aggregated by a
log-processing pipeline, but that requires such a pipeline to
exist. A `/metrics` endpoint scraped by Prometheus (or any
compatible collector) gives an ops team a zero-config answer to
"checks/sec, failure rate, p95 latency" — the exact question TD6
called out as unanswerable at scale.

Deliberately hand-rolled instead of pulling in `prometheus_client`:

  1. The exposition format is small (well under 100 lines of
     rendering) and stable — the Prometheus project has kept it
     backwards-compatible since 2015.
  2. Adding a dependency doubles the pip footprint for something
     this repo can own end-to-end.
  3. `prometheus_client` has a module-level default registry that
     is a shared singleton across the process. This matters for
     tests — a shared singleton makes counter-delta assertions
     racy under xdist. Owning the registry keeps our snapshot /
     restore semantics obvious.

Thread-safety: `_lock` protects every mutation. Counters and
histograms are read via `.value()` / `.count()` / `.sum_value()` —
those methods take the lock too, so callers get a coherent read
even mid-increment.
"""
from __future__ import annotations

import threading
from typing import Iterable


class Registry:
    """Container of named metrics. One per process is enough — see
    the module-level `METRICS` singleton at the bottom of this file
    for the shared instance the web tier uses.

    A separate `Registry()` is useful in tests that want isolation
    from the global metric state."""

    def __init__(self) -> None:
        self._by_name: dict = {}
        self._lock = threading.RLock()

    def register(self, metric) -> None:
        with self._lock:
            if metric.name in self._by_name:
                raise ValueError(
                    f"metric {metric.name!r} already registered; "
                    f"duplicate names collide in the scraper's TSDB"
                )
            self._by_name[metric.name] = metric

    def metrics(self) -> Iterable:
        """Snapshot of registered metrics — safe to iterate while
        another thread mutates values (values are read atomically
        under each metric's own lock at render time)."""
        with self._lock:
            return list(self._by_name.values())


# Module-level singleton — the web tier reads through this.
METRICS = Registry()


class Counter:
    """Monotonic non-decreasing counter. Prometheus semantics —
    the scraper computes rates via `rate(counter[5m])`, which
    breaks if a counter can decrease."""

    TYPE = "counter"

    def __init__(self, name: str, help_text: str, *,
                 registry: Registry | None = None) -> None:
        self.name = name
        self.help = help_text
        self._value = 0
        self._lock = threading.Lock()
        (registry or METRICS).register(self)

    def inc(self, amount: int | float = 1) -> None:
        if amount < 0:
            raise ValueError(
                f"Counter.inc requires a non-negative amount; got {amount!r}"
            )
        with self._lock:
            self._value += amount

    def value(self) -> int | float:
        with self._lock:
            return self._value


class Histogram:
    """Fixed-bucket histogram. Observations accumulate in every
    bucket whose upper bound they fall <=; the `+Inf` bucket
    catches everything. Combined with `_sum` and `_count`, this is
    enough for `histogram_quantile()` in PromQL."""

    TYPE = "histogram"

    # Sensible defaults for a check-duration histogram: sub-second
    # to 1min. Callers can override via the `buckets` kwarg.
    DEFAULT_BUCKETS = (0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)

    def __init__(self, name: str, help_text: str, *,
                 buckets: tuple[float, ...] | None = None,
                 registry: Registry | None = None) -> None:
        self.name = name
        self.help = help_text
        # Bucket boundaries must be sorted ascending. Always append
        # +Inf — Prometheus rejects histograms without it.
        bs = tuple(sorted(buckets or self.DEFAULT_BUCKETS))
        self._buckets = bs + (float("inf"),)
        self._counts = {b: 0 for b in self._buckets}
        self._sum = 0.0
        self._count = 0
        self._lock = threading.Lock()
        (registry or METRICS).register(self)

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum += value
            self._count += 1
            for b in self._buckets:
                if value <= b:
                    self._counts[b] += 1

    def bucket_counts(self) -> dict:
        with self._lock:
            return dict(self._counts)

    def buckets(self) -> tuple[float, ...]:
        return self._buckets

    def count(self) -> int:
        with self._lock:
            return self._count

    def sum_value(self) -> float:
        with self._lock:
            return self._sum


# --------------------------------------------------------------------- rendering

def _format_bucket_bound(b: float) -> str:
    """Prometheus wants `+Inf` (not `inf` and not `+Infinity`).
    Numeric bounds render as a plain float — `0.5`, not `5e-01`."""
    if b == float("inf"):
        return "+Inf"
    if b == int(b):
        return f"{b:.1f}"  # 1.0, not 1
    return repr(b)


def render_prometheus_text(registry: Registry = METRICS) -> str:
    """Return the full `/metrics` body in Prometheus exposition
    format 0.0.4 (text). Format spec:
    https://prometheus.io/docs/instrumenting/exposition_formats/
    """
    parts: list[str] = []
    for m in registry.metrics():
        parts.append(f"# HELP {m.name} {m.help}")
        parts.append(f"# TYPE {m.name} {m.TYPE}")
        if isinstance(m, Counter):
            parts.append(f"{m.name} {m.value()}")
        elif isinstance(m, Histogram):
            counts = m.bucket_counts()
            for b in m.buckets():
                parts.append(
                    f'{m.name}_bucket{{le="{_format_bucket_bound(b)}"}} '
                    f'{counts[b]}'
                )
            parts.append(f"{m.name}_sum {m.sum_value()}")
            parts.append(f"{m.name}_count {m.count()}")
    parts.append("")  # trailing newline required by the spec
    return "\n".join(parts)


# --------------------------------------------------------------------- app metrics

# Instantiated on import so the metric objects exist before the web
# tier attaches to them. Ordered by lifecycle: started → served-from-
# cache / completed / failed, plus the rate-limit rejection counter
# and the duration histogram.

CHECKS_STARTED = Counter(
    "posture_checks_started_total",
    "Total number of check runs started (excludes cache hits).",
)

CHECKS_COMPLETED = Counter(
    "posture_checks_completed_total",
    "Total number of check runs that reached the 'complete' event.",
)

CHECKS_FAILED = Counter(
    "posture_checks_failed_total",
    "Total number of check runs that terminated with an unhandled "
    "exception (excludes client-side cancellations).",
)

CHECKS_CACHE_HITS = Counter(
    "posture_checks_cache_hits_total",
    "Total number of POST /api/check requests served from the "
    "in-memory result cache (LRU).",
)

RATE_LIMIT_REJECTED = Counter(
    "posture_rate_limit_rejected_total",
    "Total number of requests rejected by the per-peer rate limiter "
    "(HTTP 429 responses from /api/check).",
)

CHECK_DURATION = Histogram(
    "posture_check_duration_seconds",
    "Wall time from queue to completion for check runs that reached "
    "the 'complete' event, in seconds.",
)
