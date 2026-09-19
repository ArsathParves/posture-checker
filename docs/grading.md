# Grade model

How `posture.checks.grade(report, strict=False)` turns a `Report` into
letter grades. This document is derived from the code — the code is
authoritative, this is scaffolding.

## What `grade()` returns

```python
{
    "sections":         {section_name: (band, pct), ...},
    "overall":          "A" | "B" | "C" | "D" | "F",
    "correctness_grade": "A" | ... | "F" | "—",
    "hardening_grade":   "A" | ... | "F" | "—",
    "hardening_gaps":    ["MTA-STS", "TLS-RPT", ...],
    "provisional":       bool,
    "ungraded_sections": [...],
    "unknown_in":        [...],
}
```

`"—"` is emitted only when a bucket has no scored findings (nothing to
grade). It is never a placeholder for "we skipped grading" — that's
`provisional=True` with a specific reason in `ungraded_sections` /
`unknown_in`.

## Why two axes

A domain that merely **lacks an optional hardening feature** (DNSSEC not
configured, no CAA, no MTA-STS) is not misconfigured. Most of the
public internet — including `google.com` — is in exactly that position.
Grading that identically to a genuine **misconfiguration** (broken
DNSSEC chain, delegation mismatch, open AXFR, expired domain) produced
a misleading D for `google.com`, which was the ground-truth trigger for
the correctness/hardening split.

- **Correctness grade** — genuine misconfigurations only.
- **Hardening grade** — optional-feature adoption ratio.
- **Overall grade** — correctness × 0.8 + hardening × 0.2 (round).

## Finding classification

Every `Finding` carries a `hardening: bool` attribute (default `False`),
set at the emit site via `Report.add(..., hardening=True)`. The emit
site is authoritative — the code that raised the finding is the code
that knows whether the check is an optional feature or a real
misconfiguration. Grade routing then follows a simple rule (see
`grade()::_is_hardening_absence`):

- Hardening finding, status ∈ {WARN, FAIL} → **hardening bucket only**.
- Hardening finding, status = PASS → **both buckets** (adopting an
  optional feature signals good posture across both dimensions).
- Non-hardening finding → **correctness bucket** (regardless of status).
- Status = UNKNOWN → neither bucket. Report goes `provisional=True`.

The state-conditional DNSSEC case (a bug pre-G2): DNSSEC classification
lives in `_dnssec` and depends on the observed zone state:

- `state ∈ {not_configured, unknown, validating} → hardening=True`
- `state ∈ {broken, incomplete} → hardening=False`

A broken chain is a real misconfiguration; an unsigned zone is a choice.

## Section grades

`SECTIONS` names 7 buckets:

1. Registration & delegation
2. Nameserver posture
3. SOA & zone hygiene
4. Core records
5. DNSSEC
6. Email authentication
7. Security posture

Each section grade is computed independently from its own scored
findings:

```
pct = sum(_score(f) for f in scored) / (2 * len(scored))
band = _band(pct, has_fail=any FAIL among scored)
```

## Point values (`SEVERITY_SCORE`)

| Status  | Score |
|---------|-------|
| PASS    | 2     |
| WARN    | 1     |
| FAIL    | 0     |
| INFO    | not scored |
| UNKNOWN | not scored |

`--strict` mode promotes WARN → FAIL for scoring purposes only; the
finding's `status` field stays "WARN" in the UI. Strict mode does not
reclassify findings between correctness and hardening.

## Band thresholds (`_band(pct, has_fail)`)

`has_fail` is the FAIL floor — even a partially-passing set with one
genuine FAIL is capped at D:

| Condition                       | Grade |
|---------------------------------|-------|
| `has_fail` and `pct < 0.5`      | F     |
| `has_fail` and `pct < 0.75`     | D     |
| `pct ≥ 0.95` (no FAIL floor)    | A     |
| `pct ≥ 0.8`                     | B     |
| `pct ≥ 0.6`                     | C     |
| `pct ≥ 0.4`                     | D     |
| otherwise                       | F     |

**Hardening bucket exception:** `_band` is called with
`has_fail=False` for the hardening percentage. A partial-adoption
domain (google.com — 6/7 optional features adopted) should stay at B,
not crash to D just because one hardening feature is absent. The
adoption ratio does the work; strict mode still bites via
`_score()` promoting WARN → FAIL point values.

## Overall grade

If `correctness_grade == "—"` (nothing to grade), overall falls back to
the pre-split worst-weighted computation across section bands:

```
overall_idx = round(worst * 0.6 + avg * 0.4)
```

Otherwise:

```
c_idx = order.index(correctness_grade)
h_idx = order.index(hardening_grade) if hardening_grade != "—" else c_idx
overall_idx = round(c_idx * 0.8 + h_idx * 0.2)
```

The 80/20 weighting favours correctness — a domain with correctness A
and hardening C ends up A overall (a specific requirement from
CLAUDE.md's ground-truth row for `google.com`).

## `hardening_gaps`

The un-adopted optional-hardening findings driving the hardening bucket.
Renderers use this list to caption the letter — "Hardening: C, no
MTA-STS, no TLS-RPT" is decodable; a bare "C" is opaque. Order is
finding-emit order (stable across runs). Empty on a fully-adopted
domain. PASS findings are excluded (adopted → not a gap). See L2 in
`AUDIT.md`.

## `provisional`

Set to `True` when any of the following holds:

- A section has findings but none are scored (`ungraded_sections`).
- Any finding status is UNKNOWN (`unknown_in`).
- The environment self-test flagged the run degraded (`rep.degraded`
  non-empty).

The CLI header prints `(provisional)` in yellow when this fires; the
web UI carries the same signal but currently ignores it — a follow-up
UX item.

## What breaks the model (and how tests guard it)

| Breakage                                              | Guarded by                                         |
|-------------------------------------------------------|----------------------------------------------------|
| Correctness/hardening keys renamed                    | `tests/test_grade_split_surfaced.py`               |
| DNSSEC not_configured routed into correctness         | `tests/test_grading_google_unsigned.py`            |
| DNSSEC broken routed into hardening (false hide)      | `tests/test_hardening_per_check_attribute.py::test_dnssec_broken_routes_to_correctness` |
| A section-exception silently lowers correctness       | `tests/test_checks_run_orchestration.py::test_section_exception_becomes_UNKNOWN_downstream_still_runs` |
| Strict mode reclassifies findings                     | `tests/test_grade_strict_mode.py`                  |
| google.com falls below A (ground truth from CLAUDE.md)| `tests/test_grading_google_unsigned.py::test_overall_is_A` |
| vergecloud.com falls below A (C4 ground truth)        | `tests/test_grading_ground_truth.py::test_vergecloud_overall_A` |
| Hardening bucket loses its `has_fail=False` exemption | `tests/test_grading_google_unsigned.py`            |

## Non-goals

- Does not describe every finding's classification — grep the emit
  sites for `hardening=True` if you want the current list.
- Does not enumerate section-specific weightings — there are none.
  Every scored finding in a section contributes equally to that
  section's percentage.
- Does not explain the raw grade primitives (`_band` / `_score`) beyond
  the tables above. The code is 30 lines and worth reading directly.
