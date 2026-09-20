# Architecture

One-page data-flow reference for the posture-checker tool. Every claim
here is verifiable from the code — this document is scaffolding, not
doctrine (doctrine lives in `CLAUDE.md`).

## 30-second overview

Two entry points, one shared check engine. Results must be
**byte-for-byte identical** between CLI and web — the web layer is
presentation and access control only. Every check makes live queries
against real third-party infrastructure.

```
┌─────────────────────┐         ┌──────────────────────────────────┐
│  CLI                │         │  Web                             │
│  posture-cli d.com  │         │  POST /api/check {domain}        │
│  (posture/cli.py)   │         │  (web/server.py)                 │
└─────────┬───────────┘         └────────────────┬─────────────────┘
          │                                      │
          │ checks.run(d)                        │ checks.run_streaming(d)
          │ returns Report                       │ yields events
          ▼                                      ▼
┌──────────────────────────────────────────────────────────────────┐
│  posture/checks.py — orchestrator                                │
│                                                                  │
│  0. selftest.check_environment()      ← CLAUDE.md rule 5 gate    │
│  1. _registration      (RDAP + EPP status + expiry + registrant) │
│  2. _nameservers       (parent delegation, per-NS probe, anycast)│
│  3. _soa               (SOA agreement across NSes)               │
│  4. _records           (A/AAAA/MX/CAA, authoritative vs cached)  │
│  5. _dnssec            (DS, DNSKEY, chain, AD-bit)               │
│  6. _email             (SPF, DKIM, DMARC, MTA-STS, TLS-RPT)      │
│  7. _security          (AXFR probe, open-resolver check)         │
│                                                                  │
│  Each section: Report.add(section, label, status, detail,        │
│                           why, hardening=)                       │
│                                                                  │
│  grade(report) → {correctness_grade, hardening_grade, overall,   │
│                   hardening_gaps: [...]}                         │
└──────────────────────────────────────────────────────────────────┘
          │                                      │
          │ Report                               │ SSE events:
          ▼                                      │  started
┌─────────────────────┐                          │  environment
│  cli.render         │                          │  section (×7)
│  → terminal / JSON  │                          │  complete
└─────────────────────┘                          ▼
                                     ┌──────────────────────────────┐
                                     │  web/static/app.js           │
                                     │  → DOM rendering             │
                                     └──────────────────────────────┘
```

## Wire-level primitives

The check engine composes a small set of primitives that each own one
protocol source of truth.

| Primitive                       | Layer        | Owner file        |
|---------------------------------|--------------|-------------------|
| `query(name, rdtype)`           | DNS wire     | `dnsmod.py`       |
| `parent_delegation(d)`          | Parent-zone NS | `dnsmod.py`     |
| `probe_each_ns(d, ns_map)`      | Per-NS UDP/TCP | `dnsmod.py`     |
| `dnssec_status(d)`              | DS + DNSKEY + AD | `dnsmod.py`   |
| `axfr_open_check(d, ns_map)`    | TCP/53 AXFR  | `dnsmod.py`       |
| `open_resolver_check(d, ns_map)`| UDP/53 recursion probe | `dnsmod.py` |
| `authoritative_vs_cached(...)`  | Authoritative + cached A/AAAA | `dnsmod.py` |
| `_txt_records(d)`               | TXT with rule-1 raise-or-return | `emailauth.py` |
| `evaluate_spf` / `_dkim` / `_dmarc` / `_mta_sts` | Semantic TXT layer | `emailauth.py` |
| `rdap_lookup(d)`                | DNS-RDAP     | `core.py`         |
| `ip_rdap(ip)`                   | IP-RDAP + Team Cymru ASN | `core.py` |
| `check_environment()`           | Self-test gate | `selftest.py`   |

## Key contracts

**Rule 1 (CLAUDE.md).** Three states — `not_applicable`, `unretrievable`,
`broken` — must never collapse. The mechanism: `emailauth._txt_records`
raises `TxtUnretrievable` for anything other than NXDOMAIN + NoAnswer,
so callers can propagate UNKNOWN. `dnsmod.query` returns
`{ok: False, error: ...}` for the raw-wire layer. `dnssec_status`
requires positive evidence on both DS and DNSKEY probes before emitting
`not_configured`. See `posture/emailauth.py::TxtUnretrievable`.

**Rule 5.** `check_environment()` runs before per-NS work. When it
reports the wire path is untrustworthy (`safe_for_per_ns_checks=False`),
findings that depend on direct authoritative reads degrade to UNKNOWN.
See `posture/selftest.py`.

**Byte-for-byte parity.** `run()` and `run_streaming()` walk the same
`section_steps` list. `tests/test_checks_run_orchestration.py::test_run_and_run_streaming_produce_identical_findings`
pins this contract — a refactor that adds a code path to only one
function trips a red test.

## Web-layer additions

`web/server.py` wraps `run_streaming` with:

- `POST /api/check` — creates a `Job`, queues to `_run_job` worker.
- `GET /api/check/{id}/stream` — SSE consumer (`SSE_MAX_STREAM_SECONDS = 120`).
- `GET /api/check/{id}/result` — snapshot of the terminal `complete` event.
- `GET /healthz` — 200 on clean env, 503 when `check_environment` flags degradation.
- `RESULT_CACHE` — LRU-bounded `OrderedDict` (`_RESULT_CACHE_MAX = 512`), 5-minute TTL.
- Per-IP rate limit (`slowapi`, keyed on true socket peer; XFF spoofing defeated by F3).
- Security-header middleware: strict CSP, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`.

## Where the tests are pinned

| Layer                    | Pinning test file(s)                             |
|--------------------------|--------------------------------------------------|
| Orchestrator             | `tests/test_checks_run_orchestration.py`         |
| DNSSEC state machine     | `tests/test_dnssec_state_machine.py`             |
| Grading                  | `tests/test_grade_*.py`, `tests/test_grading_*.py`|
| Web endpoints            | `tests/test_web_endpoints_integration.py`        |
| Self-test gate           | `tests/test_selftest_check_environment.py`       |
| RDAP walk (`.co.in`)     | `tests/test_rdap_endpoint_walk.py`               |
| Anycast classifier       | `tests/test_anycast_classifier.py`               |
| Anycast call-site        | `tests/test_operator_diversity_finding.py`       |

Full test-to-BUGS.md-item cross-reference: see the bottom of `BUGS.md`.

## Non-goals of this document

- Does not repeat `CLAUDE.md`'s Root Cause Principle or non-negotiable
  rules — those are doctrine, this is scaffolding.
- Does not enumerate every `Report.add` call — grep the section
  functions for the current set.
- Does not describe the grading algorithm in detail — that lives in
  `docs/grading.md`.
