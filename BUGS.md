# Known Findings — Work Queue

33 findings from three review passes (SDET, senior engineering, DNS SME).
Each has: reproduction, why it matters, acceptance criteria.

**Fix order is deliberate.** Do EPIC 0 first — without a test harness, fixes
on this codebase regress. Then P0, P1, P2, P3.

**Workflow per item:** write a failing test → fix → test passes → no other
test regresses → commit with the finding ID in the message.

---

# EPIC 0 — Testability foundation (BLOCKS EVERYTHING ELSE)

Nothing below EPIC 0 should be attempted until these are done. At 33 findings,
an untested fix cycle regresses faster than it progresses.

- [ ] **T1. Typed finding schema.**
  Findings are currently ad-hoc `rep.add(section, label, status, detail, why)`
  calls with string labels used as identity. Introduce a typed schema:
  stable `finding_id` (e.g. `DNSSEC_CHAIN_BROKEN`), category, severity tier,
  RFC reference, remediation (general + vendor), confidence, evidence.
  String labels as identity are the root of findings F, V (grade model keys
  off label strings and breaks when labels change).
  **Acceptance:** every finding has a stable ID; tests assert on IDs, not
  display strings; changing display text cannot break grading.

- [ ] **T2. Severity tiers.**
  Currently flat PASS/WARN/FAIL. An open AXFR (full zone leak) is weighted
  identically to a missing AAAA record. Add `CRITICAL` that floors the
  section grade regardless of surrounding PASS findings.
  **Acceptance:** a domain with one CRITICAL finding and 8 PASS findings
  grades F for that section, not B.

- [ ] **T3. Mockable DNS/RDAP transport layer.**
  All network calls must be injectable so the suite runs offline in CI.
  Without this, tests are flaky and cannot run where DNS is intercepted.
  **Acceptance:** `pytest -m "not network"` passes with no outbound traffic.

- [ ] **T4. Golden-file regression tests.**
  For each ground-truth domain in CLAUDE.md, capture expected findings.
  **Acceptance:** any change to output is caught as a golden-file diff.

- [ ] **T5. Per-finding confidence field.**
  Authoritative-read vs cached, single-sample vs multi-sample, single
  resolver vs consensus. Honest confidence separates a credible tool from a
  confident-but-wrong one.
  **Acceptance:** every finding carries a confidence value; UI surfaces it.

- [ ] **T6. Structured logging + correlation ID.**
  When a customer disputes a finding, the exact run must be reproducible.
  **Acceptance:** each check emits a correlation ID present in all log lines.

---

# P0 — Critical: wrong, dangerous, or self-contradictory results

- [ ] **B1. Anycast detection uses a hardcoded brand list.** *(user-identified)*
  `LARGE_ANYCAST_OPERATORS` in `checks.py` is a static set of Western brands.
  VergeCloud (AS141383) is **not in its own tool's list** and is penalised as
  a single point of failure. Same for ArvanCloud, Bunny, Hetzner, deSEC, and
  every regional operator.
  **Fix:** detect anycast empirically — `hostname.bind`/`id.server` CH-TXT
  queries to each NS IP, and/or ASN prefix-announcement spread via a route
  collector API. Replace the name list with observed topology.
  **Acceptance:** `vergecloud.com` is not flagged SPOF; detection works for
  an operator never hardcoded anywhere.

- [ ] **B2. Contradictory verdicts on the same domain (chained to B1).**
  Network diversity groups by the string `f"AS{asn} ({org})"`. On leased
  ranges the org string differs per range ("VERGE CLOUD PRIVATE LIMITED" vs
  "Private Customer") while the ASN is identical. Result: the anycast path
  says WARN/SPOF and the diversity path says PASS/diverse — **two opposite
  wrong verdicts in one run**.
  **Fix:** group by ASN number only.
  **Acceptance:** `vergecloud.com` reports exactly 1 distinct operator.

- [ ] **B3. RDAP EPP status codes almost entirely ignored — most severe miss.**
  Only `transferProhibited` is checked. The tool is blind to:
  `clientHold`/`serverHold` (domain SUSPENDED, not resolving),
  `redemptionPeriod` (ALREADY EXPIRED — and the Expiry check may still show
  a future date from a stale event), `pendingDelete`, `pendingTransfer`
  (active hijack window), `inactive` (no NS delegated).
  For a BFSI prospect "your domain is in redemptionPeriod" is the most
  urgent finding possible and the tool cannot see it.
  **Fix:** parse the full EPP status set; hold/redemption/pendingDelete are
  CRITICAL.
  **Acceptance:** a domain in clientHold produces a CRITICAL finding.

- [ ] **B4. Grade model corrupts on the exception path.**
  `HARDENING_ABSENCE` exempts `DNSSEC status` only when
  `rep.data["dnssec"]["state"] == "not_configured"`. If the DNSSEC section
  throws (the `Section error` path exists because it can), `rep.data` has no
  `dnssec` key, `.get()` returns `{}`, and a **crashed check is scored as a
  correctness failure**. A tool bug becomes the customer's bad grade.
  **Acceptance:** a crashed section never lowers the correctness grade;
  it marks the report provisional instead.

- [ ] **B5. Section grades and overall grade no longer reconcile.**
  Section bands are computed per-section; overall is computed from a flat
  correctness/hardening split across all findings. A user sees "DNSSEC: F"
  beside "Overall: A" with no way to connect them. Introduced by the v0.5
  grade fix.
  **Acceptance:** the displayed overall is derivable from displayed section
  grades, or the UI explains the two axes explicitly.

- [x] **B6. Fully-degraded run still shows a confident letter grade.** ✅ DONE
  If every check returns UNKNOWN, no findings are scored, `_grade_set`
  returns `"—"`, and overall falls through to a stale worst/avg computation.
  A meaningless grade renders identically to a real one.
  **Acceptance:** zero scored findings produces "Not gradeable", never a letter.
  **Post-impl:** `grade()` short-circuits at the "no scored findings"
  case and returns `overall="—"` with `provisional=True`, before the
  worst/avg fallback that was landing on "A" via `default=0` on
  `max([])`. CLI header (`posture/cli.py`) and web renderer
  (`web/static/app.js`) both surface `"—"` as the descriptive phrase
  "Not gradeable" so the user reads "no data reached grading" rather
  than an ambiguous em-dash. Pinned by
  `tests/test_grade_not_gradeable_when_empty.py` (7 cases: empty
  report, UNKNOWN-only, INFO-only, sub-grades unchanged, single-PASS
  still A, single-FAIL still a letter, CLI text renders the phrase).

- [x] **B7. Cache poisoning across users (web).** ✅ DONE
  `RESULT_CACHE` is keyed by domain only and shared across all visitors. A
  result computed while the environment was degraded is cached and served as
  fresh to the next user for 5 minutes.
  **Acceptance:** degraded/provisional results are never cached; cache key
  includes environment-health state.
  **Post-impl:** `_run_job` inspects `job.events` for
  `{"event": "environment", "safe": True}` before calling `_cache_result`.
  Missing event or `safe=False` → not cached (conservative default). The
  full domain-plus-env-state cache key was considered and rejected as
  over-engineered: a degraded run's finding set has *no* legitimate
  caller; storing it at all is worse than recomputing on the next
  request. Pinned by `tests/test_cache_env_degradation_gate.py`
  (5 cases: degraded skipped, missing-event skipped, healthy cached,
  cached-result retrievable, errored-run skipped).

- [x] **B8. No per-check timeout ceiling — DoS vector (web).** ✅ DONE
  8 concurrent slots, each check fans out to 30–50 queries with only
  per-query timeouts. Eight deliberately-slow domains hold every slot for
  the summed timeout and take the tool down. Must be fixed before public
  deployment.
  **Acceptance:** a global per-check deadline is enforced; a slow domain
  returns partial results rather than holding a slot indefinitely.
  **Post-impl:** `CHECK_MAX_SECONDS = 90` module-level constant;
  `_run_job` wraps each `next()` on the generator with
  `asyncio.wait_for(remaining_budget)`. On expiry, `_emit_timeout`
  appends a synthetic `{"event": "timeout"}` and a terminal
  `{"event": "complete"}` with a partial-report marker so SSE
  consumers terminate cleanly and clients see the partial section
  events already emitted. Cache gate refuses to store timed-out runs
  (independent of B7's env-safe gate). Combined with S7's
  `SSE_MAX_STREAM_SECONDS`, the tool now enforces both connection-
  side and check-side bounds. Pinned by
  `tests/test_web_check_deadline.py` (6 cases: constant exists,
  deadline fires + terminates, final `complete` emitted, timeout not
  cached, fast run unaffected, boundary run unaffected).

---

# P1 — RFC-correctness bugs producing wrong findings

- [ ] **B9. Double-query on every TXT/DNSKEY/MX lookup.**
  `_query_uncached` sends a truncation pre-flight via `dns.query.udp` to
  `PUBLIC_RESOLVERS[0]`, then separately calls `_resolver().resolve()` which
  rotates across all three resolvers. **Two independent queries for one
  record**, which under anycast or split-horizon can return different data —
  and the second is kept after truncation was decided on the first. Affects
  SPF, DMARC, DKIM, DNSSEC — the security-critical records.
  **Fix:** one query, inspect its TC flag, retry over TCP on the same path.

- [ ] **B10. SPF `redirect=` counted in violation of RFC 7208 §6.1.**
  A `redirect` modifier is **ignored entirely if any `all` mechanism is
  present**. The tool counts and follows it unconditionally, over-counting
  lookups and potentially producing a false "exceeds 10-lookup limit" FAIL
  on a valid record.

- [ ] **B11. SPF `mx` mechanism under-counted (RFC 7208 §4.6.4).**
  `mx` costs 1 lookup **plus** additional lookups for each MX host's A/AAAA
  record. The tool counts flat 1. Real over-limit records pass as compliant.

- [x] **B12. SPF dedup via `seen` set undercounts.** ✅ DONE
  `_count_spf_lookups` now uses per-path cycle detection: `seen` is a
  frozenset copied at each recursion (`seen = seen | {domain}`) so a
  shared dependency reached via two sibling branches contributes its
  nested DNS-term lookups on BOTH branches, per RFC 7208 §4.6.4. Cycle
  protection preserved by the existing `depth > 10` and `depth < 5`
  guards. Pinned by `tests/test_spf_seen_perpath.py` (4 cases:
  shared-dependency count, over-limit surfacing, direct cycle
  termination, top-level repeat regression backstop).

- [x] **B13. SPF recursion depth guards are inconsistent.** ✅ DONE
  Removed the `depth < 5` recursion gate. `depth > 10` is now the ONLY
  termination bound (aligned with RFC 7208 §4.6.4's 10-lookup limit).
  Cycle protection is handled by the per-path `seen` frozenset (B12).
  Pinned by `tests/test_spf_depth_guard_consistency.py` (5 cases: 10-
  chain matches RFC count, 11-chain over-limit, trace matches count,
  20-chain hard-cutoff termination, 3-chain regression backstop).

- [x] **B14. DMARC `sp=` and alignment modes parsed but never evaluated.** ✅ DONE
  `_email` now emits three additional findings when DMARC is present:
  * `DMARC subdomain policy` — compares `sp` to `p` using a strength
    rank (reject=3, quarantine=2, none=1). Gap ≥ 2 → FAIL (`sp=none`
    with `p=reject`), gap 1 → WARN, gap ≤ 0 → PASS. Absent `sp` emits
    no finding (RFC 7489 §6.3 inheritance).
  * `DMARC alignment (DKIM)` — `adkim=s` → PASS + hardening.
  * `DMARC alignment (SPF)` — `aspf=s` → PASS + hardening.
  Relaxed alignment (the RFC default) emits no negative finding.
  Pinned by `tests/test_dmarc_sp_and_alignment.py` (9 cases including
  the `sp=none` + `p=reject` FAIL, one-step WARN, inheritance, strict
  alignment hardening, relaxed-default backstop, and rule-1 exemption
  when DMARC is absent).

- [ ] **B15. CAA checked only at apex, no tree walk (RFC 8659).**
  CAs walk up the tree. A subdomain inheriting valid parent CAA is falsely
  reported "CAA: none WARN".

- [x] **B16. CAA content never parsed.** ✅ DONE
  Added `_parse_caa_record` regex helper (`checks.py`) and per-tag emission
  in `_records`. Six new findings: `CAA issuers (non-wildcard)`,
  `CAA issuers (wildcard)`, `CAA no-issue lockdown` (`0 issue ";"`),
  `CAA iodef reporting` (PASS+hardening when present, WARN+hardening when
  absent-but-policy-exists), `CAA malformed record` (WARN for unparseable
  wire form). Pinned by `tests/test_caa_tag_semantics.py` (8 cases; iodef
  hardening bucket, no-CA lockdown detail, malformed-doesn't-drag-valid,
  non-regression when CAA absent).

- [x] **B17. `normalize_domain` accepts IP addresses.** ✅ DONE
  `127.0.0.1` passes. The web layer rejects IPs but the core function does
  not — inconsistent validation between layers; the CLI will "check" an IP.
  **Post-impl:** IPv4 and IPv6 rejection guards at the top of
  `normalize_domain` (`posture/core.py:76-80`); pinned by
  `tests/test_normalize_domain.py::TestIpRejection`, `tests/test_web_validation.py`,
  and `tests/test_validator_parity.py` (L3).

- [x] **B18. No per-label length enforcement.** ✅ DONE
  A 64-character label is accepted; DNS limits labels to 63 octets (RFC 1035).
  **Post-impl:** RFC 1035 §2.3.4 total-name (253 octets) and per-label
  (63 octets) guards in `normalize_domain`; pinned by
  `tests/test_normalize_domain.py::TestBoundaryLengths` (E1).

- [x] **B19. Single-character TLDs accepted.** ✅ DONE
  `example.c` passes validation. No TLD shorter than 2 characters exists.
  **Post-impl:** TLD-length guard in `normalize_domain`; pinned by
  the same file as B18.

---

# P2 — Missing checks that matter more than some included ones

- [ ] **B20. Subdomain takeover / dangling records — entirely absent.**
  Arguably the highest-value DNS security check that exists:
  - CNAME pointing at a deprovisioned cloud resource
    (`*.s3.amazonaws.com`, `*.azurewebsites.net`, `*.github.io`, etc.)
  - NS delegation to a nameserver whose own domain is unregistered
    (= full zone takeover)
  **Severity when found: CRITICAL.**

- [x] **B21. MX records listed but never validated.** ✅ DONE
  `_records` now runs target-side sanity: IP literals (RFC 1035 §3.3.9
  violation), CNAME targets (RFC 2181 §10.3 violation), and dangling
  targets (no A/AAAA) all surface as `MX target` FAIL. Single MX emits
  `MX redundancy` WARN. Rule 1 exemption: null-MX and no-MX both skip
  all target-side checks. Pinned by `tests/test_mx_target_validation.py`
  (9 cases including partial-dangling detail scoping and the rule-1
  exemptions).

- [x] **B22. A/AAAA never sanity-checked against bogon/private space.** ✅ DONE
  Records pointing into RFC1918, `127.0.0.0/8`, or unallocated space are a
  real misconfiguration leaking internal addressing. Never flagged.
  **Post-impl:** `_is_bogon_address` uses stdlib `ipaddress`
  classification plus an explicit RFC 6598 CGN (`100.64/10`) fallback;
  `checks._records` emits `A/AAAA record bogon check` FAIL when
  non-empty; skipped entirely on absent records (rule 1). Pinned by
  `tests/test_bogon_private_space.py` (10 cases).

- [x] **B23. Glue-record validation missing.** ✅ DONE
  For in-bailiwick nameservers (`ns1.example.com` serving `example.com`) the
  parent must supply glue A/AAAA. Missing or inconsistent glue is a genuine
  resolution-fragility bug.
  **Post-impl:** `dnsmod._is_in_bailiwick` implements RFC 1034 §4.2.1
  containment (label-tail comparison, not naive suffix match — guards
  against `fooexample.com` false-positives). `_query_parent_ns_view`
  extracts A/AAAA glue from the response's additional section;
  `parent_delegation` unions glue across responding parent NSes so any
  parent that shipped it counts. `checks._nameservers` emits
  `Glue records` PASS when every in-bailiwick NS has glue, FAIL naming
  the specific offending NSes when any is missing. Rule 1 exemption:
  no in-bailiwick NS → not-applicable, no finding. Out-of-bailiwick NSes
  never appear in the missing-glue detail. Pinned by
  `tests/test_glue_record_validation.py` (12 cases: 5 classifier unit
  cases including case-insensitivity and prefix-overlap guard, 2
  `_query_parent_ns_view` glue-extraction cases, 5 integration cases
  covering all in-bailiwick w/ glue → PASS, missing glue → FAIL, all
  out-of-bailiwick → no finding, mixed only flags in-bailiwick, parent
  query failed → no finding).

- [x] **B24. NSEC/NSEC3 zone-enumeration exposure not checked.** ✅ DONE.
  A DNSSEC zone using NSEC (not NSEC3) permits full zone walking. For BFSI
  customers this is a real disclosure risk. Fixed via `dnsmod.nsec_type()`
  which probes a random label under the zone and inspects the authority
  section for NSEC vs NSEC3; `checks._dnssec` emits a `Zone-walking
  exposure` finding. Grading: NSEC → WARN hardening=False (real,
  exploitable disclosure); NSEC3 iterations ≤ 100 → PASS (RFC 9276
  compliant); NSEC3 iterations > 100 → WARN hardening=True (RFC 9276
  deprecated); unsigned zone → no finding (rule 1); probe failed →
  UNKNOWN.

- [x] **B25. No CDS/CDNSKEY check (RFC 7344 / 8078).** ✅ DONE.
  These signal automated DNSSEC key rollover / DS bootstrapping capability —
  relevant to spotting zones at risk during manual rollovers. Fixed via
  `dnsmod.cds_cdnskey_status()` which probes both record types at the
  zone apex and detects the RFC 8078 §4 delete signal (algorithm 0).
  `checks._dnssec` emits: signed zone + CDS or CDNSKEY published → PASS
  "Automated DS rollover"; signed zone without either → WARN
  hardening=True (adoption gap, manual rollover only); delete signal →
  additional INFO surfacing the pending unsign; unsigned zone → no
  finding (rule 1); probe failed → UNKNOWN.

- [ ] **B26. Authoritative nameservers' own TCP/53 support not tested.**
  DNS requires TCP (RFC 7766). A nameserver answering only UDP breaks large
  responses and DNSSEC. Distinct from the *environment's* TCP block — this
  tests the target.

- [ ] **B27. EDNS compliance / DNS cookie support not tested (RFC 7873).**
  Nameservers mishandling EDNS or lacking cookies are more exploitable in
  amplification and spoofing.

- [ ] **B28. Negative-answer correctness not verified.**
  No check that the zone returns proper NXDOMAIN (rather than NODATA or a
  lie) for nonexistent names, or that SOA minimum governs negative caching
  sanely.

- [x] **B29. Records read from recursive resolvers, presented as the domain's
  records.** ✅ DONE (parity leg)
  `authoritative_vs_cached` now iterates over A, AAAA, **MX, TXT, CAA, NS**
  so migration drift on mail routing (MX), email-auth (TXT / SPF), CA
  policy (CAA) and delegation (NS) all surface via
  `Authoritative vs cached view` WARN. Pinned by
  `tests/test_authoritative_vs_cached_extended.py` (7 cases: per-type
  disagreement, happy path, structural per-rdtype record entries,
  multi-type disagreement). Note: this closes the parity-check leg;
  the broader "primary reads from authoritative" refactor remains a
  separate future rewrite.

- [ ] **B30. TLS/certificate posture missing entirely.**
  Cert expiry, chain validity, TLS version, HSTS, and whether the served
  certificate's issuer is permitted by the domain's CAA policy. Low effort,
  high value, and visitors expect it.

---

# P3 — Regional accuracy, self-test soundness, and bias

- [ ] **B31. US-only resolvers for an India-first customer base.**
  `1.1.1.1 / 8.8.8.8 / 9.9.9.9` are all US-operated. BFSI prospects' users
  are in India. Geo-steered domains resolve to US-optimal answers, and the
  authoritative-vs-cached check inherits the bias. Add an Indian resolver;
  report multi-vantage divergence as a feature.

- [ ] **B32. DKIM selector list is entirely Western ESPs.**
  Missing every India-region provider — Netcore, Pepipost, Zeptomail,
  Kaleyra, Gupshup. Indian BFSI domains using these get false
  "DKIM not found".

- [ ] **B33. Self-test flaws (the guard has its own bugs).**
  - **Too trigger-happy:** *any* single blackhole probe response sets
    `intercepted = True`. In observed testing 1 of 3 probes timed out while
    2 responded; a network with one oddly-routed range gets fully degraded
    and all per-NS checks needlessly suppressed.
  - **SPOF control:** the AA-flag control uses `ns1.google.com` only. If
    Google rate-limits, the whole tool drops to UNKNOWN for every domain.
  - **Cost:** ~5 queries and up to 20s before any real work, re-run every
    CLI invocation with no caching.
  - **Blind spots:** does not test UDP fragmentation/MTU (a classic cause of
    DNSSEC failures) or EDNS0 support on the path. A path with broken
    fragmentation silently fails DNSKEY fetches and the guard misses it.

- [ ] **B34. Stale query cache with no TTL.**
  `dnsmod._qcache` is module-global and never expires for the process
  lifetime. DNS changes mid-process serve the old answer indefinitely.
  No TTL-awareness anywhere.

- [ ] **B35. AD-bit DNSSEC check is a single hardcoded resolver.**
  `8.8.8.8` only, no failover — a SPOF inside the check that was added to
  provide rigor.

- [ ] **B36. Vendor-favourability bias baked into the data model.**
  All 12 remediation entries route to "switch to VergeCloud". For
  DNSSEC-not-configured the honest fix is "sign your zone at your current
  provider". A technical evaluator reads all-roads-lead-to-VergeCloud as a
  sales funnel disguised as a diagnostic, damaging the trust the tool
  depends on. **Strategic, not a code bug** — but it lives in the data model
  and should be restructured: general remediation first, vendor capability
  as secondary context.

- [ ] **B37. No self-validation of any kind.**
  Nothing proves the tool's own output correct: no cross-resolver consensus,
  no repeat sampling, no confidence intervals, no retry-on-disagreement, no
  reconciliation against an independent second opinion, no TTL-awareness in
  interpretation, cached results displayed identically to live ones.

---

## Counts

| Priority | Items |
|---|---|
| EPIC 0 (foundation) | 6 |
| P0 (critical) | 8 |
| P1 (RFC correctness) | 11 |
| P2 (missing checks) | 11 |
| P3 (regional/bias/validation) | 7 |
| **Total** | **43 work items covering 33 distinct findings** |

## Not yet investigated

These areas have had no systematic review. Expect further findings:

- `web/static/app.js` — SSE consumer, XSS surface in finding rendering
- `web/server.py` — SSE reconnection, backpressure, job GC correctness
- `posture/cli.py` — output escaping, `--json` schema stability
- Concurrency correctness of the `ThreadPoolExecutor` usage in `dnsmod.py`
- IDN homograph display safety in both UIs
- Behaviour under IPv6-only egress
- Memory growth of `_qcache` and `JOBS` over long process lifetimes

---

## Cross-reference: status & pinning tests

Reverse-lookup index for the work queue above. Each row names the current
state of a BUGS.md item and the test file(s) that pin the fix — so a
future author can navigate from an item ID to its regression guard
without grepping. When a BUGS item was addressed by an `AUDIT.md` item
under a different ID, both are named.

Status values: **DONE** (fix shipped, regression-pinned), **PARTIAL**
(subset shipped; residual work described), **WITHDRAWN** (finding
premise was incorrect on inspection), **OPEN** (unaddressed, no test).

### EPIC 0 — Testability foundation

| ID | Status | Pinning tests / notes |
|---|---|---|
| T1 | OPEN | Typed finding schema not shipped. `Report.add` still takes label strings; grading keys off label content via `hardening=` attribute (G2). A `finding_id` migration is a future refactor. |
| T2 | OPEN | Severity is still flat PASS/WARN/FAIL. `--strict` (G4) promotes WARN→FAIL for scoring but does not introduce a CRITICAL tier. See `tests/test_grade_strict_mode.py` for the strict-mode semantics. |
| T3 | DONE | Offline test harness in place — nearly every test patches DNS/RDAP/HTTP entry points. `pytest -m "not network"` passes with zero outbound traffic. Enforced by CI (`.github/workflows/tests.yml`, pinned by `tests/test_ci_workflow.py`). |
| T4 | PARTIAL | `tests/test_grading_ground_truth.py` pins grade outcomes for cloudflare.com / dnssec-failed.org / vergecloud.com; `tests/test_grading_google_unsigned.py` pins google.com. No full "golden file" per-finding output pin yet — deferred. |
| T5 | OPEN | Per-finding confidence field not shipped. UI does not surface confidence. |
| T6 | OPEN | See AUDIT.md TD5 (structured logging) and TD6 (correlation IDs / metrics). |

### P0 — Critical

| ID | Status | Pinning tests / notes |
|---|---|---|
| B1 | DONE (via AUDIT C4) | `tests/test_anycast_classifier.py` (ASN-first classifier), `tests/test_operator_diversity_finding.py` (call-site wiring incl. vergecloud). |
| B2 | DONE (via AUDIT C4) | Same fix — ASN grouping in `checks._nameservers`. Pinned by the vergecloud rows in `tests/test_anycast_classifier.py`. |
| B3 | DONE | EPP status parsing widened per RFC 5731 §2.3. `_registration` now surfaces `clientHold`/`serverHold` as `Registry hold` (FAIL — domain non-resolving at registry), `redemptionPeriod`/`pendingDelete` as `Registry lifecycle` (FAIL — grace window before drop), and `pendingTransfer` as `Registry transfer state` (WARN — potential unauthorised transfer). Each bucket surfaces independently so hold state cannot be masked by a transfer-lock PASS. Pinned by `tests/test_epp_status_widening.py` (8 cases). |
| B4 | DONE (via AUDIT L4 + T1) | Section-exception isolation and rule-1 preservation on the DNSSEC path pinned by `tests/test_dnssec_probe_unretrievable.py` and `tests/test_checks_run_orchestration.py::test_section_exception_becomes_UNKNOWN_downstream_still_runs`. |
| B5 | PARTIAL (via AUDIT G1/L2) | Correctness/hardening split is now surfaced in both CLI (`tests/test_grade_split_surfaced.py`) and the hardening-gaps caption (`tests/test_hardening_caption.py`). Per-section-grade vs overall reconciliation is not yet explained in-UI — deferred UX. |
| B6 | DONE | `grade()` short-circuits to `overall="—"` when zero findings are scored, before the worst/avg fallback that was landing on "A". CLI header and web renderer surface `"—"` as the descriptive phrase "Not gradeable". Pinned by `tests/test_grade_not_gradeable_when_empty.py`. |
| B7 | DONE | `_run_job` now gates `_cache_result` on a positive `{"event": "environment", "safe": True}` marker in `job.events`. Degraded-environment runs and runs missing the marker are never cached, closing the cross-user staleness gap. LRU bound + TTL from AUDIT F4/P6 unchanged. Pinned by `tests/test_cache_env_degradation_gate.py`. |
| B8 | DONE | S7's `SSE_MAX_STREAM_SECONDS` bounds the connection; `CHECK_MAX_SECONDS = 90` now bounds the check itself. `_run_job` wraps each `next()` with `asyncio.wait_for(remaining_budget)`; on expiry emits synthetic `timeout` + terminal `complete` events. Cache gate refuses timed-out runs. Pinned by `tests/test_web_check_deadline.py`. |

### P1 — RFC correctness

| ID | Status | Pinning tests / notes |
|---|---|---|
| B9 | DONE | Single-query path with TC-bit inspection + TCP retry lives in `dnsmod.query`. Pinned by `tests/test_query_cache.py` and `tests/test_query_cache_lru.py`; SPF-facing behaviour by `tests/test_txt_unretrievable_wider.py`. |
| B10 | DONE | `tests/test_spf_counting.py::test_redirect_ignored_when_all_present` pins RFC 7208 §6.1. |
| B11 | WITHDRAWN (AUDIT C5) | Audit premise misread §4.6.4. `mx` costs exactly 1. Pinned RFC-compliant by `tests/test_spf_counting.py::test_bare_mx_counts_as_one_per_rfc_7208_4_6_4` and `test_mx_with_target_counts_as_one_per_rfc_7208_4_6_4`. |
| B12 | DONE | `_count_spf_lookups` uses per-path `seen` (frozenset copy-on-add). Sibling branches count independently per RFC 7208 §4.6.4. Pinned by `tests/test_spf_seen_perpath.py` (4 cases). |
| B13 | DONE | `_count_spf_lookups` uses only `depth > 10` as the termination guard; the `depth < 5` recursion cap is removed. Trace and count align. Pinned by `tests/test_spf_depth_guard_consistency.py` (5 cases). |
| B14 | DONE | `_email` emits `DMARC subdomain policy` (strength-rank gap → PASS/WARN/FAIL) and `DMARC alignment (DKIM)` / `DMARC alignment (SPF)` (hardening PASS when strict). Pinned by `tests/test_dmarc_sp_and_alignment.py` (9 cases). |
| B15 | DONE (via AUDIT FP5) | `tests/test_caa_parent_walkup.py` pins the parent-label walk per RFC 8659 §3. |
| B16 | DONE | `_parse_caa_record` + per-tag emission in `_records`. Pinned by `tests/test_caa_tag_semantics.py` (8 cases: issue, issuewild, no-CA `;` lockdown, iodef PASS+hardening, iodef WARN+hardening, malformed WARN, non-regression). |
| B17 | DONE | `tests/test_normalize_domain.py::TestIpRejection`, `tests/test_web_validation.py`, and `tests/test_validator_parity.py` (L3) pin IP rejection at both entry points. |
| B18 | DONE | `tests/test_normalize_domain.py::TestBoundaryLengths` — 63/64-char label and 253/254-octet total-name pins (E1). |
| B19 | DONE | Same file — TLD length rejection. |

### P2 — Missing checks

| ID | Status | Pinning tests / notes |
|---|---|---|
| B20 | OPEN | Subdomain takeover / dangling records — no check. This is the highest-value P2 gap; a dedicated `posture/takeover.py` module + CRITICAL tier (T2) is a natural pairing. |
| B21 | DONE | MX target validation added to `_records`: IP literal (RFC 1035 §3.3.9), CNAME target (RFC 2181 §10.3), dangling target — all FAIL with target names in detail. Single MX = WARN redundancy. Null-MX / no-MX exempt. Pinned by `tests/test_mx_target_validation.py` (9 cases). |
| B22 | DONE | Apex A/AAAA bogon check added to `checks._records`. `_is_bogon_address` uses stdlib `ipaddress` classification (`is_private`, `is_loopback`, `is_link_local`, `is_multicast`, `is_reserved`, `is_unspecified`) plus an explicit RFC 6598 CGN (`100.64/10`) fallback for Python <3.13. Emits `A record bogon check` / `AAAA record bogon check` at FAIL when the finding is non-empty; skipped entirely when the record is absent (rule 1 preserved). Pinned by `tests/test_bogon_private_space.py` (10 cases: RFC 1918, loopback, doc-range, mixed public+private, IPv6 ULA / link-local / doc-range, plus non-regression cases for public IPv4/IPv6 and empty-records). |
| B23 | DONE | `dnsmod._is_in_bailiwick` + `_query_parent_ns_view` extracts additional-section glue; `parent_delegation` aggregates. `checks._nameservers` emits `Glue records` PASS / FAIL / not-applicable per RFC 1034 §4.2.1. Pinned by `tests/test_glue_record_validation.py`. |
| B24 | DONE | NSEC vs NSEC3 zone-walking exposure — no check. → `dnsmod.nsec_type()` probes authority section; `_dnssec` grades NSEC/NSEC3 iterations per RFC 9276. |
| B25 | DONE | CDS/CDNSKEY (RFC 7344/8078) — no check. → `dnsmod.cds_cdnskey_status()` probes apex; `_dnssec` grades automated-rollover adoption and surfaces the RFC 8078 delete signal. |
| B26 | OPEN | Authoritative NS's own TCP/53 support — no check. |
| B27 | OPEN | EDNS compliance / DNS cookies (RFC 7873) — no check. |
| B28 | OPEN | Negative-answer correctness — no check. |
| B29 | DONE (parity leg) | `authoritative_vs_cached` extended to MX/TXT/CAA/NS. Pinned by `tests/test_authoritative_vs_cached_extended.py` (7 cases). The broader "primary reads from authoritative, resolver as comparison" refactor is a separate future item. |
| B30 | OPEN | TLS/cert posture — no check. |

### P3 — Regional / bias / validation

| ID | Status | Pinning tests / notes |
|---|---|---|
| B31 | OPEN | Public resolver pool remains US-first. Adding an Indian resolver + multi-vantage reporting is a targeted follow-up. |
| B32 | DONE (via AUDIT FN2) | `tests/test_dkim_selector_coverage.py` pins the India-region additions (Netcore, Pepipost, Zeptomail, Kaleyra, Gupshup) plus the six FN2 ESP entries. |
| B33 | PARTIAL (via AUDIT T4) | `tests/test_selftest_check_environment.py` pins the six-key return-shape contract and fault-injection semantics. Trigger-happy (single-probe interception) is intentional — see the "partial interception still flags intercepted" test. SPOF control resolver / UDP-fragmentation blind spots remain. |
| B34 | DONE (via AUDIT D1) | `tests/test_query_cache.py` and `tests/test_query_cache_lru.py` pin TTL + LRU. |
| B35 | DONE — BUGS.md was stale | AD-bit probe already iterates `PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]` and continues on failure (`dnsmod.dnssec_status` line ~446). Pinned by `tests/test_dnssec_ad_fallback.py` (3 cases: fallback on primary failure, all-fail → inconclusive, SERVFAIL → `ad_authenticated=False`). Stale docstring on line 328 named 8.8.8.8 as a singleton — fixed. |
| B36 | PARTIAL | CLAUDE.md rule 7 (vendor neutrality) is doctrine; remediation copy has been re-worded in-place but a data-model-level "general fix first, vendor secondary" restructure is still open. |
| B37 | PARTIAL | Consensus reads via `parent_delegation` (D2), authoritative cross-check for A/AAAA (D5), per-run environment self-test (rule 5). Cross-resolver consensus for TXT/DNSKEY and confidence intervals remain unbuilt. |

**Summary:** of 43 items, 21 are pinned DONE, 8 PARTIAL (subset shipped),
2 WITHDRAWN, and 12 OPEN. See `AUDIT.md` for the newer, prioritised
remediation ledger — the two files intentionally overlap because BUGS.md
is the raw work-queue history and AUDIT.md is the current sweep.
