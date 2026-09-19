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

- [ ] **B6. Fully-degraded run still shows a confident letter grade.**
  If every check returns UNKNOWN, no findings are scored, `_grade_set`
  returns `"—"`, and overall falls through to a stale worst/avg computation.
  A meaningless grade renders identically to a real one.
  **Acceptance:** zero scored findings produces "Not gradeable", never a letter.

- [ ] **B7. Cache poisoning across users (web).**
  `RESULT_CACHE` is keyed by domain only and shared across all visitors. A
  result computed while the environment was degraded is cached and served as
  fresh to the next user for 5 minutes.
  **Acceptance:** degraded/provisional results are never cached; cache key
  includes environment-health state.

- [ ] **B8. No per-check timeout ceiling — DoS vector (web).**
  8 concurrent slots, each check fans out to 30–50 queries with only
  per-query timeouts. Eight deliberately-slow domains hold every slot for
  the summed timeout and take the tool down. Must be fixed before public
  deployment.
  **Acceptance:** a global per-check deadline is enforced; a slow domain
  returns partial results rather than holding a slot indefinitely.

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

- [ ] **B12. SPF dedup via `seen` set undercounts.**
  The RFC counts DNS *lookups*, not distinct domains. Two different
  `include:`s referencing the same target are two lookups; `seen` collapses
  them. Combined with B10/B11 the count is unreliable in both directions —
  undermining the one hard pass/fail check in email auth.

- [ ] **B13. SPF recursion depth guards are inconsistent.**
  Entry guard is `depth > 10`, recursion guard is `depth < 5`. Count and
  displayed trace can disagree; the trace under-represents what was counted.

- [ ] **B14. DMARC `sp=` and alignment modes parsed but never evaluated.**
  `sp`, `adkim`, `aspf` are read into the dict then ignored; grading uses
  only `p=`. A domain with `p=reject; sp=none` (strict apex, wide-open
  subdomains — a real and common misconfiguration) grades identically to
  `p=reject; sp=reject`.

- [ ] **B15. CAA checked only at apex, no tree walk (RFC 8659).**
  CAs walk up the tree. A subdomain inheriting valid parent CAA is falsely
  reported "CAA: none WARN".

- [ ] **B16. CAA content never parsed.**
  No distinction between `issue`, `issuewild`, `iodef`. A domain with only an
  `iodef` reporting record grades PASS identically to one with a strict
  issuance policy. The `issue ";"` (no CA may issue) form is not recognised.

- [ ] **B17. `normalize_domain` accepts IP addresses.**
  `127.0.0.1` passes. The web layer rejects IPs but the core function does
  not — inconsistent validation between layers; the CLI will "check" an IP.

- [ ] **B18. No per-label length enforcement.**
  A 64-character label is accepted; DNS limits labels to 63 octets (RFC 1035).

- [ ] **B19. Single-character TLDs accepted.**
  `example.c` passes validation. No TLD shorter than 2 characters exists.

---

# P2 — Missing checks that matter more than some included ones

- [ ] **B20. Subdomain takeover / dangling records — entirely absent.**
  Arguably the highest-value DNS security check that exists:
  - CNAME pointing at a deprovisioned cloud resource
    (`*.s3.amazonaws.com`, `*.azurewebsites.net`, `*.github.io`, etc.)
  - NS delegation to a nameserver whose own domain is unregistered
    (= full zone takeover)
  **Severity when found: CRITICAL.**

- [ ] **B21. MX records listed but never validated.**
  No check that MX hostnames resolve (dangling MX = no mail delivery), that
  no MX points to a CNAME (**forbidden by RFC 2181 §10.3**), that MX targets
  are not IP literals (invalid per RFC 1035), or that the mail path has any
  redundancy.

- [ ] **B22. A/AAAA never sanity-checked against bogon/private space.**
  Records pointing into RFC1918, `127.0.0.0/8`, or unallocated space are a
  real misconfiguration leaking internal addressing. Never flagged.

- [ ] **B23. Glue-record validation missing.**
  For in-bailiwick nameservers (`ns1.example.com` serving `example.com`) the
  parent must supply glue A/AAAA. Missing or inconsistent glue is a genuine
  resolution-fragility bug.

- [ ] **B24. NSEC/NSEC3 zone-enumeration exposure not checked.**
  A DNSSEC zone using NSEC (not NSEC3) permits full zone walking. For BFSI
  customers this is a real disclosure risk.

- [ ] **B25. No CDS/CDNSKEY check (RFC 7344 / 8078).**
  These signal automated DNSSEC key rollover / DS bootstrapping capability —
  relevant to spotting zones at risk during manual rollovers.

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

- [ ] **B29. Records read from recursive resolvers, presented as the domain's
  records.** Everything except the per-NS SOA probe comes from public
  resolvers — the *cached* view, possibly geo-steered. v0.5 added an
  authoritative-vs-cached cross-check for A/AAAA only; MX, TXT, CAA, NS are
  never cross-checked. Primary reads should come from authoritative, with
  the resolver used as comparison.

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
| B6 | OPEN | Fully-degraded run still emits a letter grade. `provisional` is set, but no "Not gradeable" band. Follow-up. |
| B7 | PARTIAL (via AUDIT F4/P6) | `RESULT_CACHE` is now LRU-bounded (`tests/test_result_cache_lru.py`) but the *key* is still domain-only — an environment-degradation snapshot is not part of the key. Cross-user staleness under a flipping environment remains a residual risk. |
| B8 | PARTIAL (via AUDIT S7) | Per-connection SSE ceiling shipped (`tests/test_web_sse_timeout.py`, `SSE_MAX_STREAM_SECONDS = 120`). A global per-check deadline that bounds `run_streaming` itself is a separate follow-up. |

### P1 — RFC correctness

| ID | Status | Pinning tests / notes |
|---|---|---|
| B9 | DONE | Single-query path with TC-bit inspection + TCP retry lives in `dnsmod.query`. Pinned by `tests/test_query_cache.py` and `tests/test_query_cache_lru.py`; SPF-facing behaviour by `tests/test_txt_unretrievable_wider.py`. |
| B10 | DONE | `tests/test_spf_counting.py::test_redirect_ignored_when_all_present` pins RFC 7208 §6.1. |
| B11 | WITHDRAWN (AUDIT C5) | Audit premise misread §4.6.4. `mx` costs exactly 1. Pinned RFC-compliant by `tests/test_spf_counting.py::test_bare_mx_counts_as_one_per_rfc_7208_4_6_4` and `test_mx_with_target_counts_as_one_per_rfc_7208_4_6_4`. |
| B12 | OPEN | Per-lookup vs per-distinct-domain counting not addressed. `_seen` still dedupes. |
| B13 | OPEN | SPF recursion depth guards not reconciled. Trace vs count divergence not pinned. |
| B14 | OPEN | `sp` / `adkim` / `aspf` still parsed but not evaluated in grading. |
| B15 | DONE (via AUDIT FP5) | `tests/test_caa_parent_walkup.py` pins the parent-label walk per RFC 8659 §3. |
| B16 | OPEN | CAA `issue` / `issuewild` / `iodef` distinction not parsed. `issue ";"` (no-CA form) not recognised. |
| B17 | DONE | `tests/test_normalize_domain.py::TestIpRejection`, `tests/test_web_validation.py`, and `tests/test_validator_parity.py` (L3) pin IP rejection at both entry points. |
| B18 | DONE | `tests/test_normalize_domain.py::TestBoundaryLengths` — 63/64-char label and 253/254-octet total-name pins (E1). |
| B19 | DONE | Same file — TLD length rejection. |

### P2 — Missing checks

| ID | Status | Pinning tests / notes |
|---|---|---|
| B20 | OPEN | Subdomain takeover / dangling records — no check. This is the highest-value P2 gap; a dedicated `posture/takeover.py` module + CRITICAL tier (T2) is a natural pairing. |
| B21 | OPEN | MX validation (CNAME/IP-literal/dangling) — no check. |
| B22 | DONE | Apex A/AAAA bogon check added to `checks._records`. `_is_bogon_address` uses stdlib `ipaddress` classification (`is_private`, `is_loopback`, `is_link_local`, `is_multicast`, `is_reserved`, `is_unspecified`) plus an explicit RFC 6598 CGN (`100.64/10`) fallback for Python <3.13. Emits `A record bogon check` / `AAAA record bogon check` at FAIL when the finding is non-empty; skipped entirely when the record is absent (rule 1 preserved). Pinned by `tests/test_bogon_private_space.py` (10 cases: RFC 1918, loopback, doc-range, mixed public+private, IPv6 ULA / link-local / doc-range, plus non-regression cases for public IPv4/IPv6 and empty-records). |
| B23 | OPEN | Glue-record consistency — no check. |
| B24 | OPEN | NSEC vs NSEC3 zone-walking exposure — no check. |
| B25 | OPEN | CDS/CDNSKEY (RFC 7344/8078) — no check. |
| B26 | OPEN | Authoritative NS's own TCP/53 support — no check. |
| B27 | OPEN | EDNS compliance / DNS cookies (RFC 7873) — no check. |
| B28 | OPEN | Negative-answer correctness — no check. |
| B29 | PARTIAL (via AUDIT D5/FN5) | `authoritative_vs_cached` cross-checks A/AAAA. MX/TXT/CAA/NS cross-checks remain unimplemented. |
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
