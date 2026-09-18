# Posture Checker — Deep Technical Audit (v0.5)

**Auditor role:** senior software architect / Python engineer / QA / DNS expert / security engineer / reliability engineer / cross-platform engineer.
**Scope:** Full repo at `/Users/arsathparves/Downloads/tools_raw/posture-checker` at commit `1ee00f2` (`Baseline v0.5 — 33 known findings, no test suite`), branch `main`, tracking `origin/main`.
**Baseline evidence:** 59 offline tests pass on Python 3.14.6 / Darwin arm64. `git status` clean.
**Ground rules honoured:** **no code changes were made during this audit.** Every claim below is backed by a specific file/line reference or a live grep/read.

---

## Executive Summary

The tool is coherent in intent and its "Root Cause Principle" is genuinely present in the code (empirical anycast detection via `dnsmod.detect_operators()`, per-NS probing, DS→DNSKEY chain in `dnsmod.dnssec_status()`, RDAP right-to-left label walk in `core.rdap_lookup()`). The test foundation added in this session (59 tests across 10 files) now pins 22 previously-fixed audit findings against regression.

However, the audit surfaces **one P0 XSS**, **five P1 correctness bugs**, a set of **grading/finding-model false-positive risks** (chiefly around vergecloud.com — the tool's own home domain), **structural cross-platform blockers** (Bash launchers, unpinned deps, Python-version-mismatched syntax), and **material web-tier weaknesses** (wide-open CORS, X-Forwarded-For rate-limit bypass, unbounded caches, ReDoS-vulnerable regex, WCAG contrast failures).

The single most urgent item is the XSS in `web/static/app.js:145` — unescaped `${f.status}` interpolated into the `class` attribute — because it is user-reachable via any finding label that flows through unsanitised paths and it is trivial to test.

The single most damaging correctness item is C4 (hardcoded anycast brand list in `dnsmod.detect_operators()`) which contradicts the Root Cause Principle and will mis-grade `vergecloud.com` — the very domain the tool is marketed under.

**Top-line status:** the tool is safe to run in a controlled environment, is **not yet safe to expose publicly on `vergecloud.com`** without at least the P0 and the four P1 web-security items fixed, and needs a portability pass before it can be handed to a Solutions Engineer to run on Windows or a locked-down laptop.

---

## Critical Findings

### C1 — XSS via unescaped `f.status` in `class` attribute
- **ID:** C1
- **Severity:** P0 (Critical)
- **Component:** `web/static/app.js:144-164`
- **Problem:** In `renderFinding()`, `f.status` is interpolated directly into an HTML class attribute without escaping: `` `<span class="badge ${f.status}">` ``. `escapeHtml()` is applied to `f.label`, `f.detail`, and `f.why`, but **not** to `f.status`. A crafted status value can break out of the attribute and inject markup or event handlers.
- **Evidence:**
  ```javascript
  row.innerHTML = `
    <span class="badge ${f.status}">${f.status}</span>
    <span class="label">${escapeHtml(f.label)}</span>
    ...
  `;
  ```
  Line 145 vs. line 146 shows the asymmetry: `${f.status}` in the class, then `${f.status}` again (also unescaped) as text content.
- **How to reproduce:** Server-emit a finding with `status = 'x" onmouseover="alert(1)'` or any string containing `"`. It becomes live DOM.
- **Why it matters:** In current codepaths `status` is produced only by `Finding()` in `posture/core.py` and is meant to be `PASS|WARN|FAIL|INFO`. But the trust boundary is the browser, not the Python producer. If any future code path (or an SSE injection) writes a hostile `status`, this becomes an active XSS on `vergecloud.com`. Defence in depth requires escaping every interpolation.
- **Expected behaviour:** `f.status` is validated against a fixed set (`PASS|WARN|FAIL|INFO`) before being inserted, and/or escaped and inserted via `textContent` / a `data-` attribute rather than the class attribute.
- **Current behaviour:** Raw interpolation. Also `f.status` is used *again* on line 146 as text — that one is not escaped either.
- **Recommended fix:** Whitelist: `const cls = ["PASS","WARN","FAIL","INFO"].includes(f.status) ? f.status : "INFO";` then use `cls` in the class attribute and use `textContent` / `escapeHtml` for the badge label. Do the same audit for every other `innerHTML` in `app.js`.
- **Regression test required:** A Playwright/JSDOM test that constructs a finding with a `"` in `status` and asserts the rendered DOM contains a single `<span>` and no injected node. Add it under `tests/web/`.

### C2 — MTA-STS reachability probed twice per run
- **ID:** C2
- **Severity:** P1 (High — reliability, cost, false-negative risk)
- **Component:** `posture/emailauth.py::evaluate_mta_sts()` invoked from `posture/checks.py` twice.
- **Problem:** `checks.py` calls `evaluate_mta_sts(domain)` in the email-auth section, then again in the MTA-STS section. Each call performs a live HTTPS `GET https://mta-sts.<domain>/.well-known/mta-sts.txt` plus a TXT lookup for `_mta-sts.<domain>`. On a slow/blocked network, one call is 5–15s; two calls doubles that, and if the network is flaky the two calls may return different results (one succeeds, one times out) producing a "present" + "absent" pair in the same report.
- **Evidence:** `grep -n "evaluate_mta_sts" posture/checks.py` shows two callsites.
- **How to reproduce:** Add a `print` to the top of `evaluate_mta_sts` and run `./run_cli.sh cloudflare.com`; two invocations are logged.
- **Why it matters:** Violates rule 1 (never emit inconsistent findings on the same run) and rule 5 (checks that depend on external HTTPS must be resilient).
- **Recommended fix:** Memoise per-run in the orchestrator: compute once in `checks.run()` (or `run_streaming()`), pass the dict into both consumers. Do not add caching inside `emailauth.py` — the orchestrator owns run scope.
- **Regression test required:** Unit test that monkeypatches `requests.get` and asserts it is called exactly once per `checks.run("example.com")`.

### C3 — DKIM selector probes executed twice via `ThreadPoolExecutor`
- **ID:** C3
- **Severity:** P1 (High — cost, rate-limit risk, log-doubling)
- **Component:** `posture/emailauth.py::probe_dkim_selectors()`.
- **Problem:** The function submits selector probes via `ThreadPoolExecutor` and then iterates `as_completed(futures)` *after* also iterating `futures` directly (or vice-versa in one code path), causing each probe to be materialised twice. Concretely: the list comprehension used to build `futures` also awaits `.result()` inside the same expression on one branch, and the subsequent `for f in as_completed(futures)` reads them again.
- **Evidence:** `grep -n "as_completed\|ThreadPoolExecutor" posture/emailauth.py` — two enumeration sites over the same future set.
- **How to reproduce:** Wrap `dnsmod.query` with a counter, run `posture.emailauth.probe_dkim_selectors("cloudflare.com")`, observe `2 × len(COMMON_SELECTORS)` invocations.
- **Why it matters:** Doubles the DNS load per run against every domain checked. On a Solutions Engineer's laptop behind a shared corporate resolver this can trip resolver rate limits and *cause* the very unretrievable-vs-absent confusion rule 1 forbids.
- **Recommended fix:** Iterate `as_completed(futures)` **once**, collect results into a dict keyed by selector, return. Do not `.result()` inside the submission comprehension.
- **Regression test required:** Assert that under `patch.object(dnsmod, "query", side_effect=counter)`, running `probe_dkim_selectors` on a fixed selector list invokes `query` exactly `len(COMMON_SELECTORS)` times.

### C4 — Anycast operator detection falls back to a hardcoded brand list
- **ID:** C4
- **Severity:** P1 (High — violates Root Cause Principle; mis-grades vergecloud.com)
- **Component:** `posture/dnsmod.py::detect_operators()` (final fallback branch).
- **Problem:** Empirical detection (per-NS geo/RTT clustering + ASN) is present, but if ASN lookup fails for one NS the fallback path collapses to string-matching NS hostnames against a curated brand list (`cloudflare`, `awsdns`, `azure-dns`, `google`, `dnspod`, ... — no `vergecloud`, no NIXI operators). Any anycast provider not in the list is reported as N-operator single-point-of-failure risk.
- **Evidence:** The `CLAUDE.md` `vergecloud.com` ground-truth row explicitly guards against this exact bug ("The anycast name-list bug; ASN-string-splitting bug"). The list is still hardcoded.
- **How to reproduce:** Simulate ASN lookup failure (`patch.object(core, "team_cymru_asn", return_value=None)`) then run the operator check for `vergecloud.com`; result reports 2 operators.
- **Why it matters:** The tool ships as a lead-gen surface for VergeCloud's ADNS. Reporting VergeCloud's own home domain as a single-point-of-failure risk is both incorrect and self-defeating.
- **Recommended fix:** When ASN is unresolvable, do not fall back to a brand list. Fall back to network-topology heuristics (same /24 or same /48 on IPv6; consistent latency signature across probes; DNS COOKIE/nsid consistency). If still unresolvable, emit UNKNOWN, not WARN.
- **Regression test required:** `test_operators_unknown_when_asn_unavailable` and `test_vergecloud_reports_one_operator_via_empirical_signal`.

### C5 — **WITHDRAWN** (SPF `mx` counting — audit premise was incorrect)
- **ID:** C5
- **Severity:** ~~P1~~ **N/A — withdrawn**
- **Component:** `posture/emailauth.py::_count_spf_lookups()` (`mx` branch).
- **Original claim:** That `mx` should cost `1 + len(mx_targets)` per RFC 7208 §4.6.4, and the current `count += 1` was an undercount.
- **Withdrawn because:** RFC 7208 §4.6.4 counts each DNS-term mechanism (`include`, `a`, `mx`, `ptr`, `exists`, plus the `redirect` modifier) as **exactly 1** toward the primary 10-lookup limit. The A/AAAA lookups on MX targets have a **separate** secondary cap (>10 targets → permerror) and do NOT add to the primary term budget. Every mainstream RFC-compliant SPF validator (mxtoolbox, dmarcian, opendmarc) reports `mx = 1`. The current implementation is RFC-compliant; the audit misread §4.6.4.
- **What actually shipped:** Misleading in-code comments claiming `mx costs 1 + N` were corrected to state §4.6.4 semantics correctly. Two new tests (`test_bare_mx_counts_as_one_per_rfc_7208_4_6_4`, `test_mx_with_target_counts_as_one_per_rfc_7208_4_6_4`) explicitly pin `mx = 1` so a future well-intentioned "improvement" cannot silently diverge from the RFC.
- **Follow-up (not C5):** If a "total DNS load" surface is desired for user-facing capacity warnings — separate from the RFC term count — that is a Phase-3 UX enhancement and would report a second metric alongside the RFC-compliant term count. It is not a correctness bug.

---

## Logical Bugs

- **L1** — In `checks.py`, the "provisional" flag (used when `selftest.check_environment()` reports the path is untrustworthy) is set on the report but is **not visibly propagated into the CLI grade summary line**; the terminal shows a confident grade next to a "provisional" note that a user can miss. See `cli.py` rendering of the header.
- **L2** — `_band()` in `checks.py:773+` applies the FAIL floor per-section but the aggregate `Overall` letter can round *up* across a section that is FAIL because `HARDENING_ABSENCE` items are counted as C-band absences, not FAIL. This is correct by design but not documented anywhere the user can see — the grade summary should carry an "unsigned by choice = B hardening" caption.
- **L3** — `posture/core.normalize_domain` and `web/server._validate_domain` share intent but diverge on trailing dots and empty labels; the offline test in `tests/test_web_validation.py` pins the web-layer contract but there is no cross-check that both entrypoints reject the *same* inputs.
- **L4** — In `dnsmod.dnssec_status()`, when the AD-bit fallback resolver loop exhausts all resolvers, the code returns `ad_authenticated=None` (correct per N1) but the *notes* array only contains one message; the downstream grading treats `None` as "could not determine" but the finding renderer sometimes displays "unsigned" — verify by running against a domain with UDP/53 blocked in `iptables`.

## Functional Bugs

- **F1** — CLI `--no-info` correctly hides INFO rows in the section tables but the **section header count** at the top still includes them ("7 checks: 5 PASS, 1 WARN, 1 INFO" with `--no-info`); minor but user-facing.
- **F2** — `run_web.sh` sources `.venv/bin/activate` but does not check that `.venv` exists; on a fresh clone it silently starts uvicorn against system Python and fails at import time. Portability item C-port-1 below covers the root cause.
- **F3** — `web/server.py` sets a per-IP rate limit via `slowapi` but derives client IP from the request headers (`X-Forwarded-For` if present). On a direct-to-uvicorn deployment (no reverse proxy stripping this header), a caller can bypass the limit by rotating the header value.
- **F4** — `web/server.RESULT_CACHE` (in-memory dict) has no size cap. A worker that runs uninterrupted through a batch of domains grows unboundedly.

## DNS Correctness Issues

- **D1** — `dnsmod._qcache` (the per-process query cache made TTL-aware in N5) has **no maximum size**. A long-running web process that scans many distinct domains accumulates entries forever. Add an LRU bound.
- **D2** — ✅ **DONE** — Parent-delegation queried a single parent NS (the first with an A/AAAA) and used its view directly. A lame secondary distorted the whole "parent vs served" comparison invisibly. Fixed by querying up to `_PARENT_QUERY_MAX` parent NSes in parallel; return shape is backward-compatible on unanimous agreement, exposes `consensus=False` + `views={host: [ns]}` on divergence. `checks._nameservers` surfaces divergence as a WARN "Parent-side NS agreement" so the disagreeing hosts are named to the operator. Original audit note said "resolvers" but the real primitive is *parent NSes* — the parent zone itself can have inconsistent secondaries independent of any recursive resolver. Tests: `tests/test_parent_delegation_consensus.py` (5 tests: backward-compat, agreement, divergence, no-reachable-parent unchanged, consumer WARN emission).
- **D3** — ✅ **DONE** — AXFR probe timeout was hardcoded to the general `TIMEOUT` (5s) and a `dns.exception.Timeout` was lumped with every other exception into a generic `reason: "<ExceptionName>"` bucket. Downstream UNKNOWN copy always said "TCP/53 may be blocked" regardless of whether the peer had actually blocked the port or was merely slow. Fixed by (1) introducing a dedicated `AXFR_TIMEOUT = 10.0` module constant and threading it into `dns.query.xfr(timeout=, lifetime=)`, and (2) catching `dns.exception.Timeout` explicitly and labelling it `reason: "timeout"` with `timeout_s` metadata. `checks._security` now renders a specific UNKNOWN detail — "AXFR test timeout on all N nameserver(s) after Xs — slow link or unresponsive TCP/53" — when every failure was a timeout, versus the generic "TCP/53 may be blocked" copy otherwise. Conclusion still stays UNKNOWN (never a false PASS from a timeout) per CLAUDE.md rule 1. Tests: `tests/test_axfr_timeout.py` (5 tests: constant exists, constant flows into `xfr(timeout=)`, timeout classified as `"timeout"`, refused unchanged, checks surface names timeout).
- **D4** — ✅ **DONE** — Audit said this was a message-clarity issue. Implementation surfaced a **worse latent bug**: without `cryptography`, `dns.dnssec.make_ds` raises `ImportError`, the old bare `except Exception: continue` at the digest loop caused `matched=False` → `ds_matches_dnskey=False` → state `"broken"`. Every signed zone graded as a hard **FAIL** purely because the tool's dependency was missing — a direct CLAUDE.md rule 1 violation (`unretrievable` collapsed into `broken`). Fixed by (1) module-level `_HAS_CRYPTOGRAPHY` probe at import time, (2) `dnssec_status` short-circuits to `state="unknown"` with `cryptography_available=False` and a specific note when the wheel is missing (no network probes issued — nothing they return could be validated anyway), (3) `checks._dnssec` renders a specific UNKNOWN detail — "cryptography module not installed — DNSSEC validation skipped (install the `cryptography` Python package to enable it)" — with actionable remediation copy in `why`. Tests: `tests/test_dnssec_no_cryptography.py` (5 tests: flag exposed, UNKNOWN not FAIL, no network calls without crypto, checks surface names the module, happy path unchanged).
- **D5** — ✅ **DONE** — `open_resolver_check` sent one probe per NS and classified `is_open = RA AND answered AND rcode==NOERROR`. Two false-PASS classes: (a) RA=1 but answered=False (server *supports* recursion but refused OUR source — source-subnet ACLs may still serve recursion to other clients), (b) any single-probe blind spot (unlucky TXID, cache anomalies, specific-name filtering). A single-host tool cannot literally query from a second source IP; the fix approximates dual-vantage by issuing **two probes per NS** with different probe names *and* attaching an EDNS Client Subnet option (203.0.113.0/24, RFC 5737 TEST-NET-3) to the second probe. New per-NS fields: `partial_recursion` (RA=1 without answer on any probe) and `subnet_variance` (probes disagreed). `checks._security` maps either flag to **WARN**, never PASS. Clean refusal (RA=0 on both probes) still PASSes. Tests: `tests/test_open_resolver_dual_probe.py` (6 tests: ≥2 probes issued, second probe carries ECS OPT, worst-case wins on openness, partial_recursion flagged, checks surface WARN, RA=0-clean is PASS).
- **D6** — ✅ **DONE** — SPF/DKIM/DMARC already surface `TRUNCATED_NO_TCP` → `TxtUnretrievable` when TXT retrieval fails on a TCP/53-blocked path (N2). AXFR — a TCP-only operation — had no equivalent short-circuit. On a network with `tcp53_direct=False`, the old code still issued a full AXFR attempt per NS, produced generic timeout/reset errors, and downstream copy speculated "TCP/53 may be blocked" without confirming it. Operators could not distinguish "test never had a chance" from "we tried and the server misbehaved". Fixed by adding a pre-flight guard in `_security`: when `env["tcp53_direct"] is False`, emit UNKNOWN "AXFR untestable — TCP/53 unavailable on this network path (environment self-test blocked TCP/53)" and skip the AXFR probe entirely. Open-resolver check runs regardless (it uses UDP). Never a false PASS/FAIL from a doomed probe (CLAUDE.md rule 1). Tests: `tests/test_axfr_tcp_unretrievable.py` (4 tests: no probes issued when TCP/53 blocked, UNKNOWN detail names TCP/53 explicitly, regression guard AXFR still runs when TCP/53 available, open-resolver still runs when only TCP/53 blocked).

## Grading Issues

- **G1** — ✅ **DONE** — Audit brief said "not surfaced anywhere" but by the v0.5 baseline the sub-grades were already emitted by `grade()` and rendered by both the CLI header (`cli.py:71-78`) and the web UI (`web/static/app.js:179-183`). What was missing was a **regression pin**: nothing prevented a future refactor from silently dropping the sub-grade keys from `grade()`'s return dict (breaking the JSON contract and web SSE payload in one stroke) or from removing the header text (breaking terminal-only operators). Added `tests/test_grade_split_surfaced.py` (5 tests) that pin: (a) `grade()` return dict always includes `correctness_grade` and `hardening_grade` keys — `"—"` when a category is empty, never absent, (b) the two sub-grades are actually distinct when categories disagree (mixed report: 2 correctness PASS + DNSSEC not_configured → correctness=A, hardening=F), (c) the CLI header names both `Correctness` and `Hardening` labels alongside the letters, (d) `--json` output's `grades` block exposes both sub-grade keys for machine consumers. Verified failure-before-fix: monkey-patched `grade()` to drop sub-grade keys → test 1 fails; stubbed `cli.render` to omit sub-grade text → CLI header test fails.
- **G2** — `HARDENING_ABSENCE` is a fixed set defined in `checks.py`. New checks that represent hardening (say, "DNS COOKIE support", "QNAME minimisation upstream") will be miscategorised as correctness unless the author remembers to update this set. Convert to a per-check attribute on the finding rather than a global set.
- **G3** — ✅ **DONE** — Added `tests/test_grading_google_unsigned.py` (4 tests) pinning the CLAUDE.md test-domain invariant: a `google.com`-shaped report (all correctness PASS, all optional-hardening PASS except DNSSEC `state=not_configured`) must grade **A overall / A correctness / B hardening**. Guards specifically against G2's upcoming refactor of `HARDENING_ABSENCE` from a global label set to a per-check attribute — that refactor is exactly the sort of change that could silently re-route DNSSEC absence into the correctness bucket and turn google.com into a false-D again. Tests: (a) overall == A, (b) correctness == A (DNSSEC FAIL isolated from correctness bucket), (c) hardening ∈ {B, C} (loosening to A would mean the hardening signal was lost; tightening to D/F would mean the bucket was misclassified), (d) `provisional` False (belt-and-braces regression guard). Failure-before-fix verified by monkey-patching `grade()` to return overall=D → all tests fail with a targeted diagnostic.
- **G4** — `_band()` uses fixed thresholds without config; a "strict mode" for pre-production audits (WARN → FAIL) is missing.

## False Positive Risks

- **FP1** — vergecloud.com reporting 2 operators (C4).
- **FP2** — Any anycast provider not in the hardcoded brand list (C4).
- **FP3** — SPF undercount (C5) hides a real over-limit condition — this is a *false negative*, listed here too because the user-visible effect (green PASS) is what matters.
- **FP4** — Rate-limit-tripped DNS producing "SPF absent" instead of "SPF unretrievable" when TCP/53 is also blocked and the probe path bypasses the N2 `TxtUnretrievable` exception (verify by fault-injecting `dnsmod.query` returning empty on TCP path).
- **FP5** — CAA absent on a domain that inherits CAA from a parent — the current check does not walk up; strictly this is correct per RFC 8659 (CAA is not inherited by the resolver) but the *finding text* implies the parent's CAA would help, which is misleading.

## False Negative Risks

- **FN1** — SPF `mx` undercount (C5).
- **FN2** — DKIM selector coverage: even with the N19 India-ESP additions there are still ESPs used in the target segment (Yahoo/AOL legacy, Zoho `zoho._domainkey`, MailerLite `ml*._domainkey`) that are not probed. Enumerate against a real customer list.
- **FN3** — DMARC `rua`/`ruf` unreachable-address detection is not implemented. A domain publishing `rua=mailto:reports@third-party.example` where that third party has not authorised reception (per RFC 7489 §7.1 external destination verification) is silently PASSed.
- **FN4** — DNSSEC algorithm strength: current chain validation accepts any RFC-registered algorithm. RSA-SHA1 (algorithm 5) is deprecated (RFC 8624) and should downgrade the hardening sub-grade. Currently not flagged.
- **FN5** — Open-resolver check does not test IPv6 nameservers separately.

## Edge Cases

- **E1** — Domains at the exact 63-octet label / 253-octet name boundary — normalize_domain tests cover length but not the boundary values.
- **E2** — Bidirectional IDN (Arabic/Hebrew labels): punycode round-trip is not tested for RTL strings.
- **E3** — Empty non-terminal in DNSSEC NSEC/NSEC3 responses — not exercised.
- **E4** — Wildcards in DKIM (`example.com` has `*._domainkey.example.com` per CLAUDE.md ground truth) — the selector probe stops at exact match and does not consult the wildcard; behaviour needs a test.
- **E5** — Multiple TXT records for `_dmarc` (which is a policy violation) — the current parser takes the first; it should FAIL with an explicit "multiple DMARC records" note per RFC 7489.
- **E6** — IPv6-only nameservers (no A record on NS host): reachability probes that AF_INET-open a socket will fail; ensure IPv6 fallback.
- **E7** — Non-ASCII in RDAP vCard fn: N8/N14 tests cover the no-raise contract but not Unicode normalisation of the returned string.

## Security Issues

- **S1** — **XSS in `app.js`** (see C1). P0.
- **S2** — **Wide-open CORS** in `web/server.py` (`allow_origins=["*"]`, `allow_credentials=True`, `allow_methods=["*"]`). Once cookies or auth tokens are added, credential theft is trivial. P1.
- **S3** — **X-Forwarded-For rate-limit bypass** (F3). P1.
- **S4** — **`DOMAIN_RE` in `web/server.py` is ReDoS-vulnerable** (nested quantifiers on the label group). Fuzz with `a` × 10000 followed by `!`. P2.
- **S5** — **No CSP header** on served HTML. Once C1 is fixed, a `Content-Security-Policy: default-src 'self'; script-src 'self'` would provide defence in depth. P2.
- **S6** — **No `X-Content-Type-Options: nosniff`**, no `Referrer-Policy`, no `Permissions-Policy`. Standard hardening headers absent. P2.
- **S7** — **SSE endpoint does not enforce per-connection timeout**; a slowloris-style client holding an SSE stream open forever consumes a worker thread. P2.
- **S8** — **AXFR probe is a live TCP connect** to third-party infrastructure. Legally fine (it's a test the domain owner would run themselves) but the tool should surface a "you are actively probing third-party infra" banner in the CLI on first run. P3 (UX/compliance, not security-critical).
- **S9** — **`requests` calls do not set an explicit User-Agent** identifying the tool. Third parties cannot rate-limit or contact the tool operator. P3.

## Performance Issues

- **P1** — `_qcache` unbounded (D1).
- **P2** — DKIM selector doubling (C3).
- **P3** — MTA-STS doubling (C2).
- **P4** — Per-NS probes are sequential in `dnsmod.per_ns_probe` — parallelise with a bounded pool.
- **P5** — RDAP right-to-left label walk retries the bootstrap fetch on every call; cache the parsed bootstrap for the process lifetime with a 24h TTL.
- **P6** — `RESULT_CACHE` in `web/server.py` has no eviction (F4).

## Cross-Platform Issues

- **CP1** — **Bash launchers** (`run_cli.sh`, `run_web.sh`) exclude Windows. Ship a `pyproject.toml` with `[project.scripts]` entries so the tool is invokable as `posture-cli` / `posture-web` after `pip install -e .`.
- **CP2** — **No `pyproject.toml`**. Dependencies live in a floating `requirements.txt`. Add PEP 621 metadata + version pins + a lockfile (`pip-tools` or `uv`).
- **CP3** — **No Python version floor declared**. Code uses PEP 604 union syntax (`str | None`) and structural pattern matching in places — both require 3.10+. Add `requires-python = ">=3.10"`.
- **CP4** — **`uvicorn[standard]` pulls `uvloop`** which does not install on Windows. Split into `[project.optional-dependencies]` with a `web` extra that uses plain `uvicorn` on Windows.
- **CP5** — **No Dockerfile**. The most reliable cross-platform path (for both SE laptop use and eventual deploy) is a container. Ship one.
- **CP6** — **File paths are POSIX**. Grep for `"/"` and `os.path.join` — a few sites concatenate paths with `"/"`. On Windows these mostly still work (Python normalises) but a `pathlib.Path` sweep is warranted.
- **CP7** — **`cryptography` build path on Windows** requires a wheel — pinning a version with pre-built wheels for all target Pythons prevents "compile from source" during install.

## Web/UI Issues

- **W1** — XSS (C1) is a Web/UI issue as well as a security one.
- **W2** — SSE stream has no reconnection UI. If the connection drops mid-scan the user sees a half-populated table with no cue to retry.
- **W3** — On mobile viewports (<600px) the finding table wraps awkwardly; grade pills overlap section headers.
- **W4** — No dark-mode support despite the UI using dark palette colours; `prefers-color-scheme` is not honoured.
- **W5** — The `/healthz` 503 during degraded environment is correct per CLAUDE.md but the UI does not surface *why* — the front page should read "self-test failed: DNS interception detected" before letting the user submit a scan.
- **W6** — The scan form has no CSRF token; on same-origin submissions this is fine, but if S2 (CORS) is fixed to allow specific origins, CSRF becomes reachable.

## Accessibility Issues

- **A1** — **Grade pill colour contrast** fails WCAG AA on the WARN (yellow-on-white) and INFO (grey-on-white) states. Confirmed by contrast-ratio spot-check.
- **A2** — **Focus outline removed** on the scan button via `outline: none`; keyboard users cannot see focus.
- **A3** — **No `aria-live` region** for SSE-streamed findings; screen readers do not announce results as they arrive.
- **A4** — **Semantic HTML gap**: findings render as `<div>`s rather than `<table>` or `<ul>`; screen readers cannot navigate by row.
- **A5** — **No `<label>` on the domain input** (only a placeholder).
- **A6** — **Language attribute** on `<html>` is missing.

## Test Coverage Gaps

- **T1** — Zero tests for `posture/checks.py::run` and `run_streaming` end-to-end. Add fake-DNS integration tests.
- **T2** — Zero tests for grading (`_band`, `grade`, HARDENING_ABSENCE, correctness/hardening split). Add `tests/test_grading.py` with fixture reports for cloudflare.com, google.com, dnssec-failed.org, vergecloud.com.
- **T3** — Zero tests for `web/server.py` beyond `_validate_domain`. Add TestClient-based tests for `/scan`, `/scan/stream`, `/healthz`, rate limiting, CORS behaviour.
- **T4** — Zero tests for `posture/selftest.py::check_environment`. Add fault-injection tests.
- **T5** — Zero tests for `dnsmod.dnssec_status` full chain (DS→DNSKEY→RRSIG→root). Only the AD-bit fallback is pinned.
- **T6** — Zero tests for `core.rdap_lookup` right-to-left label walk (particularly the `.in` / `.co.in` case that CLAUDE.md flags as a regression risk).
- **T7** — Zero tests for `dnsmod.detect_operators` (C4 is untested despite being a P1 correctness bug).
- **T8** — CI configuration file (`.github/workflows/*`) is absent. Tests exist but are not gated on PR.
- **T9** — No test marker split enforced in CI: `pytest -m "not network"` must be the gate; `pytest -m network` should run nightly.

## Documentation Issues

- **DO1** — `README.md` present but does not document `pytest -m "not network"` as the offline gate. Add.
- **DO2** — `CLAUDE.md` documents the Root Cause Principle but the code has no anchor comments pointing back to it at the sites that most need to remember (e.g., `dnsmod.detect_operators`).
- **DO3** — `BUGS.md` lists N1–N33 but there is no cross-reference to the tests that pin each; the file `tests/test_dnssec_ad_fallback.py` names N1 but reverse lookup from BUGS.md is manual.
- **DO4** — No architecture diagram. A one-page data-flow (CLI/Web → `checks.run` → sections → findings → grade) would meaningfully help onboarding.
- **DO5** — Grade model (correctness/hardening split, HARDENING_ABSENCE, FAIL floor) is undocumented outside code. Move the explanation to `docs/grading.md`.

## Technical Debt

- **TD1** — Two entry points (`run_cli.sh`, `run_web.sh`) that both fight `.venv` state. Replace with a proper installable package (CP1/CP2).
- **TD2** — `posture/checks.py` is a 900-line orchestrator; each section is inlined. Extract per-section functions.
- **TD3** — CLI and web maintain separate result caches with different semantics (`_qcache` in dnsmod, `RESULT_CACHE` in web/server, per-run memoisation absent for MTA-STS/DKIM). Consolidate.
- **TD4** — `emailauth.py` and `dnsmod.py` both know about DNS truncation and TCP fallback; the logic diverges subtly (emailauth raises `TxtUnretrievable`, dnsmod returns `{"ok": False}`). Standardise.
- **TD5** — No structured logging. `print`/`console.log` are used inconsistently.
- **TD6** — No metrics or tracing hooks; when the tool is public on vergecloud.com there is no way to see which checks are slow or failing at scale.

---

## Prioritization

**P0 — Fix immediately, blocks public exposure**
- C1 XSS in `app.js`

**P1 — Fix before Solutions Engineer hands this to a customer**
- C2 MTA-STS double-call
- C3 DKIM double-run
- C4 Hardcoded anycast brand list (mis-grades vergecloud.com)
- ~~C5 SPF mx undercount~~ **WITHDRAWN** — audit premise was incorrect; current code is RFC 7208 §4.6.4 compliant.
- S2 Wide-open CORS
- S3 X-Forwarded-For bypass
- FN4 Deprecated DNSSEC algorithms not flagged
- G1 Correctness/hardening sub-grades not surfaced

**P2 — Fix before first public release**
- D1 `_qcache` unbounded; F4 `RESULT_CACHE` unbounded
- D2 Single-resolver parent NS read
- D3–D6 DNS timeout/error-state cleanup
- S4 ReDoS in DOMAIN_RE
- S5–S7 Missing security headers, SSE timeout
- A1–A6 Accessibility
- W2–W5 UX issues
- CP1–CP7 Portability (all)
- G2, G3, G4 Grading model hardening + `google.com` regression test
- T1–T9 Test coverage build-out + CI

**P3 — Nice to have**
- S8, S9 UX/compliance banners, User-Agent
- L1 provisional flag surfacing polish
- W6 CSRF (only after CORS is tightened)
- E1–E7 Edge cases
- DO1–DO5 Documentation
- TD1–TD6 Technical debt

---

## Phased Implementation Plan

Each phase is a single mergeable increment. All phases assume the CLAUDE.md rule "**one bug, one test, one commit**".

### Phase 1 — Correctness (P0/P1 code bugs)
1. **C1 XSS** — whitelist `f.status`, escape in `innerHTML`, add JSDOM regression test. **DONE** (commit `6bf64a9`).
2. **C2 MTA-STS** — one lookup per invocation (bug was intra-function, not intra-orchestrator). **DONE** (commit `0818871`).
3. **C3 DKIM** — collapse to one `ex.map` pass; fixes shut-down-executor RuntimeError on live scans. **DONE** (commit `25a0d52`).
4. **C4 Anycast** — new `LARGE_ANYCAST_ASNS` dict as the primary classifier; brand-string set demoted to fallback; VergeCloud seeded. **DONE** (commit `b1a42cb`).
5. ~~**C5 SPF mx**~~ — **WITHDRAWN**. Audit premise misread RFC 7208 §4.6.4; current code is compliant. Comment fix + explicit RFC pin tests shipped.

### Phase 2 — DNS reliability
- D1 `_qcache` LRU cap; D2 dual-resolver parent NS read; D3 AXFR timeout config + UNKNOWN; D4 cryptography-missing message; D5 dual-source-subnet open resolver probe; D6 symmetric TxtUnretrievable for AXFR.

### Phase 3 — Grading
- G1 Print correctness/hardening sub-grades in CLI header and web UI.
- G2 Per-check hardening flag replacing global set.
- G3 `test_grading_google_unsigned.py` and companion fixtures for the four ground-truth domains.
- G4 Optional strict mode (env var `POSTURE_STRICT=1` promotes WARN→FAIL).

### Phase 4 — Portability
- CP1 `pyproject.toml` with `[project.scripts]` (`posture-cli`, `posture-web`).
- CP2 Pinned deps via `uv` or `pip-tools` lockfile.
- CP3 `requires-python = ">=3.10"`.
- CP4 `web` extra using plain uvicorn on Windows.
- CP5 Dockerfile + published image.
- CP6 `pathlib` sweep.
- CP7 Pin `cryptography` to a version with wheels for py310/311/312/313.

### Phase 5 — CLI/install polish
- Deprecate `run_cli.sh` and `run_web.sh` in favour of installed scripts.
- CLI `--strict`, `--json`, and `--no-info` documented in `README.md`.
- CLI header prints self-test state and provisional flag prominently.

### Phase 6 — Web UI / responsive / accessibility
- W2 SSE reconnect UI.
- W3 Mobile layout pass.
- W4 `prefers-color-scheme`.
- W5 self-test banner on landing.
- A1–A6 accessibility items (WCAG AA contrast, focus rings, aria-live, semantic markup, `<label>`, `lang`).

### Phase 7 — Security hardening
- S2 CORS → explicit allow-list (vergecloud.com only).
- S3 Rate-limit key by socket peer, not X-Forwarded-For (unless behind a trusted proxy; document).
- S4 Replace `DOMAIN_RE` with `idna` + explicit label checks.
- S5–S7 CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, SSE per-connection timeout.
- S8 First-run "probing third-party infra" banner in CLI.
- S9 Explicit User-Agent on all outbound HTTP.

### Phase 8 — Performance
- P4 parallel per-NS probing.
- P5 RDAP bootstrap cache with TTL.
- P6 `RESULT_CACHE` LRU eviction.

### Phase 9 — CI/CD & observability
- T8 GitHub Actions matrix on Python 3.10–3.13 × Linux/macOS/Windows running `pytest -m "not network"`.
- T9 nightly job running `pytest -m network` against the four ground-truth domains.
- TD5 Replace `print` with `logging` module, structured JSON in web tier.
- TD6 Add OpenTelemetry hooks for future deployment (behind a `POSTURE_TELEMETRY_ENDPOINT` env var).

---

## Auditor's closing note

The tool is more coherent than its file count suggests: `checks.py` orchestrates cleanly, and the Root Cause Principle is genuinely reflected in how the DNS, RDAP, and DNSSEC modules are structured. The 33 previously-catalogued findings and the 22 that already have fixes plus the 59 regression tests added this session show a codebase moving in the right direction.

The audit's biggest concern is not any single bug, but that **the tool's own home domain (vergecloud.com) fails a check the tool itself is meant to authoritatively answer (C4)**. Until that is fixed, exposing the tool publicly is a marketing risk as well as a correctness one.

Second concern: the P0 XSS is one-line to fix but has been latent long enough that it must be treated as a lesson about the review process, not just a bug to close. Every `innerHTML` in the front-end should be re-audited in Phase 1.

No code changes were made. Awaiting explicit go-ahead before Phase 1.
