# Known Biases and Limitations — Posture Checker v0.5

**Scope:** the tool at `main`, post-BIAS-1..9 sweep (through commit `09633b5`).
**Purpose:** an honest catalogue of what this tool is not good at, what it
assumes, and where its output should be read with caveats. **Reading this file
before consuming the tool's output is part of using it correctly.**

**Nothing here is a defect that needs urgent fixing.** Defects go in
[`BUGS.md`](BUGS.md). This file describes *residual* biases — the ones that
survive after the 42-item audit and the BIAS-1..9 sweep, and the ones that are
structural to the tool's design rather than incidental.

---

## How to read this file

Each entry has:

- **Bias/limitation** — one-line claim.
- **Where it lives** — file/module or "design".
- **What it means for output** — how a reader is misled if they take the tool
  at face value.
- **Mitigation today** — what to check alongside the tool's output.
- **v2 status** — whether v2 closes it, softens it, or leaves it in place.
  Cross-referenced to `V2.md` where applicable.

Severity keys:

- 🔴 **Structural** — cannot be closed without a major redesign; documented
  and accepted.
- 🟠 **Scoped** — closed for a subset of cases, open for the rest.
- 🟡 **Enforcement** — the invariant is correct in the code today but the
  regression test that would keep it correct is shallow.
- 🟢 **Deferred** — known, tracked, v2 closes it.

---

## 1. Recursion-trust biases

### 1.1 🟠 Primary reads for TXT records (SPF/DMARC/MTA-STS) still go through the recursive resolver

- **Where:** `posture/emailauth.py` → `_txt_records`. `posture/checks.py` calls
  the recursive path.
- **What it means:** on a captive-portal or SSL-inspection network, a
  validating stub can silently return a filtered TXT set. The tool would emit
  UNKNOWN (rule 1 tri-state protects against emitting `absent`) but not
  `broken`. On networks where the filter passes some TXTs and blocks others,
  the grade dispersion is misleading.
- **Mitigation today:** re-run from a clean network before acting on SPF /
  DMARC / MTA-STS findings on a customer domain. Compare the tool's finding
  to `dig +short TXT <domain>` from a public resolver.
- **v2 status:** 🟢 closed by V2.md Headliner 1 (authoritative-first) + P0
  cross-resolver TXT consensus.

### 1.2 🟢 DNSKEY reads have cross-resolver consensus, TXT reads do not

- **Where:** B37 shipped DNSKEY cross-resolver consensus. `posture/dnsmod.py`
  uses this for the DNSSEC chain. `posture/emailauth.py` does not.
- **What it means:** DNSSEC-chain findings are hardened against one-resolver
  bias. SPF/DMARC/BIMI findings are not.
- **Mitigation today:** as 1.1.
- **v2 status:** 🟢 closed by V2.md P0.

### 1.3 🔴 Environment self-test is a one-shot snapshot at scan start

- **Where:** `posture/selftest.py::check_environment`, invoked once by
  `posture/checks.py::run` / `run_streaming`.
- **What it means:** a 45-second scan spans network-condition changes that
  the self-test never re-measures. A VPN reconnect, a captive-portal
  re-authentication, or an office WiFi hop mid-scan makes the tool's
  "environment safe" claim stale by the time it matters.
- **Mitigation today:** run the tool on a stable network. Do not roam mid-
  scan.
- **v2 status:** 🟠 partially closed — V2.md P0 dimensional self-test
  improves granularity (per-transport) but does not add temporal
  re-measurement. The temporal side stays open as a v2.x candidate.

### 1.4 🔴 Environment self-test is binary today (safe / not-safe)

- **Where:** `posture/selftest.py`.
- **What it means:** blocking TCP/53 is overweighted. TCP/53 is strictly
  needed only for responses > 512 bytes (or EDNS-negotiated size) and for
  AXFR. A network that blocks only TCP/53 for AXFR while allowing normal
  UDP+TCP DNS is still 95% trustworthy for this tool's purposes, but the
  binary self-test flags the whole environment.
- **Mitigation today:** the tool errs toward UNKNOWN rather than false FAIL,
  so the bias is toward under-reporting, not over-reporting.
- **v2 status:** 🟢 closed by V2.md P0 dimensional self-test.

---

## 2. Data-source biases

### 2.1 🟢 `LARGE_ANYCAST_ASNS` is a hand-curated allowlist

- **Where:** `posture/checks.py::LARGE_ANYCAST_ASNS`.
- **What it means:** operators are added by PR review, not discovered
  automatically. VergeCloud (AS141383) was the operator whose omission
  triggered the whole BIAS sweep. Regional operators (Indian, Southeast-Asian,
  Latin-American, African anycast providers) will be under-represented until
  someone flags them.
- **Mitigation today:** BIAS-4's wire-level `id.server` probe catches
  professionally-run infrastructure without a table lookup. An anycast
  operator not in `LARGE_ANYCAST_ASNS` but running RFC 4892-compliant
  authoritatives will still upgrade brand-only from medium → high.
- **v2 status:** 🟠 softened by V2.md P0 RIPE Atlas integration (multi-vantage
  PoP-spread measurement grades measured topology, not just ASN membership).
  The table itself remains hand-curated.

### 2.2 🟠 RFC 4892 `id.server` probe upgrades confidence for any RFC 4892-
compliant server, not only for anycast

- **Where:** `posture/dnsmod.py::probe_ns_id_server`.
- **What it means:** a single-unicast BIND with `hostname.bind` CH TXT
  enabled will pass this probe and upgrade a brand-only match to `high`
  confidence. The signal is "professionally-run infrastructure," not
  "anycast." A well-run single-unicast NS remains a real single point of
  failure the grade will not reflect.
- **Mitigation today:** check the operator's own network topology docs before
  relying on a `high`-confidence anycast verdict.
- **v2 status:** 🟢 closed by V2.md P0 RIPE Atlas — multi-vantage PoP-spread
  distinguishes single-unicast from anycast structurally.

### 2.3 🟠 Cymru ASN lookup has no local cache

- **Where:** `posture/core.py::cymru_asn`.
- **What it means:** every scan hits `origin.asn.cymru.com`. Cymru
  rate-limits and asks for polite usage. Under public-deploy load, the ASN
  path silently falls back to no-lookup on rate-limit failure, and BIAS-1's
  correctness quietly degrades — the tool would revert to brand-string-only
  classification without emitting an environment note.
- **Mitigation today:** run the tool sparingly. Do not batch-scan hundreds
  of domains from one deployment.
- **v2 status:** 🟢 closed by V2.md P1 Cymru ASN cache with polite-usage
  backoff.

### 2.4 🟠 IANA registries (DNSSEC algorithm numbers, RDAP bootstrap, EPP
status codes) are not vendored

- **Where:** DNSSEC algorithm handling depends on `dnspython`'s built-in
  tables. RDAP bootstrap fetches live.
- **What it means:** an upstream registry change or `dnspython` version skew
  can shift grading without any local commit. Reproducibility across time is
  not guaranteed.
- **Mitigation today:** pin `dnspython` in `requirements.txt`. Note the
  scan-time in report metadata (the CLI does this; `--json` output includes
  timestamps).
- **v2 status:** 🟢 closed by V2.md P2 vendored IANA registry snapshots +
  RDAP bootstrap cache.

### 2.5 🔴 Ground-truth test domains are frozen in time

- **Where:** `tests/test_grading_*.py`, `CLAUDE.md` § GROUND TRUTH TEST DOMAINS.
- **What it means:** `cloudflare.com` DNSSEC-validates *today*. `google.com`
  is deliberately unsigned *today*. `paypal.com` is near the 10-lookup SPF
  limit *today*. All three could change tomorrow. When they do, the
  regression suite fails for reasons unrelated to the tool's code.
- **Mitigation today:** when a ground-truth fixture starts failing, verify
  by hand whether the operational posture changed before assuming the tool
  regressed. `git log` of the fixture file is the paper trail.
- **v2 status:** 🟠 partially softened by V2.md P3 cross-tool comparison
  harness (dnsviz, hardenize, MXToolbox) — divergences between the tools
  will catch a fixture-drift event earlier. Not closed structurally.

---

## 3. Test-enforcement biases

### 3.1 🟡 BIAS-8 AST walker only sees literal-string arguments

- **Where:** `tests/test_finding_language_neutrality.py`.
- **What it means:** the ownership-token guard walks `ast.Constant` and static
  `ast.JoinedStr` parts. Code like `rep.add("S", "L", "WARN", f"{s} zone
  uses NSEC", ...)` or `" ".join(["your", "zone"])` slips past the guard.
  The invariant is correct at every literal string in the codebase today;
  the *test* protecting the invariant is not.
- **Mitigation today:** code review is the second layer of defence. The
  guard catches the naïve regression, not the sophisticated one.
- **v2 status:** 🟢 closed by V2.md test-discipline P0 — extend BIAS-8 walker
  to f-strings-with-variables, `.format`, `.join`, and `+` concatenation.

### 3.2 🟡 BIAS-6 vendor-neutrality guard is scoped to `Remediation.general`
and `Remediation.vendor` only

- **Where:** `tests/test_remediation_vendor_neutrality.py`.
- **What it means:** the guard does not scan `Finding.detail` or
  `Finding.why`. A check emitting `detail="Cloudflare's dashboard has a
  one-click enable for this"` would pass every current test.
- **Mitigation today:** code review as above.
- **v2 status:** 🟢 closed by V2.md test-discipline P0 — extend BIAS-6 guard
  into `Finding.detail` and `Finding.why`.

### 3.3 🟡 There is no CLI ↔ web output-parity test

- **Where:** doctrine (CLAUDE.md) but not code.
- **What it means:** "byte-for-byte identical between the two entry points"
  is aspirational. A refactor that adds a finding to `run()` but not to
  `run_streaming()` (or vice versa) would ship green.
- **Mitigation today:** manual smoke-check both entry points on a ground-
  truth domain before releasing.
- **v2 status:** 🟢 closed by V2.md P1 CLI ↔ web output-parity test.

---

## 4. Emit-model biases

### 4.1 🟢 `Finding.confidence` is dead code today

- **Where:** `posture/core.py::Finding`.
- **What it means:** T5 shipped the mechanism; no emit populates it. External
  JSON consumers see `confidence=None` uniformly. A slot for a future
  contributor to fill inconsistently.
- **Mitigation today:** external consumers should treat `confidence=None`
  as "unspecified" and not draw inferences from it.
- **v2 status:** 🟢 closed by V2.md P1 confidence-population migration.

### 4.2 🟢 `finding_id` migration is partial

- **Where:** across `posture/checks.py`. Some emits declare stable IDs
  (e.g. `NS_TOPOLOGY` from BIAS-2), most do not.
- **What it means:** `--json` consumers keying on IDs must handle a mix of
  stable-ID and label-only findings. The stability contract is not yet
  enforceable across the whole emit surface.
- **Mitigation today:** consumers should fall back to `label` when
  `finding_id` is absent; new emits should declare an ID from the start.
- **v2 status:** 🟢 closed by V2.md P1 finding_id migration.

### 4.3 🔴 Findings render prose, they don't ship evidence

- **Where:** all `rep.add` sites.
- **What it means:** a finding says "SPF present, hardfail" but does not
  ship the raw TXT bytes. A customer's DNS team reading the report cannot
  independently verify without re-running the tool themselves. Every
  serious audit tool (Qualys SSL Labs, dnsviz.net, hardenize.com) ships
  the wire evidence alongside the verdict. This one does not.
- **Mitigation today:** the SE running the tool must re-verify by hand
  with `dig` / `openssl s_client` when the customer challenges a finding.
- **v2 status:** 🟢 closed by V2.md Headliner 3 (structured evidence).

### 4.4 🟠 `Finding.detail` / `Finding.why` have no length cap

- **Where:** `posture/core.py::Finding`.
- **What it means:** a pathological zone (100+ NS, 1000+ TXT lines, DKIM
  probed-list of 500 selectors) produces unbounded rendered output. Grade
  computation is linear; rendering is not always bounded.
- **Mitigation today:** BIAS-7 introduces `(…and N more)` truncation for
  the DKIM probed-list specifically. Other emit sites do not truncate.
- **v2 status:** not explicitly in V2.md; candidate for v2.1 if it bites.

---

## 5. Grade-model biases

### 5.1 🔴 Grade dispersion is poor — most non-trivial domains grade B

- **Where:** `posture/checks.py::grade`.
- **What it means:** the letter grade compresses ~30 dimensions of finding
  data into one alphanumeric character. Most well-configured domains
  cluster at B, most badly-configured domains cluster at D. The signal is
  in the sub-grades and the finding list, not the overall letter.
- **Mitigation today:** read the finding list, not the letter. The `--json`
  output has sub-grades even when the CLI table hides them.
- **v2 status:** 🟢 mitigated (not closed) by V2.md P0 sub-grade breakdown
  always visible.

### 5.2 🟠 Grade model has no version pin

- **Where:** `posture/checks.py::grade`.
- **What it means:** two runs of the tool at different `git` revisions can
  produce different grades on the same domain state, and the report has no
  field that says which grade model was used. Historical reports are not
  cleanly interpretable after a grade-model change.
- **Mitigation today:** record the tool's `git` SHA when saving a report.
- **v2 status:** 🟢 closed by V2.md P1 grade-model versioning +
  `GRADE_TABLE` as data.

### 5.3 🟠 Grade weights live in code, not in a table

- **Where:** `posture/checks.py::grade`.
- **What it means:** a customer asking "why did we get B+ and not A-?"
  needs a code walkthrough to answer. There is no lookup a customer can
  read.
- **Mitigation today:** documentation, verbally.
- **v2 status:** 🟢 closed by V2.md P1 `GRADE_TABLE` as data.

### 5.4 🟡 The `hardening` flag is authored by hand at every emit

- **Where:** every `rep.add(hardening=True|False)` call in
  `posture/checks.py`. BIAS-5 swept for symmetry across nine sites.
- **What it means:** a new emit that forgets to pass `hardening=True` will
  silently be graded as correctness rather than modernity. BIAS-5's
  regression test enforces symmetry across the sweep-covered labels,
  not across all future labels.
- **Mitigation today:** authors follow the pattern in adjacent emits.
- **v2 status:** not explicitly in V2.md; candidate for a schema-level
  fix (e.g. hardening as a property of the `finding_id`, not the emit
  call).

---

## 6. Query-path biases

### 6.1 🔴 Single-vantage measurement

- **Where:** every check in `posture/dnsmod.py` and adjacent.
- **What it means:** all measurements are from the tool's own network
  position. Anycast operators route responses to their nearest PoP, so a
  scan run from India sees a Mumbai PoP's answer, and a scan run from
  Frankfurt sees Frankfurt's. A geo-steering misconfiguration is invisible
  to a single-vantage scan.
- **Mitigation today:** scans should be run from at least two geographies
  before a customer report is finalised.
- **v2 status:** 🟢 closed by V2.md Headliner 2 (RIPE Atlas integration).

### 6.2 🟠 EDNS Client Subnet detection is present, correctness scoring is not

- **Where:** B31 shipped ECS-based geo-steering detection.
- **What it means:** the tool detects that a domain uses geo-steering. It
  does not grade whether the geo-steering is *correct* — i.e. whether a
  Mumbai client is actually routed to a Mumbai PoP.
- **Mitigation today:** as 6.1.
- **v2 status:** 🟢 closed by V2.md P3 ECS geo-correctness scoring
  against curated prefix list.

### 6.3 🟠 DKIM selector probing is fixed-list, not adaptive

- **Where:** `posture/emailauth.py::evaluate_dkim`.
- **What it means:** every scan burns 26 queries (24 defaults + up to 2
  extras) against the customer's DNS. On rate-limited authoritatives this
  is heavy. Adaptive probing (common-selector heuristics first, stop on
  first hit) would cut the budget in half.
- **Mitigation today:** BIAS-7's evidence emit at least tells the reader
  which 26 were tried, so the query cost is visible.
- **v2 status:** 🟢 closed by V2.md P2 DKIM adaptive selector probing.

### 6.4 🟠 IPv6 open-resolver check is separate from IPv4

- **Where:** `posture/dnsmod.py`.
- **What it means:** FN5 in the ledger. An operator running an open
  resolver on IPv6 only would be caught in principle but the plumbing
  through `_dns` is scoped narrowly today.
- **Mitigation today:** manual `dig @<ns-v6> version.bind CH TXT`.
- **v2 status:** not explicitly in V2.md; candidate for v2.1.

---

## 7. Anti-abuse and public-deploy biases

### 7.1 🔴 Rate limit is per-IP, not per-target-domain

- **Where:** `web/server.py`.
- **What it means:** an attacker with a botnet can scan a single target
  domain from many IPs, each below the per-IP limit, and DoS both this
  tool and the target's authoritatives. On public deploy this is
  recon-as-a-service liability.
- **Mitigation today:** do not deploy publicly until per-target limits
  are in place.
- **v2 status:** 🟢 closed by V2.md P2 per-target rate limit +
  `_posture-optout` TXT.

### 7.2 🔴 There is no domain-owner opt-out

- **Where:** design.
- **What it means:** a domain owner has no way to signal "do not scan me"
  to a public deployment of this tool. The tool respects DNS-standard
  robots-style mechanisms in principle (does not honour `security.txt`
  today), but no dedicated opt-out exists.
- **Mitigation today:** as 7.1.
- **v2 status:** 🟢 closed by V2.md P2 `_posture-optout.<domain>` TXT.

### 7.3 🟠 `JOBS` dict is unbounded

- **Where:** `web/server.py`.
- **What it means:** S7 caps per-connection SSE lifetime. It does not TTL
  the `Job` object itself. A busy public deploy accumulates jobs until
  the process is restarted.
- **Mitigation today:** restart the web process periodically.
- **v2 status:** 🟢 closed by V2.md P1 JOBS-dict TTL eviction.

### 7.4 🟠 First-run banner is not shipped

- **Where:** S8 in the ledger.
- **What it means:** the CLI does not print a "you are actively probing
  third-party infrastructure" banner on first run. This is legal-cover
  material for public-facing distribution.
- **Mitigation today:** documentation in `README.md`.
- **v2 status:** 🟢 closed by V2.md P2 first-run banner.

### 7.5 🟠 No explicit User-Agent on `requests` calls

- **Where:** `posture/emailauth.py` (MTA-STS HTTPS fetch), any other
  HTTP-touching site. S9 in the ledger.
- **What it means:** target-domain operators cannot identify the scan as
  coming from this tool. Good netizenship says the UA should name the
  tool + version.
- **Mitigation today:** documentation only.
- **v2 status:** 🟢 closed by V2.md P2 explicit User-Agent.

---

## 8. UX / reporting biases

### 8.1 🔴 Point-in-time snapshot only

- **Where:** design.
- **What it means:** the tool does not persist reports and cannot show
  drift between two runs of the same domain. A zone with fluctuating
  signing state (mid-KSK rollover, say) is graded on today's snapshot,
  and two runs 5 minutes apart could disagree with no way to represent
  this to the reader.
- **Mitigation today:** save `--json` output externally, diff by hand.
- **v2 status:** 🟢 closed by V2.md P3 historical view (persist reports,
  diff two runs). Persistence-layer decision open — see V2.md open
  question 3.

### 8.2 🔴 In-memory storage — closing the tab loses the report

- **Where:** `web/server.py`.
- **What it means:** an SE runs a check for a customer, closes the
  browser tab, and there is no way to retrieve the report. Workflow bug
  for the lead-gen use case.
- **Mitigation today:** copy-paste the URL of the completed report
  before closing.
- **v2 status:** 🟠 softened by V2.md P0 `--bundle` (customer downloads
  their own artefact) + P1 JOBS-dict TTL. Not fully closed — the
  persistence-layer decision remains open.

### 8.3 🟠 `example.com` is treated as a real domain

- **Where:** `posture/checks.py`.
- **What it means:** RFC 2606 reserves `example.com` for documentation.
  The tool grades it. A curious reader running `./run_cli.sh example.com`
  gets a real-looking report with no INFO row saying "this is a reserved
  domain, results are illustrative only."
- **Mitigation today:** the test suite uses `example.test` and
  `example.com` in fixtures with the understanding that they will be
  graded like any other zone.
- **v2 status:** not explicitly in V2.md; candidate for a UX pass in
  v2.x.

### 8.4 🟠 Administrative-hold state is not distinguished from resolution failure

- **Where:** `posture/core.py`, `posture/dnsmod.py`.
- **What it means:** domains in registrar hold (`clientHold`, `serverHold`)
  don't resolve. The tool queries them and interprets NXDOMAIN /
  SERVFAIL as protocol failure rather than administrative state. EPP
  status codes are read separately, but the grade path does not currently
  short-circuit on hold state.
- **Mitigation today:** check the EPP status section before reading the
  rest of the report.
- **v2 status:** not explicitly in V2.md; candidate for v2.x correctness
  sweep.

### 8.5 🟠 Version number in CLAUDE.md is stale

- **Where:** `CLAUDE.md` § CURRENT STATE says "Version 0.5. 33 known
  findings."
- **What it means:** BUGS.md now says 42/43 DONE, and the BIAS sweep
  added 9 more items on top. The version pin has not been bumped.
- **Mitigation today:** trust `git log` over the CLAUDE.md pin.
- **v2 status:** administrative — fix in the v2.0-alpha commit that
  cuts the release.

---

## 9. Recon-and-privacy biases

### 9.1 🟠 The tool emits recon intelligence

- **Where:** design.
- **What it means:** every finding — SPF weakness, missing DMARC, RDAP
  registrant, ASN, per-NS IP list, IPv6 exposure — is target-selection
  intelligence for an attacker. This is intrinsic to any DNS-audit tool.
- **Mitigation today:** use responsibly. Do not scan third-party
  domains without authorisation. Public deployment requires §7 items
  (rate limit, opt-out, banner) to raise misuse cost.
- **v2 status:** the recon surface is intrinsic; V2.md §7 items raise
  the cost of misuse but do not eliminate it. Documented and accepted.

### 9.2 🟠 Team Cymru sees every scan's target IP

- **Where:** `posture/core.py::cymru_asn`.
- **What it means:** Cymru's `origin.asn.cymru.com` service logs the
  IP being looked up. A scan of a customer's authoritatives reveals to
  Cymru which IPs the customer runs.
- **Mitigation today:** Cymru is a well-known and trusted community
  resource. Users concerned about this should self-host the origin.asn
  data.
- **v2 status:** not explicitly in V2.md; RPKI data-source decision
  (V2.md open question 4) touches an adjacent concern.

### 9.3 🟠 RIPE Atlas measurements are public

- **Where:** V2.md Headliner 2 (not yet shipped).
- **What it means:** every Atlas measurement created by v2's `--atlas`
  path is world-readable via the measurement ID. Anyone who obtains the
  ID can see the scan happened, when, and what the results were.
- **Mitigation today:** N/A (feature not shipped).
- **v2 status:** 🟢 documented in V2.md Headliner 2 privacy section.
  `--atlas-oneshot` will scrub local linkage but the measurement data
  stays public on Atlas.

---

## 10. Test-fixture biases

### 10.1 🟠 The regression suite is offline-only in CI

- **Where:** `pytest -m "not network"` gate.
- **What it means:** every network-touching correctness claim is
  validated by fixtures, not against live infrastructure. If a fixture
  captures a stale RRSIG structure, or an obsolete Cymru response
  format, CI is green but production behaviour is wrong.
- **Mitigation today:** manual smoke against `cloudflare.com`,
  `google.com`, `dnssec-failed.org` periodically.
- **v2 status:** 🟠 softened by V2.md P3 cross-tool comparison harness
  (weekly CI cron against real tools); not closed structurally.

### 10.2 🟠 Test coverage is uneven

- **Where:** `tests/`.
- **What it means:** BIAS-1..9 added ~9 test files with strong coverage
  of their specific invariants. Older orchestration paths in
  `checks.py::run` are covered indirectly by ground-truth grade tests
  but not by unit tests.
- **Mitigation today:** manual review of any change to `run` /
  `run_streaming`.
- **v2 status:** not explicitly in V2.md; candidate for v2.x hygiene
  pass.

---

## 11. Design-choice biases (documented and accepted)

These are not defects. They are design choices this tool made deliberately.
They limit the tool's scope; they do not mislead its readers.

### 11.1 🔴 The tool audits, it does not remediate

- **What it means:** no "apply fix" button. Every finding routes to
  `REMEDIATION` prose (general fix + VergeCloud rider), not to an
  automated action.
- **Rationale:** editing a customer's zone is a different trust boundary
  than reading it. Conflating the two would make the tool a lateral-
  movement asset.
- **v2 status:** explicit non-goal in V2.md.

### 11.2 🔴 The tool is single-shot, not continuous monitoring

- **What it means:** no persistent scheduler, no alerting, no on-call
  rota.
- **Rationale:** monitoring is a different product with a different
  architecture. Building it into this tool would compromise the audit
  posture of the audit tool.
- **v2 status:** explicit non-goal in V2.md.

### 11.3 🔴 No multi-tenant customer accounts

- **What it means:** no login, no per-user saved reports.
- **Rationale:** accounts imply auth surface, session lifecycle, data-
  retention obligations. This tool is presales-facing; the SE running
  it owns the workflow.
- **v2 status:** explicit non-goal in V2.md. `--bundle` in v2 is the
  persistence story (customer downloads their own artefact).

### 11.4 🔴 CLI and web are separate entry points to the same engine

- **What it means:** the doctrine says output must be byte-for-byte
  identical. There is no auto-generated web from a CLI spec; they are
  parallel implementations.
- **Rationale:** the two entry points have different auth boundaries
  (CLI = local process, web = HTTP surface) and different rendering
  requirements (Rich terminal vs SSE). Sharing the engine but forking
  the front-end is the correct trade-off.
- **v2 status:** V2.md P1 CLI ↔ web output-parity test enforces the
  doctrine mechanically.

---

## 12. Withdrawn — audit was wrong

Documented so nobody reopens them.

### 12.1 B11 / C5 / FP3 — "SPF `mx` mechanism undercount"

- **Original claim:** the SPF lookup counter undercounts `mx`.
- **Verdict:** WITHDRAWN. RFC 7208 §4.6.4 says `mx` counts as one lookup
  (the MX query itself) *plus* one per resulting A/AAAA lookup. The tool
  is correct; the audit misread the RFC.
- **Where recorded:** `BUGS.md`.

### 12.2 A6 — accessibility `lang="en"` missing

- **Original claim:** `web/static/index.html` was missing `<html lang>`.
- **Verdict:** N/A. `lang="en"` was already present. The audit was
  inaccurate.
- **Where recorded:** `AUDIT.md`.

### 12.3 TD2, TD4 — audit conflated layers

- **Verdict:** no change needed. Recorded so a future refactor does not
  reintroduce the "fix" that would have made the code worse.
- **Where recorded:** `AUDIT.md`.

---

## 13. Not-a-bias-but-worth-naming

Things this tool does that a reader might mistake for a bias.

### 13.1 The tool grades `google.com` as A overall despite deliberate DNSSEC non-adoption

- **Why:** DNSSEC is a hardening feature, not a correctness feature. The
  `hardening` flag on the `Finding` dataclass separates the two, and the
  grader credits hardening-PASS toward the hardening sub-grade only.
  A zone that is deliberately unsigned but perfectly configured
  otherwise scores well on correctness and takes only a hardening hit.
- **This is intended.** Docs: `CLAUDE.md` § GROUND TRUTH TEST DOMAINS.

### 13.2 UNKNOWN is often the correct output

- **Why:** CLAUDE.md rule 1 tri-state. "Could not retrieve" (UNKNOWN)
  is not "absent" (FAIL). Reporting UNKNOWN on a network path that
  cannot reliably retrieve the data is a feature, not a hedge.
- **This is intended.** Docs: `CLAUDE.md` § NON-NEGOTIABLE RULES.

### 13.3 The `Nameserver topology` finding sometimes reads as PASS with only one operator

- **Why:** an anycast operator with verified ASN + verified wire signal
  is a single-operator topology that is nonetheless not a single point
  of failure. Verified anycast is a legitimate deployment.
- **This is intended.** Docs: BIAS-2 commit message
  (`77f1c72f2fa14445f32e175f60ef4c4efde08545`).

### 13.4 The tool refuses to emit findings on an untrustworthy network

- **Why:** CLAUDE.md rule 5. A confident finding on an untrustworthy
  path is worse than no finding.
- **This is intended.** Docs: `CLAUDE.md` § NON-NEGOTIABLE RULES.

---

## Bias-and-limitation summary table

Structural (🔴, cannot be closed without redesign): 9
Scoped (🟠, partially closed, remainder open): 17
Enforcement (🟡, test shallow but invariant holds): 3
Deferred (🟢, v2 closes): 20 (with overlap where v2 closes a scoped item)

**Net:** this tool is above the category median on correctness and
below the category median on evidence-shipping. v2's headliners are
aimed at exactly that gap.

---

## Change log

- `2026-09-22` — initial catalogue of residual biases after BIAS-1..9
  sweep and v2 plan finalisation. Living document — amend in place.
