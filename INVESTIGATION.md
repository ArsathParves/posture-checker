# Systematic Investigation Brief

Instructions for a full line-by-line, function-by-function, module-by-module
audit of this project from three perspectives simultaneously.

Read `CLAUDE.md` first (project context and the ROOT CAUSE PRINCIPLE), then
`BUGS.md` (33 findings already known — do not re-report these; find what is
NOT yet there).

---

## The three hats

Hold all three at once. Every function gets all three questions.

### 1. Senior SDET
- What input breaks this? Empty, null, malformed, oversized, wrong type,
  unicode, injection, boundary values, deliberately hostile.
- What happens on partial failure? Timeout mid-loop? Exception in a thread?
- Is the failure path tested, or only the happy path?
- Is this deterministic? If not, what makes it flaky?
- What state persists between calls that shouldn't?
- Can two concurrent callers interfere?

### 2. Senior Engineering Architect
- Where does this function get its truth from, and is that the real source
  or a convenient proxy? (See ROOT CAUSE PRINCIPLE.)
- What implicit assumption is encoded that nobody stated?
- What happens when this scales 100x? 1000 concurrent users?
- Is the contract between modules explicit or accidental?
- Does the same concept have two representations that can drift apart?
- What's the blast radius when this fails?

### 3. DNS SME
- Is this RFC-correct? Cite the RFC and section.
- What real-world DNS behaviour breaks this? Anycast, split-horizon,
  geo-steering, CNAME flattening, CDN fronting, wildcards, DNSSEC rollover,
  lame delegation, glue records, IDN, negative caching.
- Does it distinguish authoritative from recursive answers?
- Does it handle EDNS0, truncation, TCP fallback, fragmentation?
- Would a large real-world zone break this? A tiny parked one? A ccTLD with
  unusual registry behaviour?

---

## Mandatory method

**Do not skim. Do not sample.** Previous reviews of this project were
opportunistic and missed findings that a systematic pass caught. Work
through every module, every function, every branch.

For each module, in this order:

1. **Read the entire file top to bottom before analysing anything.**
2. **List every function** with its inputs, outputs, side effects, and
   external calls.
3. **For each function, line by line:** what does this line assume? What
   happens if that assumption is false?
4. **Trace every branch**, including `except` blocks and early returns.
5. **Identify shared/global state** and who mutates it.
6. **Write down what you'd need to verify empirically** — then verify it
   with a real query. Never assume DNS behaviour.
7. **Record findings in the format below** in `FINDINGS_NEW.md`.

### Verification is mandatory, not optional

Any claim about real-world DNS behaviour must be backed by a query you
actually ran. Example: do not assert "operator X is anycast" — query
`hostname.bind` CH TXT from multiple angles and show the evidence.

If the environment blocks a verification (TCP/53 filtered, DNS intercepted),
say so explicitly and mark the finding **unverified** rather than asserting it.

---

## Module-by-module scope

Work in this order — dependencies first, so you understand what callers rely on.

### 1. `posture/core.py`
`normalize_domain`, `rdap_endpoint_for`, `rdap_lookup`, `parse_rdap`,
`cymru_asn`, `ip_rdap`, `_ip_endpoints`, `Finding`, `Report`.

Focus: IDN/punycode edge cases and homograph safety. RDAP bootstrap caching
and staleness. vCard parsing assumptions (index `[3]` on `fn` — what if the
structure differs?). Entity role selection. Redaction detection logic.
Team Cymru parsing (pipe-split — what if a field contains a pipe?). What
happens when a TLD has multiple RDAP endpoints? Trailing-dot and case
handling consistency between `Finding` labels and lookups.

### 2. `posture/dnsmod.py`
`_resolver`, `query`, `_query_uncached`, `domain_exists`, `get_ns_and_ips`,
`probe_each_ns`, `get_soa`, `parent_delegation`, `dnssec_status`,
`authoritative_vs_cached`, `axfr_open_check`, `open_resolver_check`.

Focus: the memoisation cache (keys, TTL, cross-contamination). The
double-query problem (B9). Resolver rotation vs. pinned resolver
inconsistency. EDNS0/DO/CD flag correctness per query type. Thread-pool
usage and exception propagation. `parent_delegation` for multi-label TLDs
(`co.in`, `bank.in`) and for the apex of a TLD itself. DNSSEC state machine
completeness — enumerate every reachable combination of
(ds, dnskey, self_signed, ds_matches, ad) and confirm each maps to a sane
state. AXFR exception taxonomy (which exceptions mean "refused" vs
"couldn't test"?). Open-resolver probe false positives.

### 3. `posture/emailauth.py`
`_txt_records`, `_count_spf_lookups`, `get_spf`, `evaluate_spf`,
`_dkim_key_state`, `evaluate_dkim`, `evaluate_dmarc`, `evaluate_mta_sts`.

Focus: full RFC 7208 conformance for SPF (see B10–B13 for known issues, but
audit the whole parser — `exp=`, macros, `ptr` deprecation, void lookups,
the 2-void-lookup limit, `%{}` macro expansion, multiple `all`, malformed
records, `+all` danger). TXT string concatenation across 255-byte chunks.
DKIM key parsing beyond `p=` (`k=`, `t=y` testing mode, `h=`). DMARC tag
validation (unknown tags, `rf=`, `ri=`, `fo=`, malformed `pct`). MTA-STS
policy file fetch (currently only the DNS record is checked — the actual
HTTPS policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt` is never
retrieved or validated).

### 4. `posture/selftest.py`
`check_environment`.

Focus: known flaws in B33. Beyond those: is the control-query choice sound?
What does "safe_for_per_ns_checks" actually guarantee? Should there be
degrees of trust rather than a boolean? Does it detect DNS64/NAT64,
IPv6-only egress, captive portals, or resolver-level response rewriting that
still sets AA correctly?

### 5. `posture/checks.py` (largest, most complex)
`run`, `run_streaming`, `_registration`, `_nameservers`, `_soa`, `_records`,
`_dnssec`, `_email`, `_security`, `grade`, `_band`, `_f2d`,
`_report_to_dict`, `_days_since`, `_days_until`.

Focus: `run()` and `run_streaming()` must produce identical Reports — verify
by diffing outputs for the same domain; they are separately maintained and
have already drifted once. Section ordering and data dependencies (`_soa`
depends on `ns_map` from `_nameservers`; `_records` and `_email` depend on
`rep.data` keys that may be absent if an earlier section threw — enumerate
every `rep.data.get()` and what happens when the key is missing). The grade
model (B4, B5, B6). Date parsing robustness (`_days_since`/`_days_until`
with malformed or timezone-less RDAP dates). `HARDENING_ABSENCE` string
coupling.

### 6. `posture/cli.py`
`render`, `main`, `_jsonable`, `REMEDIATION`.

Focus: Rich markup injection — finding `detail` text is interpolated into
Rich markup strings; a domain whose DNS records contain `[` sequences could
break or manipulate rendering. `--json` schema stability and whether it
round-trips. Exit codes. Terminal width assumptions.

### 7. `web/server.py`
`_validate_domain`, `create_check`, `stream_check`, `get_result`, `healthz`,
`_run_job`, `Job`, cache and semaphore handling.

Focus: SSE correctness (client disconnect handling, reconnection, `Last-Event-ID`,
backpressure when the client reads slower than the producer). Job lifecycle
and GC (`loop.call_later` on a possibly-closed loop). `asyncio.Event` reuse
across consumers (`_wake.clear()` races with multiple simultaneous SSE
readers). Cache poisoning (B7). DoS ceiling (B8). Whether `run_in_executor`
with the default pool can starve. Rate-limit bypass via header spoofing
(`get_remote_address` behind a proxy — `X-Forwarded-For` trust).

### 8. `web/static/app.js`
Focus: **XSS.** Finding `detail` and `why` come from DNS records — attacker-
controllable content. Verify `escapeHtml` covers every interpolation site;
note that `innerHTML` is used with template literals. `cssEscape` is a naive
quote-replace used in a selector — check for breakage/injection with
unusual section names. EventSource error handling and reconnect storms.

### 9. `web/static/index.html`, `style.css`
Focus: CSP absence, accessibility, dark-mode rendering, mobile layout.

### 10. Cross-cutting
- Do `run()` and `run_streaming()` diverge? Prove it with a diff test.
- Is any finding emitted by one path and not the other?
- Is `rep.data` schema documented anywhere? (No.) Make it explicit.
- Memory growth: `_qcache`, `JOBS`, `RESULT_CACHE` over a long-lived process.
- What happens on IPv6-only egress?
- Is the tool safe to point at a hostile domain that returns adversarial
  DNS responses (huge record sets, deeply nested CNAMEs, CNAME loops,
  compression-pointer loops)?

---

## Finding report format

Write all new findings to `FINDINGS_NEW.md` using this structure:

```markdown
### N<n>. <Short title>

**Module / function:** posture/dnsmod.py :: _query_uncached (lines 45–62)
**Perspective:** SDET | Architect | DNS SME
**Severity:** CRITICAL | HIGH | MEDIUM | LOW
**Type:** correctness | RFC violation | security | performance | bias | robustness

**What is wrong**
<precise description>

**Reproduction**
<exact command or code that demonstrates it>

**Evidence**
<actual query output / test result — not reasoning>

**Why it matters**
<real-world consequence, with the domain type it affects>

**Root cause principle instance?**
<yes/no — is this another case of trusting a shortcut over the real source?>

**Suggested fix**
<approach, with RFC citation if applicable>

**Acceptance criteria**
<what test proves it fixed>
```

---

## Deliverables

1. `FINDINGS_NEW.md` — all newly discovered findings in the format above.
2. `COVERAGE.md` — a table of every module, every function, marked audited
   or not, so gaps in the audit itself are visible.
3. An updated `BUGS.md` with new findings merged into the priority queue.
4. **No code changes during the investigation phase.** Audit first, fix
   second. Mixing them makes the audit incomplete and the fixes unreviewable.

---

## Explicit anti-goals

- Do not fix bugs during the investigation pass. Record and move on.
- Do not re-report the 33 findings already in `BUGS.md`. Confirm or refute
  them if you find contradicting evidence, but focus on what is new.
- Do not assert DNS behaviour without querying it.
- Do not mark something "fine" because it looks conventional. This codebase's
  worst bugs looked conventional — a hardcoded operator list, a
  self-signature check, an RDAP nameserver comparison. All looked reasonable.
  All were wrong.

---

## Success criterion

The audit succeeds when, for every function in every module, you can state:
what it assumes, how it fails, whether it is RFC-correct, and whether its
truth source is authoritative or a proxy — with evidence, not reasoning.
