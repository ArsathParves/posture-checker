# Domain Posture Checker — Project Context

## What this is

A DNS/RDAP/DNSSEC/email-authentication posture checker. Two entry points,
one shared check engine:

- **CLI** — `posture/cli.py`, launched via `./run_cli.sh <domain>`
- **Web** — `web/server.py` (FastAPI + SSE), launched via `./run_web.sh`

Both call `posture/checks.py`. Results must be **byte-for-byte identical**
between the two — the web layer is presentation and access control only.

The tool makes **live** DNS, RDAP, AXFR and HTTPS queries against real
third-party infrastructure. It is intended for eventual public deployment on
`vergecloud.com` as a lead-generation tool for VergeCloud's ADNS product,
and for internal pre-sales use by a Solutions Engineer assessing customer
domains (largely Indian BFSI, government and enterprise).

## Module map

| File | Responsibility |
|---|---|
| `posture/checks.py` | Orchestrator. Runs sections, emits findings, computes grades. Contains `run()` (CLI) and `run_streaming()` (web generator). |
| `posture/core.py` | Domain normalisation (IDN/punycode), RDAP bootstrap + registry lookup, IP-RDAP, Team Cymru ASN lookup, `Finding`/`Report` dataclasses. |
| `posture/dnsmod.py` | All DNS querying. Record lookups, per-NS probing, parent delegation, DNSSEC chain validation, AXFR, open-resolver. |
| `posture/emailauth.py` | SPF parsing + RFC 7208 lookup counting, DKIM selector probing, DMARC, MTA-STS, TLS-RPT. |
| `posture/selftest.py` | Network-path integrity guard. Detects DNS interception, AA-flag rewriting, TCP/53 blocking. |
| `posture/cli.py` | Rich terminal rendering, JSON output, remediation mapping. |
| `web/server.py` | FastAPI endpoints, SSE streaming, in-memory cache, per-IP rate limit, `/healthz`. |
| `web/static/` | Single-page UI: `index.html`, `style.css`, `app.js` (SSE consumer). |

## THE ROOT CAUSE PRINCIPLE

Read this before fixing anything. Every significant bug found in this project
so far shares one root cause:

> **The tool trusts a convenient shortcut instead of querying the real
> protocol source of truth.**

Concrete instances already identified:

| Shortcut trusted | Real source of truth |
|---|---|
| RDAP's nameserver list | Parent zone's actual NS delegation |
| A hardcoded list of operator brand names | Observed network topology (ASN, PoP spread) |
| One recursive resolver's cached answer | Consensus across resolvers + authoritative read |
| DNSKEY self-signature | Full DS→DNSKEY→chain-to-root validation |
| `transferProhibited` only | The complete EPP status code set |
| IP-range RDAP registrant string | ASN number |

**When you find a new bug, ask whether it is another instance of this
pattern.** If it is, fix the pattern, not just the symptom. When adding any
new check, ask: "am I reading the authoritative source, or a convenient
proxy for it?"

## NON-NEGOTIABLE RULES

1. **Never emit a false finding.** Three states must remain permanently
   distinct and must never collapse into each other:
   - `not applicable` — the check does not apply to this domain
   - `could not retrieve` — the check applies but data was unobtainable (UNKNOWN)
   - `broken` — the check applies, data was obtained, and it is wrong (FAIL)

   Reporting "absent" when the truth is "unretrievable" is the single worst
   failure mode this tool can have. It has happened before (SPF reported
   absent for Cloudflare and Bandhan Bank because TXT truncated and TCP/53
   was blocked). Do not let it happen again.

2. **Verify against real ground truth. Never assume, never reason from
   memory about what a domain's DNS looks like.** Query it. Every claim in a
   commit message or a code comment about real-world DNS behaviour must be
   backed by an actual query you ran.

3. **Every fix requires a test that fails before the fix and passes after.**
   No exceptions. A fix without a failing-then-passing test is not done.

4. **One bug, one test, one commit.** Do not batch fixes. Batched fixes on
   this codebase have historically introduced regressions (a `checks.py`
   update shipped without its matching `dnsmod.py` broke the whole tool).

5. **Respect the environment self-test.** If `selftest.check_environment()`
   reports the network path is untrustworthy, checks that depend on direct
   nameserver access MUST be suppressed and reported UNKNOWN. Never produce
   a confident finding on an untrustworthy path.

6. **Do not weaken accuracy for convenience.** If a correct implementation is
   slower or more complex, implement it correctly. This tool's entire value
   is that its output can be trusted.

7. **Vendor neutrality in findings.** Findings describe what is true about
   the domain. Remediation guidance should state the general fix first
   ("sign your zone at your current DNS provider"); the VergeCloud capability
   is secondary context, not the primary recommendation. A tool where every
   finding routes to "switch to VergeCloud" reads as a sales funnel and
   destroys the credibility the tool depends on.

## GROUND TRUTH TEST DOMAINS

Verify fixes against these. Expected states confirmed by live query.

| Domain | Expected state | Guards against |
|---|---|---|
| `cloudflare.com` | DNSSEC fully validating; anycast operator; SPF present | DNSSEC false negative |
| `google.com` | DNSSEC **unsigned by choice**; must grade **A overall** (correctness A, hardening B) — NOT D | Grade model punishing non-adoption |
| `dnssec-failed.org` | DNSSEC **broken** (DS present, DNSKEY absent, resolver SERVFAILs) | DNSSEC false positive |
| `example.com` | Null MX (`0 .`) per RFC 7505; wildcard `_domainkey` with empty `p=` (revoked key) | Null-MX handling; DKIM wildcard/revocation |
| `vergecloud.com` | **AS141383, IS anycast.** Two NS ranges, one ASN. Must report **1 operator**, and must NOT be penalised as a single point of failure | The anycast name-list bug; ASN-string-splitting bug |
| `indianbankuat.bank.in` | No MX, no A/AAAA — email auth section must be **skipped entirely**, not FAILed | Email-auth false positives on UAT/staging |
| `indianbank.bank.in` | Parent delegation lists 4 NS; NIXI RDAP under-reports (lists 3) | RDAP-vs-parent-delegation false FAIL |
| `paypal.com` | DNSSEC validating; SPF near the 10-lookup limit | SPF lookup counting |

`.in` and `.co.in` resolve RDAP via NIXI using right-to-left label walking —
there is no separate `co.in` bootstrap entry. Do not regress this.

## KNOWN ENVIRONMENT CONSTRAINTS

- The tool requires **outbound UDP/53, TCP/53 and HTTPS**. TCP/53 is needed
  for AXFR testing and for truncated-response retries.
- On corporate networks and VPNs, DNS is frequently intercepted. The
  self-test exists for this reason. Test on a clean network.
- `web/server.py` `/healthz` returns **503** when the environment is
  degraded. This is correct behaviour, not a bug.

## COMMANDS

```bash
./run_cli.sh example.com              # single check, terminal output
./run_cli.sh example.com --json       # machine-readable
./run_cli.sh example.com --no-info    # hide INFO rows
./run_web.sh                          # web tool on http://127.0.0.1:8000/
pytest                                # test suite (build this first)
pytest -m "not network"               # offline tests only (must pass in CI)
```

## DEPENDENCIES

`dnspython`, `rich`, `requests`, `cryptography`, `fastapi`, `uvicorn[standard]`,
`pydantic`, `slowapi`. All in `requirements.txt`.

`cryptography` is **required** for DNSSEC validation — without it, validation
silently raises ImportError and every signed zone grades "could not determine".

## CURRENT STATE

Version 0.5. **33 known findings** documented in `BUGS.md`, ranging from
critical correctness bugs to missing checks to structural gaps. The tool has
no test suite. Building the test foundation is the first task — see
`INVESTIGATION.md` for the full systematic audit brief and `BUGS.md` for the
prioritised work queue.
