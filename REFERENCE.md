# VergeCloud Domain Posture Checker — Complete Reference

This document describes everything the tool does, every check it runs, every
finding it can produce, the data sources it queries, the scoring model, the
failure modes it handles, and the limitations it has. Nothing is omitted.

---

## What this tool is

A domain posture checker that takes any domain name as input, queries public
DNS and RDAP infrastructure in real time, and produces a structured report
covering registration health, nameserver posture, zone hygiene, core DNS
records, DNSSEC signing status, and email authentication. Every finding is
graded and mapped to a VergeCloud ADNS capability where applicable.

The tool has two entry points — a CLI for terminal use and a FastAPI web tool
with progressive rendering via Server-Sent Events — both powered by the same
check engine. Results are identical between the two.

---

## What this tool is NOT

- Not a vulnerability scanner, penetration tester, or web application
  security scanner.
- Not a continuous monitoring service. It produces a point-in-time snapshot
  each time it runs.
- Not a substitute for a full security assessment. It checks publicly
  observable DNS/RDAP posture only.
- Not authoritative for historical data. It cannot tell you uptime
  percentages, past outages, or trend data.

---

## Data sources

Every piece of data the tool displays comes from one of these sources. No
data is guessed, estimated, or retrieved from proprietary databases.

| Source | What it provides | Protocol | Notes |
|---|---|---|---|
| IANA RDAP bootstrap (`data.iana.org/rdap/dns.json`) | Maps TLDs to their registry's RDAP endpoint | HTTPS | Cached per process lifetime |
| Registry RDAP (e.g. `rdap.verisign.com`, `rdap.nixiregistry.in`) | Registrar, registered NS, domain status codes, creation/expiry dates, registrant redaction status | HTTPS (RDAP) | Not all TLDs have RDAP. `.io`, `.de`, `.jp`, `.cn` currently return UNKNOWN. |
| Live DNS queries to public resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9) | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, DS, DNSKEY records | UDP/53 with EDNS0 (4096-byte buffer) | Falls back through resolvers on failure |
| Direct DNS queries to the domain's own authoritative nameservers | SOA (ground-truth serial), AA flag, response time | UDP/53 direct to NS IP | Only performed when the environment self-test confirms the network path is trustworthy |
| Parent zone delegation query | NS records delegated at the parent zone | UDP/53 to parent zone's NS | The authoritative source for "what a resolver actually sees" |
| IANA IPv4 RDAP bootstrap (`data.iana.org/rdap/ipv4.json`) | Maps IP ranges to their owning RIR's RDAP endpoint | HTTPS | Used for IP-to-network-owner lookups |
| RIR RDAP (APNIC, RIPE, ARIN, etc.) | Network name, country, registrant entities | HTTPS (RDAP) | Fallback for ASN owner when Team Cymru fails |
| Team Cymru DNS whois (`origin.asn.cymru.com`, `AS<n>.asn.cymru.com`) | IP-to-ASN mapping, ASN owner name | DNS TXT queries | Primary source for operator identification. More reliable than IP-range RDAP registrant for leased ranges. |

---

## Checks by section

### Section 1: Registration & delegation

Queries RDAP for the domain's registry record. Falls back to noting
unavailability if the TLD has no RDAP endpoint.

| Check | Statuses | What it looks for |
|---|---|---|
| **Domain resolves** | FAIL | Domain returns NXDOMAIN from SOA/NS/A queries. If this fails, the entire check halts — there is nothing to analyse. |
| **RDAP availability** | UNKNOWN | The TLD has no published RDAP endpoint in the IANA bootstrap. Currently affects `.io`, `.de`, `.jp`, `.cn` and others. |
| **RDAP record** | WARN, UNKNOWN | Registry returned 404, rate-limited (429), or an unexpected error. |
| **Registrar** | INFO | Name of the sponsoring registrar, extracted from the RDAP entity with role `registrar`. Displays "not disclosed" if absent. |
| **Domain age** | INFO | Creation date and days since, from RDAP `registration` event. |
| **Expiry** | PASS, WARN, FAIL | Expiry date from RDAP `expiration` event. FAIL if < 30 days, WARN if < 90 days. A lapsed domain causes total outage. |
| **Transfer lock** | PASS, WARN | Checks for `clientTransferProhibited` in the RDAP status codes. Without it, the domain is easier to hijack via a registrar transfer. |
| **Registrant data** | INFO | Notes if registrant fields are privacy-protected or redacted (common under GDPR). Explicitly labelled as "not a misconfiguration." |

### Section 2: Nameserver posture

Examines the NS set, their reachability, consistency, network diversity,
and response time.

| Check | Statuses | What it looks for |
|---|---|---|
| **Nameserver count** | PASS, FAIL | Number of NS records in the served zone. FAIL if fewer than 2 (RFC 1034 recommends at least two). |
| **Parent delegation vs zone NS** | PASS, FAIL, UNKNOWN | Queries the parent zone's authoritative nameserver for the child's NS delegation and compares it against the NS set actually served by the zone. A mismatch here means resolvers see a different NS set than the zone claims — this is a real delegation error. This is the authoritative check. |
| **RDAP-listed NS vs zone NS** | PASS, WARN | Compares the NS list in the RDAP record against the served zone. This is a paperwork check — RDAP can lag behind actual delegation, especially at some registries (observed at NIXI for `.bank.in`). Mismatches are WARN, not FAIL. |
| **IPv6 (AAAA) on nameservers** | PASS, WARN | Checks whether each NS hostname has an AAAA record. IPv6-only clients depend on AAAA-reachable nameservers. |
| **Nameserver reachability** | PASS, WARN, FAIL, UNKNOWN | Sends a direct SOA query to each NS IP. Checks: did it respond? Did it set the AA (Authoritative Answer) flag? Did it return the zone's SOA? Detects lame delegation (NS delegated but not serving the zone), non-authoritative responses (AA flag missing, may indicate a proxy), and complete unresponsiveness. **Skipped entirely** when the environment self-test detects DNS interception — reports UNKNOWN with an explanation rather than producing false findings. |
| **Nameserver response time** | INFO | Round-trip time in milliseconds for the SOA query to each NS. Sorted fastest to slowest. Explicitly labelled as single-vantage-point measurement, not global performance. Only displayed when the environment is trustworthy enough for per-NS probing. |
| **SOA serial consistency** | PASS, WARN | Compares the SOA serial returned by each NS. Differing serials indicate zone transfer lag — nameservers are serving different versions of the zone. |
| **Nameserver network operator** | INFO | Resolves each NS hostname's IP, then looks up the ASN owner via Team Cymru DNS whois. Displays the AS number and owner name. Explicitly labelled as the network operator, which may differ from the customer-facing DNS brand (e.g. a reseller). |
| **Network diversity** | PASS, WARN, INFO | Counts distinct ASN owners across the NS set. Multiple ASNs = PASS (resilient to a single-network failure). Single ASN = WARN if it is a small/unknown operator, INFO if it is a known large anycast operator (Cloudflare, Google, Amazon, Akamai, etc. — curated list). The INFO case acknowledges that concentration with a large anycast provider is an architectural choice, not a naive single point of failure. |

**Known large anycast operators (curated list, needs periodic review):**
Cloudflare, Google, Amazon, Akamai, Microsoft, Azure, Verisign, NS1, Dyn,
Oracle, Neustar, UltraDNS, Gcore, Fastly, Vercel, DigitalOcean, Alibaba,
Tencent.

### Section 3: SOA & zone hygiene

Examines the SOA record's operational parameters and checks for a wildcard.

| Check | Statuses | What it looks for |
|---|---|---|
| **SOA record** | FAIL | Zone must have an SOA. If missing, the section halts. |
| **Primary nameserver (MNAME)** | INFO | The primary NS from the SOA record. |
| **Zone admin (RNAME)** | INFO | The responsible party's email from the SOA record (encoded as a DNS name). |
| **Serial** | INFO | The zone serial number. |
| **Refresh** | PASS, WARN | How often secondaries check for zone updates. Typical range: 1,200–43,200 seconds (RFC 1912 s2.2). |
| **Retry** | PASS, WARN | How long a secondary waits before retrying after a failed refresh. Typical range: 120–7,200 seconds. |
| **Expire** | PASS, WARN | How long a secondary continues serving the zone after losing contact with the primary. Typical range: 1,209,600–2,419,200 seconds (14–28 days). |
| **Minimum / negative TTL** | PASS, WARN | The negative-caching TTL (how long resolvers cache NXDOMAIN). Typical range: 300–86,400 seconds. |
| **Wildcard record** | PASS, WARN | Queries a random subdomain (`<uuid>.domain`). If it resolves, a wildcard record exists. Wildcards mask NXDOMAIN responses and can hide typos or aid subdomain abuse. |

### Section 4: Core records

Examines the fundamental DNS records at the domain apex.

| Check | Statuses | What it looks for |
|---|---|---|
| **A record** | PASS, WARN | IPv4 address(es) at apex, with TTL. WARN if absent. Flags very low TTL (< 60s, increases resolver query volume) or very high TTL (> 86,400s, slows failover). |
| **A record TTL** | WARN | Only appears when the TTL is outside normal range. |
| **AAAA record (IPv6)** | PASS, WARN | IPv6 address(es) at apex. WARN if absent — IPv6-only clients cannot reach the apex directly. |
| **CNAME at apex** | FAIL | A CNAME must not coexist with other records at the zone apex (RFC 1034 s3.6.2). If present, it is an RFC violation. |
| **MX record** | PASS, INFO | Mail exchange records. INFO "none — domain does not receive mail" if absent. Detects RFC 7505 null MX (`0 .`) and labels it correctly as an explicit declaration that the domain sends and receives no mail. |
| **CAA record** | PASS, WARN | Certificate Authority Authorization. Without CAA, any public CA may issue certificates for the domain (RFC 8659). |

### Section 5: DNSSEC

Checks the DNSSEC signing chain — DS at parent, DNSKEY and RRSIG at child,
and validates the DNSKEY RRset's self-signature.

| Check | Statuses | What it looks for |
|---|---|---|
| **DNSSEC status** | PASS, WARN, FAIL, UNKNOWN | Four distinct states, not a binary. See table below. |
| **DS at parent** | INFO | Whether a DS record exists at the parent zone. |
| **DNSKEY at child** | INFO | Whether the child zone publishes DNSKEY records. |
| **Algorithms** | INFO | Cryptographic algorithms in use (e.g. ECDSAP256SHA256), labelled KSK or ZSK. |
| **Note** | INFO | Additional context — validation failure reasons, rollover caveats. |
| **Caveat** | INFO | When the state is `broken` or `incomplete`, notes that it may be a transient key-rollover state and recommends re-checking. |

**DNSSEC state machine:**

| State | DS at parent | DNSKEY at child | Signature validates | Displayed as | Severity |
|---|---|---|---|---|---|
| `not_configured` | absent | absent | n/a | "Not configured" | FAIL |
| `validating` | present | present | yes | "Configured and validating" | PASS |
| `broken` | present | absent or present | no | "Configured but NOT validating" | FAIL |
| `incomplete` | absent | present | n/a | "Zone signed but no DS at parent" | WARN |
| `unknown` | any | any | inconclusive | "Could not determine" | UNKNOWN |

### Section 6: Email authentication

Checks SPF, DKIM, DMARC, MTA-STS, and TLS-RPT. The scope of checks adapts
to what the domain actually does.

**Applicability rules (added in v0.4 to prevent false positives on non-mail
domains):**

| Has MX? | Has A/AAAA? | What the tool checks |
|---|---|---|
| Yes | Yes | Full check: SPF, DKIM, DMARC, MTA-STS, TLS-RPT |
| Yes | No | Inbound checks: DMARC, MTA-STS, TLS-RPT |
| No (null MX `0 .`) | either | Section skipped — RFC 7505 explicitly declares no mail. INFO note shown. |
| No (absent) | Yes | Sending checks only (SPF, DKIM, DMARC) — missing items graded WARN, not FAIL. MTA-STS/TLS-RPT skipped. |
| No | No | Section skipped entirely — domain publishes no MX and no address records. INFO note shown. |

| Check | Statuses | What it looks for |
|---|---|---|
| **SPF** | PASS, WARN, FAIL, UNKNOWN | Looks for a `v=spf1` TXT record at the apex. FAIL if absent and domain has MX. WARN if absent and domain has no MX (may not be sending). UNKNOWN if TXT records could not be retrieved (truncation without TCP fallback). Detects and FAILs multiple SPF records (RFC 7208 s3.2 permanent error). |
| **SPF DNS lookup count** | PASS, WARN, FAIL | Recursively counts DNS-querying mechanisms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) up to 5 levels deep. RFC 7208 s4.6.4 hard limit is 10. FAIL if exceeded, WARN at 8–10. Displays the lookup trace. |
| **SPF 'all' qualifier** | PASS, WARN, FAIL | Checks the trailing `all` mechanism. `-all` (hardfail) = PASS. `~all` (softfail) = WARN. `?all` / `+all` / missing = FAIL. |
| **DKIM** | PASS, FAIL, UNKNOWN | Probes 26 common selectors via DNS TXT queries at `<selector>._domainkey.<domain>`. See selector list and detection logic below. |
| **DMARC policy** | PASS, WARN, FAIL, UNKNOWN | Checks `_dmarc.<domain>` TXT record. Grading is based on the `p=` policy value: `reject` = PASS, `quarantine` = WARN, `none` = FAIL. Also reports `pct=` (percentage enforcement). |
| **DMARC reporting** | PASS, WARN | Checks for `rua=` (aggregate reporting address). Without rua, you get no visibility into who is sending as your domain. |
| **MTA-STS** | PASS, WARN | Checks for `v=STSv1` TXT record at `_mta-sts.<domain>`. MTA-STS enforces TLS for inbound mail (RFC 8461). Only checked when domain has MX. |
| **TLS-RPT** | PASS, WARN | Checks for `v=TLSRPTv1` TXT record at `_smtp._tls.<domain>`. Only checked when domain has MX. |

**DKIM detection logic:**

DKIM selectors are not discoverable via DNS — there is no registry of which
selectors a domain uses. The tool probes a curated list of 26 common
selectors used by major email providers:

`google`, `default`, `selector1`, `selector2`, `k1`, `k2`, `k3`, `mail`,
`dkim`, `s1`, `s2`, `smtp`, `mandrill`, `everlytickey1`, `zoho`, `zmail`,
`pm`, `mailjet`, `sendgrid`, `sig1`, `litesrv`, `protonmail`, `amazonses`,
`hs1`, `hs2`, `mimecast20220101`

Critical safeguards in the DKIM check:

- **Wildcard detection.** Before probing any real selector, a random canary
  selector is queried. If the canary resolves, a wildcard `*._domainkey`
  record exists and per-selector probing is meaningless — the tool reports
  the wildcard instead of falsely claiming all selectors were found.
- **Revoked key detection.** A DKIM record with `v=DKIM1; p=` (empty public
  key) means the key is revoked per RFC 6376 s3.6.1. The tool reads this
  correctly as a revocation, not as a valid key.
- **"Not found" labelling.** A negative result is always reported as "Not
  found under 26 common selectors" — never "DKIM absent." DKIM absence
  cannot be proven via DNS.

Additional DKIM selectors can be specified via CLI (`--dkim-selector`) or
API (`dkim_selectors` field) for targeted probing.

---

## Scoring model

### Per-section grading

Each section receives an A–F letter grade based on its scored findings.

- Only findings with status PASS, WARN, or FAIL contribute to the grade.
  INFO and UNKNOWN findings are not scored.
- Each scored finding earns: PASS = 2 points, WARN = 1, FAIL = 0.
- The percentage is `total_points / (2 × count_of_scored_findings)`.
- A section with any FAIL and a percentage below 50% grades F.
- A section with any FAIL and a percentage below 75% grades D.
- 95%+ = A, 80%+ = B, 60%+ = C, 40%+ = D, below 40% = F.
- A section with no scored findings (all INFO/UNKNOWN) grades "—" (not graded).

### Overall grading

The overall grade is worst-weighted, not a simple average.

- Formula: `0.6 × worst_section_grade + 0.4 × average_section_grade`, rounded
  to the nearest letter band.
- This means a single F in DNSSEC pulls the overall grade significantly even
  if every other section is A.
- Sections that could not be graded ("—") are excluded from the calculation,
  but their absence is flagged.

### Provisional grades

The overall grade is marked **(provisional)** when any of these are true:

- One or more sections graded "—" (ungraded, excluded from overall).
- One or more findings have status UNKNOWN (data could not be retrieved).
- One or more modules are listed as degraded (environment limitation).

The header explicitly lists which sections are ungraded and which contain
unresolved checks, so the reader knows what is missing.

---

## VergeCloud capability mapping

Each WARN or FAIL finding can map to a VergeCloud ADNS capability. This
mapping is displayed in the "Findings — worst first" summary. The current
mappings are:

| Finding | VergeCloud capability |
|---|---|
| DNSSEC status (not configured / broken) | One-click DNSSEC signing with managed key rollover |
| Nameserver count (< 2) | Redundant anycast nameserver set by default |
| Parent delegation vs zone NS (mismatch) | Onboarding validates parent-side delegation against the served zone |
| Nameserver reachability (unreachable / lame) | Anycast removes single-node reachability failure |
| Network diversity (single small operator) | Distributed anycast network |
| CAA record (absent) | Publish CAA policy from the same control panel |
| SPF (absent) | DNS management simplifies SPF record maintenance |
| SPF DNS lookup count (exceeds 10) | SPF flattening keeps you inside the RFC limit |
| DMARC policy (none / absent) | Host DMARC records and aggregate reporting endpoints |
| AAAA record (absent) | Dual-stack (IPv4 + IPv6) by default |
| IPv6 on nameservers (absent) | Dual-stack nameservers |
| CNAME at apex | Apex aliasing without violating RFC 1034 |
| Expiry (imminent) | Alert on approaching expiry |

Findings without a mapped VergeCloud capability (e.g. SPF qualifier strength,
SOA timer ranges) are still displayed but without a "→ VergeCloud..." line.

---

## Environment self-test

Before running any check, the tool verifies that the network path it is on
can produce trustworthy results. This runs automatically every time.

### What it tests

1. **DNS interception detection.** Sends DNS queries to RFC 5737 / RFC 1918
   addresses that must never respond (192.0.2.1, 203.0.113.99, 198.51.100.42).
   If any of them answer, a transparent DNS proxy is rewriting queries in
   transit. Per-NS probing results would be fabricated.

2. **AA flag trustworthiness.** Queries a known authoritative-only server
   (ns1.google.com for google.com SOA). If the response lacks the AA
   (Authoritative Answer) flag or has the RA (Recursion Available) flag set,
   responses are being rewritten — the tool cannot distinguish authoritative
   from recursive answers.

3. **TCP/53 availability.** Attempts a TCP DNS query. If blocked, truncated
   responses (large TXT record sets, DNSKEY responses) cannot be retried
   over TCP, and the tool may report records as absent when they exist.

### How results are affected

| Environment condition | Effect on results |
|---|---|
| DNS intercepted OR AA flag untrustworthy | Per-NS reachability, authority checks, serial consistency, and response time are **suppressed entirely**. Reported as UNKNOWN with explanation. All other sections (RDAP, record queries via public resolvers, DNSSEC, email auth) still run. |
| TCP/53 blocked | Large TXT record sets (SPF, DKIM, DNSKEY) that truncate beyond 4096-byte EDNS0 buffer are reported as UNKNOWN ("Could not retrieve"), never as absent. |
| Both clean | All checks run with full confidence. |

### Web tool health endpoint

`GET /healthz` runs the self-test and returns HTTP 200 if the environment is
trustworthy, HTTP 503 if it is degraded. This is designed to be used by a
load balancer to keep the tool offline rather than serving wrong data.

---

## Input handling

### Normalisation

- Leading `www.` is stripped (the tool checks the apex domain, not the www
  subdomain). A note is shown.
- URL schemes (`http://`, `https://`), paths, query strings, fragments,
  ports, and userinfo are rejected at the boundary with HTTP 400 (web) or a
  ValueError (CLI). The tool does not silently transform URLs into domains.
- IDN (internationalised domain names) are converted to punycode for
  querying. Both the Unicode and punycode forms are displayed.
- Trailing dots are stripped.
- Input is validated against a strict regex after normalisation.

### Rejected inputs

- URLs (`http://example.com/path`) — rejected, not silently stripped.
- IP addresses (`192.168.1.1`) — rejected.
- Single-label names (`localhost`) — rejected.
- Empty or too-short strings — rejected.
- Strings with `@` (email addresses) — rejected.

---

## Failure modes and how they are handled

Every failure mode discovered during prototyping and real-network testing is
handled explicitly. The tool never silently omits a section or reports a
false finding when a check fails.

| Failure | Detection | User sees | Internal handling |
|---|---|---|---|
| NXDOMAIN | RDAP + DNS both fail | "Domain not found — check spelling or confirm it is registered." | Check halts — no sections after Registration. |
| Authoritative NS timeout | Per-NS SOA query times out | "No response from: [nameserver]" — treated as a finding, not hidden | Lame/unreachable nameservers flagged explicitly. |
| Lame delegation | NS responds but without zone data or AA flag | "Responded without zone data" or "without AA flag" | Distinguished from full unreachability. |
| RDAP not available for TLD | IANA bootstrap has no entry | "No RDAP endpoint published for this TLD" | Registrar section degrades; other sections proceed. |
| RDAP rate-limited | HTTP 429 | "Registry rate-limited the request" | "Temporarily unable to verify registrar data." |
| GDPR-redacted registrant | Registrant fields return redacted markers | "Privacy-protected / redacted — not a misconfiguration" | Separate code path from lookup failure. |
| TXT record truncation without TCP | TC=1 in UDP response, TCP/53 blocked | "Could not retrieve TXT records — not reported as absent" | UNKNOWN status, not FAIL. |
| DNSSEC mid-rollover | Inconsistent key state | "May be a transient key-rollover state — re-check recommended" | Caveat shown; does not hard-FAIL without corroboration. |
| DKIM wildcard `_domainkey` | Random canary selector resolves | "Wildcard _domainkey record present" | Per-selector probing skipped entirely. |
| DKIM empty `p=` (revoked key) | `v=DKIM1; p=` parsed | "Revoked key (empty p=)" | FAIL, not PASS. |
| SPF > 10 DNS lookups | Recursive mechanism counting | "Exceeds limit — SPF fails permanently (RFC 7208 s4.6.4)" | Hard FAIL with lookup trace. |
| Null MX (RFC 7505) | MX record is `0 .` | "Domain explicitly declares it sends and receives no mail" | Entire email auth section suppressed. |
| No MX and no A/AAAA | Record queries return empty | "Skipped — domain publishes no MX and no A/AAAA at apex" | Email auth section suppressed. |
| No MX but has A/AAAA | MX absent, A/AAAA present | Missing SPF/DMARC graded WARN, not FAIL. MTA-STS/TLS-RPT skipped. | "Send-only" mode. |
| ASN owner not resolvable | Team Cymru + RDAP both fail | Network operator shown as the IP or net-name | Graceful degradation. |
| Parent delegation query fails | Parent zone unreachable | "Could not query parent zone" — falls back to RDAP-only comparison | RDAP comparison retained as WARN-level paperwork check. |
| DNS interception detected | Self-test blackhole probe | Per-NS checks suppressed. UNKNOWN with full explanation. | Never produces false reachability/authority findings. |
| Section throws an exception | try/except in run_streaming | "Section error: [exception]" — section marked UNKNOWN | Other sections still run. |

---

## What the tool cannot do (known limitations)

### DNSSEC

- Validates the DNSKEY RRset self-signature only, NOT the full chain of trust
  from root → TLD → domain. A zone with a mismatched DS/DNSKEY pair at the
  TLD boundary would still pass as "validating." Full chain validation is the
  highest-priority hardening item.

### DKIM

- Can only probe 26 common selectors. Custom selectors used by niche ESPs or
  internal mail systems will not be found. "Not found" does not mean "absent."
- Cannot verify that a found DKIM key is actually in use for signing — only
  that the DNS record exists.

### Performance

- Nameserver response time is single-vantage-point only (measured from the
  machine running the check). It reflects the runner's network path, not
  global performance.
- Multi-region latency benchmarking (RIPE Atlas / DomainMON) is designed but
  not built. Requires RIPE Atlas credits with an assigned owner.

### RDAP / WHOIS

- TLDs without RDAP (`.io`, `.de`, `.jp`, `.cn`, and others) return UNKNOWN
  for the entire Registration section. WHOIS text-parsing fallback is not
  implemented.
- RDAP data can lag behind actual delegation at some registries. The tool
  handles this by using parent-side delegation as the authoritative source,
  but the lag is visible as a WARN.

### Domain role inference

- The tool does not infer whether a domain is production, staging, UAT,
  parked, or infrastructure-only. It uses observable signals (presence/absence
  of MX, A, AAAA) to decide which checks apply, but does not attempt to label
  the domain's role.

### SOA timer ranges

- The "typical range" values are from RFC 1912 (1996). Modern CDN-fronted
  domains legitimately use refresh intervals and TTLs outside these ranges.
  The tool does not yet detect CDN-fronted domains and suppress low-TTL
  warnings for them.

### CNAME flattening

- CNAME-at-apex is flagged as an RFC violation. Cloudflare, Route 53 (ALIAS),
  and similar providers use CNAME flattening which is functionally correct but
  syntactically looks like a violation. The tool does not yet detect flattening.

### Anycast detection

- Network diversity is determined by ASN, not by actual PoP/geographic
  distribution. A single ASN on the curated large-anycast list is treated as
  INFO (architectural choice), but the tool cannot verify that the provider's
  anycast is actually deployed for this specific customer.

### Web tool (POC scope)

- No OTP gate, no authentication, no authorization.
- In-memory cache only — restarts wipe state.
- No persistence or shareable result URLs.
- No Redis, no database, no structured logging with correlation IDs.
- Rate limiting is per-IP only (10 checks/minute), no CAPTCHA.
- Progressive rendering depends on real uvicorn + browser; in-process test
  clients batch SSE frames.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Entry points                         │
│                                                             │
│   CLI (run_cli.sh)              Web (run_web.sh)            │
│   posture/cli.py                web/server.py               │
│   Rich terminal output          FastAPI + SSE streaming     │
│                                  Static HTML/JS/CSS UI      │
│                                  In-memory cache             │
│                                  Per-IP rate limit           │
│                                  /healthz env guard          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                     Check engine                            │
│                     posture/checks.py                       │
│                                                             │
│  run()              → full Report (CLI)                     │
│  run_streaming()    → generator of per-section events (web) │
│  grade()            → per-section + overall letter grades   │
│                                                             │
│  Calls these modules in order:                              │
│    1. selftest.py   → environment integrity                 │
│    2. core.py       → RDAP + normalisation                  │
│    3. _registration → registrar, dates, locks               │
│    4. _nameservers  → NS set, delegation, diversity, RTT    │
│    5. _soa          → SOA params, wildcard                  │
│    6. _records      → A/AAAA/MX/CAA/CNAME                  │
│    7. _dnssec       → DS/DNSKEY/RRSIG chain                 │
│    8. _email        → SPF/DKIM/DMARC/MTA-STS/TLS-RPT       │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                     Query modules                           │
│                                                             │
│  dnsmod.py          DNS queries (EDNS0, memoised),          │
│                     per-NS probing, parent delegation,      │
│                     DNSSEC state machine                    │
│                                                             │
│  core.py            RDAP bootstrap + registry lookup,       │
│                     IP-RDAP via IANA bootstrap,              │
│                     Team Cymru ASN owner lookup,             │
│                     domain normalisation + IDN               │
│                                                             │
│  emailauth.py       SPF parser + recursive lookup counter,  │
│                     DKIM selector prober (parallel),         │
│                     DMARC parser, MTA-STS, TLS-RPT          │
│                                                             │
│  selftest.py        Blackhole probe, AA flag check,          │
│                     TCP/53 check                             │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                     External queries                        │
│                                                             │
│  IANA RDAP bootstrap (HTTPS)                                │
│  Registry RDAP endpoints (HTTPS)                            │
│  Public DNS resolvers: 1.1.1.1, 8.8.8.8, 9.9.9.9 (UDP/53) │
│  Direct queries to domain's own NS IPs (UDP/53)            │
│  Parent zone NS delegation queries (UDP/53)                 │
│  RIR RDAP endpoints: APNIC, RIPE, ARIN, etc. (HTTPS)       │
│  Team Cymru DNS whois (UDP/53 TXT queries)                  │
│                                                             │
│  No proprietary APIs. No paid services. No authentication.  │
│  Everything is public infrastructure.                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Files

| File | Purpose | Lines (approx) |
|---|---|---|
| `posture/__init__.py` | Package marker | 0 |
| `posture/checks.py` | Orchestrator: runs all modules, emits findings, computes grades, streaming generator | 710 |
| `posture/cli.py` | CLI renderer: Rich terminal output, JSON mode, findings-worst-first summary | 130 |
| `posture/core.py` | RDAP bootstrap + registry lookup, IP-RDAP, Team Cymru ASN, domain normalisation | 270 |
| `posture/dnsmod.py` | DNS queries (EDNS0, memoised), per-NS probing, parent delegation, DNSSEC validation | 230 |
| `posture/emailauth.py` | SPF parser + recursive lookup counting, DKIM probe, DMARC, MTA-STS, TLS-RPT | 200 |
| `posture/selftest.py` | Network-path integrity: interception detection, AA flag, TCP/53 | 80 |
| `web/server.py` | FastAPI: endpoints, SSE streaming, cache, rate limit, health check, static mount | 280 |
| `web/static/index.html` | Single-page form | 50 |
| `web/static/style.css` | Dark minimal styling | 130 |
| `web/static/app.js` | SSE consumer, progressive section rendering | 140 |
| `run_cli.sh` | CLI launcher (activates venv, runs from correct directory) | 10 |
| `run_web.sh` | Web launcher (activates venv, starts uvicorn) | 10 |
| `requirements.txt` | All Python dependencies | 8 |

---

## Version history

| Version | Changes |
|---|---|
| v0.1 | Initial CLI prototype. RDAP + DNS + DNSSEC + SPF/DKIM/DMARC + CAA. |
| v0.2 | DKIM wildcard/revoked-key detection. ASN registrant-role filtering. IP-RDAP via IANA bootstrap. DNSSEC `cryptography` dependency. Null MX (RFC 7505). Grading-hole fix (provisional flag). Large-anycast operator INFO. Nameserver RTT display. |
| v0.3 | Parent-side delegation as ground truth (replaces RDAP-only NS mismatch). Team Cymru ASN as primary operator source (replaces IP-range RDAP registrant). |
| v0.4 | FastAPI web tool with SSE streaming. Email-auth false-positive fix for non-mail domains (UAT/staging/parked). URL rejection at input boundary. Unified clean bundle with launcher scripts. |

---

## v0.5 — Tier 1 correctness fixes + security posture (this version)

### DNSSEC: real chain validation (was: self-signature only)
The DNSSEC check now verifies **three independent things** instead of one:
1. **DNSKEY self-signature** — the RRSIG over the DNSKEY RRset validates against the zone's own KSK.
2. **DS-matches-DNSKEY** — the DS record published at the *parent* zone matches a digest of the child's KSK. This is the link that anchors the zone into the global chain of trust. A stale or wrong DS here means the zone is broken for every validating resolver, even if its self-signature is perfect. **This was the missing check that made the old "validating A" verdict unreliable.**
3. **AD-bit confirmation** — an independent validating resolver (8.8.8.8) is queried without the CD bit; if it sets the AD (Authenticated Data) flag, the chain to root actually resolves. If it returns SERVFAIL, a real validating resolver rejects the zone.

A zone is only reported "Configured and validating" when the self-signature is valid AND the DS matches AND the resolver check does not contradict it. `dnssec-failed.org` is now correctly caught as **broken** where the old code could not distinguish it.

The DNSSEC section now shows the three sub-results ("DNSKEY self-signature", "DS matches DNSKEY (chain anchor)", "Validating-resolver check (AD bit)") so the verdict is auditable.

### Authoritative vs cached cross-check (new)
Core records are read from public resolvers (the cached view). The tool now additionally reads A/AAAA directly from the authoritative nameserver and reports any disagreement. A mismatch indicates propagation lag, split-horizon DNS, or geo-targeted answers — each a useful finding. Runs only when the environment self-test confirms the path is trustworthy.

### Security posture section (new)
A new section with two checks, both run directly against the authoritative nameservers (and both gated behind the environment self-test):
- **Zone transfer (AXFR)** — tests whether any nameserver allows an anonymous full zone transfer. An open AXFR leaks the entire zone (every subdomain and internal host) to anyone. FAIL if open, PASS if refused by all tested servers, UNKNOWN if TCP/53 is blocked on the running path.
- **Open recursive resolver** — tests whether an authoritative nameserver also answers recursive queries for third-party domains. An open resolver is usable in DNS amplification DDoS attacks. FAIL if open, PASS if not.

### Grade model: correctness vs hardening split
The overall grade previously scored "missing an optional feature" identically to "misconfigured", which gave `google.com` a **D** for not signing DNSSEC (a choice most of the internet shares). The grade is now split:
- **Correctness grade** — genuine misconfigurations only (broken DNSSEC, delegation mismatch, open AXFR, expired domain, multiple SPF records, etc.).
- **Hardening grade** — optional-feature adoption (DNSSEC signing, CAA, MTA-STS, IPv6, DMARC reporting, strict SPF qualifier).
- **Overall** now tracks correctness primarily (80%) with a small hardening nudge (20%). `google.com` now grades **A** overall (correctness A, hardening B) — the honest read: correctly run, not maximally hardened.

### SOA timer ranges modernised
RFC 1912 (1996) predates anycast DNS and CDN fronting. Ranges widened, and when the nameserver operator is a known large anycast provider, short refresh/retry/TTL values are reported as INFO (deliberate design) rather than WARN. `google.com`'s 900s refresh is no longer flagged as a problem.

### New known limitations
- AXFR and open-resolver checks require outbound TCP/53 (AXFR) and direct UDP/53 to nameservers. On paths where these are blocked, the checks report UNKNOWN rather than a false PASS.
- The AD-bit DNSSEC check trusts Google Public DNS (8.8.8.8) as the validating resolver. If that resolver is unreachable, the third validation leg is inconclusive (the DS-match check still stands on its own).
