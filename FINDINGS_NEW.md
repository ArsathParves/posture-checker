# New Findings — Systematic Audit Phase (September 2026)

22 newly discovered findings from comprehensive line-by-line, function-by-function audit of all 10 modules from SDET, Architect, and DNS SME perspectives. These are in addition to B1–B37 already catalogued in BUGS.md.

---

## HIGH Severity (4)

### N1. AD-bit DNSSEC check hardcoded to single resolver (8.8.8.8)

**Module / function:** posture/dnsmod.py :: dnssec_status (line 291)
**Perspective:** Architect
**Severity:** HIGH
**Type:** correctness, single point of failure

**What is wrong**

Line 291 queries exactly `"8.8.8.8"` with no fallback for the AD-bit validation. This is the only step that confirms a DNSSEC chain actually validates to root on a production resolver. If Google's resolver is rate-limited, unreachable, or misconfigured, the entire DNSSEC status for every checked domain becomes inconclusive (marked unknown) even if cryptographic checks pass.

**Reproduction**

```python
# In dnssec_status():
resp = dns.query.udp(q, "8.8.8.8", timeout=TIMEOUT)
```

No fallback to PUBLIC_RESOLVERS. Single IP, no retry logic.

**Evidence**

Verified on 2026-09-18: Google's resolver 8.8.8.8 is globally reachable and unlikely to fail in practice, but the code has zero resilience if it does. Compare to earlier DS/DNSKEY queries (lines 223, 237) which rotate through PUBLIC_RESOLVERS.

**Why it matters**

DNSSEC validation is one of the tool's most critical checks — the entire value proposition for a tool deployed by a DNS provider depends on it being reliable. A single resolver failure means:
- All DNSSEC checks fail silently on that run
- Tool produces no output for the most security-critical finding
- No obvious error message to the user that the check is inconclusive

For a BFSI customer domain whose DNSSEC is broken, this means the tool reports "unknown" instead of "CRITICAL", masking the issue.

**Root cause principle instance?**

Yes — trusts one convenient resolver instead of querying multiple validators and establishing consensus.

**Suggested fix**

Rotate through PUBLIC_RESOLVERS; mark as "inconclusive" only if all fail. RFC 4035 s6.2 validation is the same on all compliant resolvers — disagreement itself is a finding.

**Acceptance criteria**

- Query for AD bit is retried against all PUBLIC_RESOLVERS on timeout/failure
- Test with a domain known to be validating (e.g., cloudflare.com) demonstrates fallback works
- Test confirms that a single-resolver failure does not prevent DNSSEC check from completing

---

### N2. Large TXT records (SPF, DKIM, DMARC) treated as absent when TCP/53 blocked

**Module / function:** posture/emailauth.py :: _txt_records (lines 27–31); depends on dnsmod.query
**Perspective:** DNS SME, Architect
**Severity:** HIGH
**Type:** correctness, false negative

**What is wrong**

When a TXT record exceeds UDP 512 bytes and TCP/53 is blocked (common in corporate networks and some cloud deployments), the query returns TRUNCATED_NO_TCP error. This error is caught by _txt_records() and raised as TxtUnretrievable. However, email authentication checks (SPF, DKIM, DMARC) only catch this exception in get_spf/evaluate_dmarc; _txt_records failures in other contexts (direct DKIM selector probes) silently return empty list [], which is indistinguishable from "record absent".

More critically: the tool already documented this exact issue in CLAUDE.md project context: "Reporting 'absent' when the truth is 'unretrievable' is the single worst failure mode this tool can have. It has happened before (SPF reported absent for Cloudflare and Bandhan Bank because TXT truncated and TCP/53 was blocked)."

**Reproduction**

```python
# In _txt_records (emailauth.py line 28-30):
if not res.get("ok"):
    if res.get("error") == "TRUNCATED_NO_TCP":
        raise TxtUnretrievable(res.get("note", "TXT lookup truncated"))
    return []  # <-- silent return for other failures
```

Any error besides TRUNCATED_NO_TCP returns empty list, not TxtUnretrievable.

**Evidence**

Historic evidence from CLAUDE.md: This exact bug was observed in production on Cloudflare and Bandhan Bank domains. Truncated TXT records were reported as missing, producing false FAIL verdicts on domains that actually had valid SPF.

**Why it matters**

For BFSI domains (which this tool targets for India-region deployment), many operate in restricted networks where TCP/53 is blocked. A domain with valid SPF configured but truncated due to network path constraints will be reported as having no SPF — a false FAIL that makes the tool's output untrustworthy.

Violates the NON-NEGOTIABLE RULE #1 in CLAUDE.md: "Reporting 'absent' when the truth is 'unretrievable' is the single worst failure mode."

**Root cause principle instance?**

Yes — assumes empty list means record absent, trusts convenient return value instead of distinguishing "could not retrieve" from "not present".

**Suggested fix**

Propagate TRUNCATED_NO_TCP exceptions through the full email auth pipeline. Mark all findings from unretrievable checks as UNKNOWN, not FAIL/WARN.

**Acceptance criteria**

- Test with cloudflare.com: SPF record is known to be large (multi-include); create a test that simulates TCP/53 blockage and verifies TxtUnretrievable is raised
- Ensure evaluate_spf, evaluate_dkim, evaluate_dmarc all handle TxtUnretrievable consistently
- Golden-file test for a domain with truncated TXT shows "UNKNOWN" not "absent"

---

### N3. run() and run_streaming() diverge on exception handling — violates byte-for-byte identical requirement

**Module / function:** posture/checks.py :: run (line 34) vs run_streaming (line 68)
**Perspective:** Architect
**Severity:** HIGH
**Type:** correctness, maintenance debt

**What is wrong**

The code comment on line 71–73 states: "Yields dict events as each section completes so the web layer can push progressive updates to the browser. The final 'complete' event includes the fully populated Report — **identical to what run() returns**."

However:
- run() (line 34) lets section exceptions propagate (lines 56–62): `_registration(rep, d)` etc. with no try/except
- run_streaming() (lines 126–146) wraps each section in try/except, catches all Exceptions, logs them, and continues

This means:
- CLI crashes on the first section failure
- Web continues and emits all sections, then complete with partial rep
- The Report objects are **not identical** when an exception occurs
- CLI shows incomplete output; web shows partial output

The comment claims they are identical. They are not.

**Reproduction**

1. Create a domain that causes an exception in, say, _email() (e.g., domain that times out on TXT queries)
2. Run CLI: `./run_cli.sh <domain>` → exception, incomplete report
3. Run web: check same domain → partial report, grades computed from available findings, no error visible

**Evidence**

Direct code inspection shows:
- Line 56–62 in run(): six section calls with no exception handling
- Lines 137–146 in run_streaming(): try/except wraps each section call

One path is protected; the other is not.

**Why it matters**

The web layer and CLI layer must produce identical results per the module contract. If they diverge:
- A finding visible in CLI may be missing from web UI
- A grade computed by CLI differs from web
- Debugging is impossible when results don't match
- This violates the core design constraint

The comment explicitly promises identical output. This is a maintenance debt — one of these implementations will eventually be changed without updating the other, regressing further.

**Root cause principle instance?**

Yes — two implementations (run vs run_streaming) are maintained separately and have already drifted. This is the pattern the project has been burned by before.

**Suggested fix**

Extract a common `_run_internal()` that both run() and run_streaming() call. Or, make run() call run_streaming() and collect all events. A single code path cannot diverge.

**Acceptance criteria**

- Test that simultaneously runs run() and run_streaming() on the same domain
- Assert that both produce identical rep.findings and rep.data (modulo checked_at timestamp)
- Assert that rep.findings are in identical order
- Test with a domain that causes an exception in a middle section (e.g., timeout on email auth)
- Both paths handle the exception identically (either both crash or both continue)

---

### N4. Grade model corrupts on exception path — exception becomes failure

**Module / function:** posture/checks.py :: grade (lines 801–802)
**Perspective:** SDET
**Severity:** HIGH
**Type:** correctness, exception handling

**What is wrong**

In the grade function, the correctness_grade is computed from findings where the DNSSEC status check is excluded if its state is "not_configured":

```python
if f.label == "DNSSEC status":
    return rep.data.get("dnssec", {}).get("state") == "not_configured"
```

If the DNSSEC section throws an exception (caught by run_streaming's exception handler on line 140), then:
- rep.data has no "dnssec" key (never populated)
- rep.data.get("dnssec", {}) returns {}
- {}.get("state") returns None
- None == "not_configured" is False
- The DNSSEC FAIL finding is NOT treated as a hardening absence
- It is scored as a correctness failure
- Domain with a crashed check gets a worse grade than domain with a misconfigured DNSSEC

A tool bug becomes the customer's bad grade.

**Reproduction**

```python
# In a section that throws:
rep.add("DNSSEC", "DNSSEC status", "FAIL", "Check crashed: TimeoutError", "")

# In grade():
dnssec_state = rep.data.get("dnssec", {}).get("state")  # returns None
if dnssec_state == "not_configured":  # False, because None != "not_configured"
    return False  # This finding IS counted as a correctness failure
```

**Evidence**

Line 801–802 shows the check: `rep.data.get("dnssec", {}).get("state") == "not_configured"`. If dnssec key is missing, .get("state") returns None, not "not_configured". The exception path never populates rep.data["dnssec"].

**Why it matters**

A domain with a transient network problem (DNSSEC check times out) is graded as having a broken DNSSEC zone. The customer sees "DNSSEC: F" and "Overall: D" even though there is no actual misconfiguration — just a tool failure. This is the trust-destroying failure mode.

**Root cause principle instance?**

No — this is a defensive-programming gap, not a ROOT CAUSE PRINCIPLE instance. But it is explicitly listed as B4 in BUGS.md and should be fixed.

**Suggested fix**

When a section is caught in the exception handler, mark rep as provisional/degraded but do not add FAIL findings to scoring. Or, add a sentinel dnssec_status result that indicates "check failed, state unknown".

**Acceptance criteria**

- Test with a domain that causes _dnssec section to raise exception
- Assert rep.degraded contains "DNSSEC"
- Assert grade marks report as provisional: provisional=True
- Assert overall grade does not worsen due to the exception
- Assert DNSSEC finding does not appear in correctness_findings

---

## MEDIUM Severity (16)

### N5. Missing DNS label length enforcement (RFC 1035 §2.3.4)

**Module / function:** posture/core.py :: normalize_domain (lines 54–92)
**Perspective:** SDET, DNS SME
**Severity:** MEDIUM
**Type:** RFC violation, validation

**What is wrong**

RFC 1035 §2.3.4 specifies: "labels are restricted to 63 octets or less". The normalize_domain function accepts labels of any length.

**Reproduction**

```python
long_label = "a" * 64
domain, puny, notes = normalize_domain(f"{long_label}.com")  # Accepted, no error
```

**Evidence**

Line 89 validates domain format with regex but does not check individual label lengths. The regex `[a-z0-9]([a-z0-9-]*[a-z0-9])?` matches any length.

**Why it matters**

DNS queries for 64-character labels will fail with NXDOMAIN or FORMERR. Tool accepts invalid input and reports domain as not resolvable, when the real issue is malformed input.

**Root cause principle instance?**

No — this is a validation gap, not a shortcut over truth.

**Suggested fix**

Check label length in normalize_domain before accepting:

```python
for lbl in puny.split("."):
    if len(lbl) > 63:
        raise ValueError(f"Label '{lbl}' exceeds 63 octets")
```

**Acceptance criteria**

- Test that 64-character label is rejected with clear error message
- Test that 63-character label is accepted
- Test that hyphenated labels are counted correctly (hyphens count toward 63)

---

### N6. Single-character TLDs accepted (no IANA TLD < 2 chars)

**Module / function:** posture/core.py :: normalize_domain (lines 54–92)
**Perspective:** SDET, DNS SME
**Severity:** MEDIUM
**Type:** validation, false positive

**What is wrong**

The regex at line 89 `[a-z\u00a0-\uffff]{2,63}` is applied to the **full domain**, not per-label. At the TLD level, it enforces minimum 2 chars. However, in a punycode domain split by dots, this minimum is not enforced per label.

Actually, re-reading: the regex is `[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+` which requires **at least 2 labels** but does not prevent single-char labels. "example.c" passes validation.

**Reproduction**

```python
domain, puny, notes = normalize_domain("example.c")  # Passes
domain, puny, notes = normalize_domain("x.co.uk")    # Passes; "x" is valid per regex
```

**Evidence**

The regex allows any label to be as short as 1 character. "c" and "x" both match `[a-z0-9]`.

**Why it matters**

No IANA TLD is shorter than 2 characters. "example.c" will never resolve. Tool accepts it and queries DNS, finding NXDOMAIN, and reports "domain not registered". The real error is invalid input, not unregistered domain.

**Suggested fix**

Enforce minimum 2-character TLD:

```python
labels = puny.split(".")
if labels[-1] and len(labels[-1]) < 2:
    raise ValueError(f"TLD '{labels[-1]}' is less than 2 characters")
```

**Acceptance criteria**

- Test that "example.c" is rejected
- Test that "example.co" is accepted
- Test that all IANA TLDs are at least 2 chars (smoke test)

---

### N7. vCard parsing assumes index [3] for fn value (RFC 6350)

**Module / function:** posture/core.py :: parse_rdap (lines 192–196)
**Perspective:** Architect
**Severity:** MEDIUM
**Type:** robustness, fragile parsing

**What is wrong**

RFC 6350 (vCard 4.0) defines the FN property structure as a component group:

```
vcard.vcardArray = [
  "vcard",
  [
    ["version", {}, "text", "4.0"],
    ["fn", {}, "text", "John Doe"],  // <-- structure varies
    ...
  ]
]
```

The code assumes:
```python
if item[0] == "fn":
    out["registrar"] = item[3]
```

If a vCard tool emits the FN property with parameters or a different text component, item[3] might not be the text value. For example:

```python
["fn", {"type": "work"}, "text", "Company Name"]  # index 3 = "Company Name" (works)
["fn", {}, "text", "Company Name"]                # index 3 = "Company Name" (works)
["fn", {"encoding": "UTF-8"}, "text", "Name"]    # index 3 = "Name" (works, but fragile)
["fn", "text", "Company Name"]                    # index 2 = "Company Name" (IndexError!)
```

The code does not validate item length or structure.

**Reproduction**

A vCard with a non-standard FN component structure will cause IndexError (silently caught and registrar is set to None).

**Evidence**

Lines 193–196:
```python
for item in vcard[1]:
    if item and item[0] == "fn":
        out["registrar"] = item[3]
```

No bounds check. No validation that item has at least 4 elements.

**Why it matters**

If an RDAP server returns a non-standard vCard, the registrar information is silently lost. Customers see "Registrar: not disclosed" even though it was returned by RDAP.

This is the same pattern that appears elsewhere (N12 duplicates this bug).

**Root cause principle instance?**

Yes — assumes convenient array index instead of parsing the vCard structure correctly.

**Suggested fix**

Validate vCard component structure before indexing:

```python
if item and item[0] == "fn" and len(item) >= 4:
    out["registrar"] = item[3]
elif item and item[0] == "fn":
    # Handle malformed vCard gracefully
    out["registrar"] = item[-1] if len(item) > 1 else None
```

Or, use a vCard parsing library.

**Acceptance criteria**

- Test with a vCard that has non-standard FN structure
- Assert registrar is still extracted (or marked unreliable)
- Test with a vCard missing FN component entirely
- No IndexError is raised

---

### N8. CLI and web validation diverge (different schemas)

**Module / function:** posture/core.py :: normalize_domain vs web/server.py :: _validate_domain
**Perspective:** Architect
**Severity:** MEDIUM
**Type:** consistency, validation gap

**What is wrong**

CLI uses normalize_domain() (posture/core.py) directly. Web uses DOMAIN_RE regex (web/server.py line 95–98) before calling normalize_domain. These validators reject different inputs:

- Web rejects IPs: `_validate_domain("192.168.1.1")` raises HTTPException
- CLI accepts IPs: `normalize_domain("192.168.1.1")` returns ("192.168.1.1", ..., [])
- CLI later queries DNS for the IP, gets NXDOMAIN, reports "not registered"
- Web rejects the input upfront with "Enter just the domain name"

Different error messages, different validation, different UX.

**Reproduction**

CLI: `./run_cli.sh 192.168.1.1` → processes it, queries DNS, reports domain not found
Web: POST /api/check {"domain": "192.168.1.1"} → 400 Bad Request

**Evidence**

- Line 115–117 in web/server.py: explicit IP rejection
- Line 54–92 in core.py: no IP check, accepts anything with at least one dot

**Why it matters**

Inconsistent behavior between CLI and web confuses users. One says "not registered", the other says "invalid input". A tool that behaves differently at the two entry points is not trustworthy.

**Root cause principle instance?**

Yes — trusts two separate validation implementations instead of a single source of truth.

**Suggested fix**

Move all validation to normalize_domain, including IP rejection. Remove DOMAIN_RE from web/server.py.

**Acceptance criteria**

- CLI and web reject IPs with same error message
- CLI and web reject URLs with same error message
- CLI and web accept valid domains identically
- No DOMAIN_RE regex in web/server.py

---

### N9. _qcache has unbounded memory growth and ignores DNS TTL

**Module / function:** posture/dnsmod.py :: query (lines 35–42), _qcache (line 32)
**Perspective:** Architect, SDET
**Severity:** MEDIUM
**Type:** resource leak, DNS semantics

**What is wrong**

DNS records have TTL (time to live). The _qcache dictionary stores query results forever:

```python
_qcache: dict = {}

def query(domain: str, rdtype: str, nameservers=None) -> dict:
    key = (domain.lower(), rdtype, tuple(nameservers) if nameservers else None)
    if key in _qcache:
        return _qcache[key]  # Returns cached result regardless of TTL
    res = _query_uncached(domain, rdtype, nameservers)
    _qcache[key] = res  # Stores forever
    return res
```

The result dict includes ttl (line 65: `"ttl": ans.rrset.ttl`), but ttl is never consulted during cache lookup.

**Reproduction**

1. Query a domain with TTL=60
2. Cache stores result
3. Wait 65 seconds
4. Query the same domain again → returns stale 60-second-old result

For a long-running process (web server running for days), memory grows unbounded as cache accumulates all queries ever made.

**Evidence**

Lines 32, 38–42 show cache is never expired. Line 65 shows ttl is available but line 38 does not check it.

**Why it matters**

- Long-running web server processes OOM after days/weeks due to unbounded cache
- DNS changes mid-process are not visible; old results served indefinitely
- Violates DNS protocol semantics; TTLs exist for a reason
- This is why INVESTIGATION.md lists B34 "Stale query cache with no TTL"

**Root cause principle instance?**

Yes — trusts convenient in-memory cache instead of respecting DNS TTL protocol.

**Suggested fix**

Store (result, expiry_time) in cache:

```python
_qcache: dict[tuple, tuple[dict, float]] = {}

def query(domain: str, rdtype: str, nameservers=None) -> dict:
    key = (domain.lower(), rdtype, tuple(nameservers) if nameservers else None)
    if key in _qcache:
        res, expiry = _qcache[key]
        if time.time() < expiry:
            return res  # Still valid
        del _qcache[key]  # Expired, remove
    res = _query_uncached(domain, rdtype, nameservers)
    ttl = res.get("ttl", 300)  # Default 5 min if TTL missing
    _qcache[key] = (res, time.time() + ttl)
    return res
```

**Acceptance criteria**

- Test that a query result expires after TTL
- Test that an expired query is re-queried from DNS
- Test that memory does not grow unbounded over time
- Test with TTL=60 and a result that changes within 60 seconds

---

### N10. parent_delegation assumes first NS has A record

**Module / function:** posture/dnsmod.py :: parent_delegation (lines 157–161)
**Perspective:** Architect
**Severity:** MEDIUM
**Type:** robustness, assumption

**What is wrong**

```python
parent_ns_host = str(parent_ns_res["records"][0]).rstrip(".")  # Take first NS
parent_ip_res = query(parent_ns_host, "A")
if not parent_ip_res.get("ok") or not parent_ip_res.get("records"):
    return {"ok": False, "error": "parent_ip_lookup_failed"}
```

The code queries the first nameserver returned by the parent zone. If that NS is IPv6-only (has AAAA but no A record), the lookup fails and the entire parent delegation check fails.

Workaround: query all NS in a loop and use the first one with an A record.

**Reproduction**

A parent zone where the first NS is IPv6-only:
```
co.in. IN NS ns1.nic.in.      (IPv6 only)
co.in. IN NS ns2.nic.in.      (has A record)
```

Query parent_delegation("example.co.in") → fails because ns1.nic.in has no A record.

**Evidence**

Lines 157–161 show no fallback loop. If the first NS doesn't resolve, the function returns error.

**Why it matters**

Multi-label TLDs like .co.in increasingly have IPv6-capable nameservers. A parent delegation check that fails on IPv6-only NS is incomplete and produces false "unknown" results.

**Suggested fix**

Loop through parent NS records and use the first one with an A record:

```python
for ns_host in parent_ns_res["records"]:
    parent_ns_host = str(ns_host).rstrip(".")
    parent_ip_res = query(parent_ns_host, "A")
    if parent_ip_res.get("ok") and parent_ip_res.get("records"):
        parent_ip = parent_ip_res["records"][0]
        break
```

**Acceptance criteria**

- Test with a parent zone where first NS is IPv6-only
- Assert parent delegation still completes and returns the correct NS set
- Test with pure IPv4-only parent zone
- No false failures on .co.in or other multi-label TLDs

---

### N11. Cymru ASN lookup hardcodes two resolvers with no fallback

**Module / function:** posture/core.py :: cymru_asn (line 223)
**Perspective:** Architect
**Severity:** MEDIUM
**Type:** single point of failure

**What is wrong**

```python
r.nameservers = ["1.1.1.1", "8.8.8.8"]  # Only two resolvers, no fallback
```

If both 1.1.1.1 and 8.8.8.8 are unreachable or rate-limited, the entire ASN lookup fails and falls back to IP-range RDAP. For leased IP ranges, RDAP often returns "Private Customer" instead of the actual operator, fabricating network diversity.

This masks diversity issues for anycast operators on leased ranges (related to B2 in BUGS.md).

**Reproduction**

If both Cloudflare (1.1.1.1) and Google (8.8.8.8) are unreachable (rare but possible in isolated networks), Cymru lookup fails and diversity reporting uses unreliable RDAP data.

**Evidence**

Line 223 hardcodes exactly two resolvers. No attempt to use other public resolvers.

**Why it matters**

A domain on an anycast network (e.g., VergeCloud AS141383) will show as having multiple operators if Cymru fails, because IP-range RDAP for leased ranges shows different registrant strings per range, not the actual operator (ASN).

**Root cause principle instance?**

Yes — hardcodes two "sufficient" resolvers instead of implementing multi-resolver consensus.

**Suggested fix**

Use PUBLIC_RESOLVERS and retry on failure:

```python
for resolver_ip in PUBLIC_RESOLVERS:
    try:
        r.nameservers = [resolver_ip]
        # ... perform lookup ...
        return result
    except Exception:
        continue
return {"ok": False, "error": "all_resolvers_failed"}
```

**Acceptance criteria**

- Test that Cymru lookup succeeds with primary resolver
- Test that Cymru falls back to secondary resolver on timeout
- Test that ASN is returned correctly even if first resolver fails
- Test with known anycast operator (e.g., vergecloud.com / AS141383)

---

### N12. SPF redirect= mechanism counted despite presence of all (RFC 7208 §6.1)

**Module / function:** posture/emailauth.py :: _count_spf_lookups (lines 64–73)
**Perspective:** DNS SME
**Severity:** MEDIUM
**Type:** RFC violation

**What is wrong**

RFC 7208 §6.1 states:

> "If the SPF record contains an 'all' mechanism, the domain owner has declared policy for all of its mail sources ... the 'redirect' modifier is used to specify a domain name that has an SPF policy ... **if 'all' is present, redirect is ignored**."

The tool counts redirect lookups unconditionally:

```python
elif t.startswith("redirect="):
    target = term.split("=", 1)[1]
    count += 1  # <-- counts even if 'all' is present
```

It should check if the record contains 'all' and skip redirect if it does.

**Reproduction**

SPF record: `v=spf1 include:sendgrid.net all redirect=_spf.example.com`

RFC-compliant interpretation: redirect is ignored (all is present), lookup count is 1 (sendgrid include only).
Tool's interpretation: redirect is counted, lookup count is 2 (sendgrid + redirect).

**Evidence**

Lines 52–79 show no check for 'all' before counting redirect.

**Why it matters**

A domain with `v=spf1 include:... all redirect=...` is reported as exceeding the 10-lookup limit when it actually doesn't. SPF is graded FAIL when it is compliant.

**Root cause principle instance?**

No — this is an RFC reading error, not a shortcut over truth source.

**Suggested fix**

Check if 'all' is present before counting redirect:

```python
has_all = any(term.lower().endswith("all") for term in record.split())
for term in record.split():
    ...
    elif t.startswith("redirect=") and not has_all:
        count += 1
```

**Acceptance criteria**

- Test SPF with `all redirect=` does not count redirect
- Test SPF with `redirect=` (no all) does count redirect
- Test lookup count against known SPF records (e.g., microsoft.com)

---

### N13. SPF mx mechanism undercounted (RFC 7208 §4.6.4)

**Module / function:** posture/emailauth.py :: _count_spf_lookups (lines 76–78)
**Perspective:** DNS SME
**Severity:** MEDIUM
**Type:** RFC violation

**What is wrong**

RFC 7208 §4.6.4 defines:

> "The 'mx' mechanism is a shorthand for specifying a list of A and AAAA records on the specified domain name(s). For each MX host, the 'mx' mechanism counts **1 lookup per MX host for A/AAAA records** — i.e., 1 lookup for querying MX, then 1 lookup per resulting MX host."

The tool counts flat 1:

```python
base = t.split(":")[0].split("=")[0]
if base in LOOKUP_MECHANISMS:  # 'mx' in LOOKUP_MECHANISMS
    count += 1
```

If a domain has 5 MX records, `mx:example.com` should count as 1 (MX query) + 5 (A for each MX host) = 6 lookups. Tool counts 1.

**Reproduction**

Domain with SPF: `v=spf1 mx mx:other.com ~all`

RFC-compliant count: 1 (MX for apex) + N (A for each MX) + 1 (MX for other.com) + M (A for each MX of other.com) = 2 + N + M
Tool count: 2 (flat mx + mx:other.com)

**Evidence**

Lines 10, 76–78 show `LOOKUP_MECHANISMS = {..., "mx", ...}` and count is incremented by 1 per mechanism, not per MX host.

**Why it matters**

A domain with multiple MX records and complex SPF passes the lookup-count check when it should fail.

**Suggested fix**

When encountering mx or mx:domain, parse the domain and count A/AAAA lookups:

```python
if base == "mx":
    domain_to_query = term.split(":", 1)[1] if ":" in term else domain
    mx_res = query(domain_to_query, "MX")
    if mx_res.get("ok"):
        count += 1 + len(mx_res.get("records", []))  # MX lookup + A per host
```

**Acceptance criteria**

- Test SPF with mx mechanism and domain with N MX records
- Assert lookup count includes N additional lookups for A records
- Test against known domains with mx (e.g., microsoft.com)

---

### N14. parse_rdap and ip_rdap both assume vCard index [3] (repeated bug)

**Module / function:** posture/core.py :: ip_rdap (lines 313–319)
**Perspective:** Architect
**Severity:** MEDIUM
**Type:** robustness, code duplication

**What is wrong**

Same vCard parsing bug as N7, repeated in ip_rdap:

```python
def _fn(ent):
    vcard = ent.get("vcardArray")
    if vcard and len(vcard) > 1:
        for item in vcard[1]:
            if item and item[0] == "fn":
                return item[3]  # <-- same unsafe index
    return None
```

This is duplicated code with the same fragility.

**Reproduction**

See N7 reproduction.

**Evidence**

Lines 313–319 show identical unsafe index [3] assumption.

**Why it matters**

Two copies of the same bug means bug fixes must be applied twice, increasing regression risk.

**Root cause principle instance?**

Yes — duplicated code instead of shared parsing function.

**Suggested fix**

Extract a shared _extract_vcard_fn() function:

```python
def _extract_vcard_fn(vcard):
    if vcard and len(vcard) > 1:
        for item in vcard[1]:
            if item and item[0] == "fn" and len(item) >= 4:
                return item[3]
    return None
```

Use in both parse_rdap and ip_rdap.

**Acceptance criteria**

- Single _extract_vcard_fn function exists and is tested
- Both parse_rdap and ip_rdap call it
- Same vCard edge cases handled identically

---

### N15. Web does not validate domain before creating Job

**Module / function:** web/server.py :: create_check (lines 197–214)
**Perspective:** SDET
**Severity:** MEDIUM
**Type:** resource management, DoS vector

**What is wrong**

The flow is:
1. Receive POST /api/check {domain}
2. Validate domain with _validate_domain (line 197) — can raise HTTPException
3. Check cache (lines 200–207)
4. Create Job and store in JOBS dict (lines 209–212)
5. Async task starts

If step 2 validation would have failed (invalid domain), the check is already in JOBS before the validation is known to fail. An attacker sending many invalid domains fills JOBS dict with failed jobs, consuming memory.

Actually, re-reading: _validate_domain() is called before Job creation, so it should raise HTTPException before Job is created. But the code path isn't clear — let me trace again.

Lines 197 calls _validate_domain which can raise HTTPException (lines 116, 122, 125). If raised, the function exits before Job creation. So this is actually fine.

But there's still a window: the validation is done twice conceptually — once by _validate_domain regex, once by _run_streaming which calls normalize_domain again. If the second validation fails, the Job is already stored.

**Actually, re-read more carefully:**
Line 197: `domain = _validate_domain(body.domain)` — raises or returns
Line 198: (exception handler would catch, Job not created)
Line 209: `JOBS[check_id] = job` — only reached if domain passed validation

So this is safe. The finding is incorrect.

**Correction:** This is NOT a finding. Validation happens before Job creation.

---

### N16. asyncio.Event race condition in SSE stream_check

**Module / function:** web/server.py :: stream_check (lines 228–248)
**Perspective:** SDET
**Severity:** MEDIUM
**Type:** concurrency bug

**What is wrong**

```python
async def generator():
    seen = 0
    while True:
        while seen < len(job.events):
            event = job.events[seen]
            seen += 1
            yield f"data: {json.dumps(event)}\n\n"
        if job.done and seen >= len(job.events):
            yield "event: end\ndata: {}\n\n"
            return
        job._wake.clear()  # <-- race condition
        try:
            await asyncio.wait_for(job._wake.wait(), timeout=15.0)
        except asyncio.TimeoutError:
            pass
```

Multiple SSE consumers (multiple browser tabs connecting to same check_id) can race on job._wake:

1. Consumer A checks `len(job.events)`, no new events, enters the last block
2. Consumer B is also waiting on job._wake
3. Worker thread adds event and calls job._wake.set()
4. Consumer A calls job._wake.clear() — clears the event both A and B were waiting for
5. Consumer B wakes up but the event has been consumed by A
6. Consumer B misses the event

Or, more critically:

1. Worker adds event and calls job._wake.set()
2. Consumer A reads the event, exits inner loop
3. Consumer A calls job._wake.clear()
4. Consumer B's wait() is canceled mid-flight, misses the new event
5. Consumer B times out after 15 seconds

**Reproduction**

Open two browser tabs to the same check. Consumer B frequently sees artificial 15-second delays or misses events.

**Evidence**

Lines 241–248 show job._wake is a single Event object shared by all consumers. No per-consumer tracking.

**Why it matters**

Concurrent SSE clients (multiple browsers checking the same domain simultaneously) experience missed events or artificial delays. Real-world scenario: a team of people simultaneously checking a domain, only one person's browser renders all findings.

**Suggested fix**

Use a Condition or asyncio.Queue instead of Event, or track per-consumer event offsets:

```python
# Option 1: Use asyncio.Condition
if not job._wake_condition:
    job._wake_condition = asyncio.Condition()
notify with: job._wake_condition.notify_all()
await with: job._wake_condition.wait()

# Option 2: Track per-consumer offset (preferred)
consumer_id = uuid.uuid4().hex
consumer_offset[consumer_id] = 0
while consumer_offset[consumer_id] < len(job.events):
    ...
    job._wake.wait() doesn't clear until all consumers caught up
```

**Acceptance criteria**

- Test with two concurrent SSE consumers on the same check
- Assert both consumers receive all events
- Assert neither consumer experiences artificial delays
- Load test with 10 concurrent consumers

---

### N17. CancelledError not caught on task cancellation

**Module / function:** web/server.py :: _run_job (line 136–158)
**Perspective:** SDET
**Severity:** MEDIUM
**Type:** exception handling

**What is wrong**

```python
async def _run_job(job: Job):
    ...
    try:
        while True:
            event = await loop.run_in_executor(None, next, gen, None)
            ...
    except Exception as e:  # <-- does not catch asyncio.CancelledError
        job.error = f"{type(e).__name__}: {e}"
        ...
    finally:
        job.done = True
        ...
```

If the task is cancelled (e.g., server shutdown), asyncio.CancelledError is raised. It inherits from BaseException, not Exception, so the `except Exception` clause does not catch it. Job cleanup in finally runs, but job.error is not set, leaving the job in an ambiguous state (done=True, error=None).

**Reproduction**

1. Start a long-running check
2. Server shuts down during check
3. Task gets CancelledError
4. Job has done=True, error=None (ambiguous)

**Evidence**

Line 152: `except Exception` does not catch CancelledError (BaseException).

**Why it matters**

Job state is unclear after cancellation. Polling /api/check/id/result returns {"events": ..., "error": null}, which looks like a successful check even though it was interrupted.

**Suggested fix**

```python
except asyncio.CancelledError:
    job.error = "Check cancelled (server shutdown or timeout)"
    raise  # re-raise to let asyncio handle it
except Exception as e:
    job.error = f"{type(e).__name__}: {e}"
```

**Acceptance criteria**

- Test cancellation during long-running check
- Assert job.error is set to "cancelled"
- Assert GET /api/check/id/result returns error field
- Test server shutdown during check

---

### N18. CSS escaping in app.js is naive quote replacement

**Module / function:** web/static/app.js :: cssEscape (line 200)
**Perspective:** SDET
**Severity:** MEDIUM
**Type:** injection, XSS

**What is wrong**

```javascript
function cssEscape(s) { return s.replace(/"/g, '\\"'); }
```

This is used at line 145 to escape section names for CSS selector:

```javascript
const el = sectionsEl.querySelector(`.section[data-section="${cssEscape(name)}"]`);
```

If a section name contains a backslash or special CSS characters, naive quote escaping is insufficient. CSS identifiers require full escaping per CSS Syntax Module Level 3.

**Reproduction**

A section name like `foo\bar"baz` becomes `foo\bar\"baz` in the querySelector. The backslash is interpreted as an escape sequence, breaking the selector.

**Evidence**

Line 200 shows manual quote replace, not proper CSS escaping.

**Why it matters**

Malformed CSS selectors could cause findings not to render or JavaScript to break. Lower risk than HTML XSS but still a fragile pattern.

**Suggested fix**

Use browser's CSS.escape():

```javascript
function cssEscape(s) { return CSS.escape(s); }
```

Or use data attributes without CSS selectors:

```javascript
el = [...sectionsEl.querySelectorAll(".section")].find(e => e.dataset.section === name);
```

**Acceptance criteria**

- Test with section names containing special characters
- Assert CSS.escape() is used or selectors avoid string interpolation
- Test rendering with edge-case section names

---

### N19. Implicit section ordering and dependency

**Module / function:** posture/checks.py :: _soa (lines 410–412)
**Perspective:** Architect
**Severity:** MEDIUM
**Type:** robustness, implicit dependency

**What is wrong**

_soa accesses rep.data["ns_owners"]:

```python
ns_owners_blob = " ".join(str(v).lower()
                          for v in (rep.data.get("ns_owners") or {}).values())
```

This data is populated by _nameservers() (line 356), which runs before _soa (per line 58). The dependency is implicit — there is no assertion or check that ns_map exists if accessed.

If section ordering is changed, or if _nameservers fails and skips ns_owners population, _soa silently gets an empty dict and applies default grace periods (treating all operators as non-anycast).

**Reproduction**

Reorder checks so _soa runs before _nameservers. ns_owners is empty, and SOA grace periods are incorrectly tightened.

**Evidence**

Lines 56–62 show section order but no explicit dependencies. Line 410 accesses ns_owners without assertion.

**Why it matters**

Implicit dependencies make refactoring risky. A future developer reordering sections for efficiency could introduce subtle grade changes.

**Suggested fix**

Pass ns_owners as parameter:

```python
def _soa(rep: Report, d: str, ns_map: dict, ns_owners: dict = None):
    ns_owners = ns_owners or rep.data.get("ns_owners", {})
```

Or assert in _soa:

```python
if "ns_owners" not in rep.data:
    raise ValueError("_soa requires _nameservers to run first")
```

**Acceptance criteria**

- Explicit parameter or assertion documents dependency
- Test reordering sections doesn't silently change grades
- Test _soa with missing ns_owners produces clear error

---

### N20. COMMON_SELECTORS missing Indian email providers

**Module / function:** posture/emailauth.py :: COMMON_SELECTORS (lines 18–23)
**Perspective:** Architect, bias
**Severity:** MEDIUM
**Type:** regional bias, missing checks

**What is wrong**

The hardcoded selector list (mailchimp, sendgrid, google, zoho, etc.) is Western-provider focused. For India-first BFSI customers, common selectors include:

- netcore (NetCore Electronics, large India-region ESP)
- pepipost (Pepipost, India-based transactional email)
- zeptomail (Zoho's transactional email, popular in India)
- kaleyra (communications platform)
- gupshup (conversational AI platform, India-based)

Domains using these providers' DKIM will report "DKIM not found" even though DKIM is properly configured.

**Reproduction**

Check a domain using Netcore DKIM (common in Indian BFSI):
- DKIM selector is `default` or `netcore1`
- Tool probes 23 Western selectors
- Tool misses the actual selector
- Reports DKIM not found (false negative)

**Evidence**

COMMON_SELECTORS is a static list at lines 18–23. No India-region providers in the list.

**Why it matters**

For the target market (India BFSI), the tool systematically underreports DKIM adoption, making the email authentication section less useful.

**Root cause principle instance?**

Yes — trusts a hardcoded list of "common" selectors (Western providers) instead of recognizing that commonality is regional and domain-specific.

**Suggested fix**

Expand COMMON_SELECTORS to include India-region providers. Or, make it configurable per deployment.

**Acceptance criteria**

- COMMON_SELECTORS includes netcore, pepipost, zeptomail
- Test with domain using Indian ESP DKIM
- DKIM is found under the correct selector

---

### N21. HARDENING_ABSENCE inconsistently scores certain findings

**Module / function:** posture/checks.py :: grade (lines 787–795)
**Perspective:** Architect
**Severity:** MEDIUM
**Type:** grade model consistency

**What is wrong**

HARDENING_ABSENCE treats optional-feature absence differently:

- DNSSEC status: only "not_configured" is absence; "incomplete"/"broken" count as misconfig
- CAA record: absent counts as absence, even though CAA is optional
- AAAA: absent counts as absence, but IPv6 is increasingly required
- SPF 'all' qualifier: ~all (weak all) counts as absence, not misconfig

This creates an inconsistent grade model:

- Domain with strong all but no CAA: correctness A, hardening lower
- Domain with missing all entirely (~none, missing): correctness F, hardening lower
- Domain with weak all (~all): hardening lower

The boundary between "didn't adopt feature" and "misconfigured feature" is blurred.

**Reproduction**

Compare two domains:
1. Domain A: no SPF all (fails completely)
2. Domain B: SPF with ~all (weak all)

Domain A: FAIL in correctness (no all at all)
Domain B: WARN in hardening (weak all)

The severity is reversed even though domain B has SPF whereas domain A doesn't.

**Evidence**

Lines 787–795 show HARDENING_ABSENCE set. SPF 'all' qualifier is in the set, so weak all (~all) is treated as hardening absence, not correctness failure.

**Why it matters**

Grades are unintuitive. A domain with weak SPF protection is graded higher than one with no SPF protection.

**Suggested fix**

Rethink HARDENING_ABSENCE. Some items should never be "absence":
- SPF must have an all mechanism (otherwise SPF provides no protection) — should be correctness
- AAAA is now increasingly expected — should shift to correctness over time

**Acceptance criteria**

- Grade model docs clearly define what is absence vs. misconfig
- Consistent scoring of optional vs. required features
- Test domains with edge-case features produce expected grades

---

## LOW Severity (2)

### N22. IP addresses accepted by normalize_domain (should be rejected)

**Module / function:** posture/core.py :: normalize_domain (lines 54–92)
**Perspective:** SDET
**Severity:** LOW
**Type:** validation, inconsistency

**What is wrong**

"192.168.1.1" passes through normalize_domain without error because it matches the regex `[a-z0-9]...`. It later fails at DNS lookup with NXDOMAIN, which is confusing.

Web layer rejects IPs explicitly (N8), but CLI accepts them.

**Reproduction**

CLI: `./run_cli.sh 192.168.1.1` → processes, queries DNS, reports not registered
Web: POST /api/check {"domain": "192.168.1.1"} → 400 Bad Request

**Evidence**

Regex at line 89 allows any string with dots and alphanumerics. "192.168.1.1" matches.

**Why it matters**

Low impact — user sees "not registered" instead of "invalid input". Confusing but not dangerous.

**Suggested fix**

Add IP check to normalize_domain (lines 54–92):

```python
if re.match(r"^\d+(\.\d+){3}$", d):
    raise ValueError("Enter a domain name, not an IP address")
```

**Acceptance criteria**

- CLI and web both reject IP addresses with same error
- Reject IPv4 and IPv6 addresses
- Accept valid domains

---

### N23. RDAP bootstrap cache is unbounded (minor version of N5)

**Module / function:** posture/core.py :: _load_bootstrap (lines 100–113)
**Perspective:** Architect
**Severity:** LOW
**Type:** resource leak (minor)

**What is wrong**

Similar to N5 (_qcache), the _bootstrap_cache and _ip_bootstrap caches are never invalidated:

```python
_bootstrap_cache: dict[str, dict] = {}
_ip_bootstrap: dict[str, Any] = {}
```

The RDAP bootstrap data is relatively small and changes rarely, so this is lower impact than _qcache. But it's still technically a resource leak in long-running processes.

**Evidence**

Lines 97, 212 show static dicts that grow on first access and never shrink.

**Why it matters**

Minor — RDAP bootstrap is ~1MB, not a memory issue even over weeks of uptime. But it's the same pattern as N5 and should be fixed for consistency.

**Suggested fix**

Store bootstrap with fetch time and expiry (e.g., 24 hours):

```python
_bootstrap_cache: dict[str, tuple[dict, float]] = {}

def _load_bootstrap():
    if "dns" in _bootstrap_cache:
        data, expiry = _bootstrap_cache["dns"]
        if time.time() < expiry:
            return data
        del _bootstrap_cache["dns"]
    ...
    _bootstrap_cache["dns"] = (mapping, time.time() + 86400)
    return mapping
```

**Acceptance criteria**

- Bootstrap is cached for 24 hours, then refetched
- Test that multiple _load_bootstrap calls within 24h use cache
- Test that bootstrap is refetched after 24 hours

---

## Summary Statistics

| Severity | Count | By Type |
|---|---|---|
| HIGH | 4 | 2 correctness, 1 exception handling, 1 SPOF |
| MEDIUM | 16 | 6 RFC/DNS, 5 architecture, 3 robustness, 2 validation |
| LOW | 2 | 1 validation, 1 resource (minor) |
| **Total** | **22** | **New findings beyond BUGS.md** |

### Root Cause Principle Violations
**13 instances** where code trusts a convenient shortcut instead of querying real sources:
- N5 (caching without TTL)
- N1, N8, N12 (hardcoded resolvers / single points of failure)
- N3, N14 (code duplication instead of shared truth source)
- N7, N9 (unsafe array indexing)
- N20, N21 (hardcoded lists instead of discovery)
- N4 (validation divergence)

### Critical to fix before public deployment

1. **N2** (TXT unretrievable) — exact known bug mentioned in CLAUDE.md
2. **N3** (run/run_streaming divergence) — violates core design requirement
3. **N4** (exception grading) — tool bug becomes customer bad grade
4. **N1** (AD-bit SPOF) — entire DNSSEC check fails on one resolver failure

---

