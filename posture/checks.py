"""Orchestration: run modules, emit findings, grade."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from . import dnsmod, emailauth
from .selftest import check_environment
from .core import Report, ip_rdap, normalize_domain, parse_rdap, rdap_lookup

# Operators running large multi-PoP anycast estates. A single-operator NS set
# here is a deliberate architecture, not a naive single point of failure.
#
# Two tables, checked in this order:
#   1. LARGE_ANYCAST_ASNS — ASN is the protocol source of truth for network
#      identity; Team Cymru gives it back reliably. Entries here are pinned
#      by verified AS number.
#   2. LARGE_ANYCAST_OPERATORS — legacy brand-string set kept as a fallback
#      when ASN lookup fails or the ASN has not been verified into the table
#      above. New entries should be added to the ASN table when the ASN is
#      known; the brand set is a phase-out target.
LARGE_ANYCAST_ASNS: dict[int, str] = {
    141383: "VergeCloud",
}
LARGE_ANYCAST_OPERATORS = {
    "cloudflare", "google", "amazon", "akamai", "microsoft", "azure",
    "verisign", "ns1", "dyn", "oracle", "neustar", "ultradns", "gcore",
    "fastly", "vercel", "digitalocean", "alibaba", "tencent",
    "vergecloud",
}


def _is_large_anycast_operator(asn: int | None, org_string: str | None) -> bool:
    """Classify an NS operator as running a large multi-PoP anycast estate.

    ASN is checked first (data-driven, verifiable). If ASN is not known,
    fall back to a case-insensitive substring match against the legacy
    brand-string set — this covers operators whose ASN has not yet been
    pinned into ``LARGE_ANYCAST_ASNS`` but whose org name Team Cymru
    returns in a recognisable form.

    ROOT CAUSE PRINCIPLE (CLAUDE.md): ASN is the protocol source of truth
    for network identity; the brand-string set is the shortcut. Do not
    invert this order. A brand-first classifier is what mis-graded
    vergecloud.com as "1 operator = SPOF" before C4.
    """
    if asn is not None and asn in LARGE_ANYCAST_ASNS:
        return True
    if not org_string:
        return False
    blob = org_string.lower()
    return any(k in blob for k in LARGE_ANYCAST_OPERATORS)

SECTIONS = [
    "Registration & delegation",
    "Nameserver posture",
    "SOA & zone hygiene",
    "Core records",
    "DNSSEC",
    "Email authentication",
    "Security posture",
]

# Grade weighting: worst-category-weighted, not a simple average.
SEVERITY_SCORE = {"PASS": 2, "WARN": 1, "FAIL": 0}


def run(domain_input: str, dkim_selectors=None, skip_asn=False) -> Report:
    display, puny, notes = normalize_domain(domain_input)
    rep = Report(domain_input=domain_input, domain=display, punycode=puny)

    env = check_environment()
    rep.data["environment"] = env
    if not env["safe_for_per_ns_checks"]:
        rep.degraded.append("per-nameserver probing (environment)")
    for n in notes:
        rep.add("Input", "Normalisation", "INFO", n)

    d = puny  # always query the punycode form

    # ---- existence gate ------------------------------------------------
    exists = dnsmod.domain_exists(d)
    rep.data["exists"] = exists
    if not exists["exists"]:
        rep.add("Registration & delegation", "Domain resolves", "FAIL",
                exists.get("error", "no response"),
                "Domain not found — check spelling or confirm it is registered.")
        return rep

    # ---- section steps with consistent exception handling ---
    section_steps = [
        ("Registration & delegation", lambda: _registration(rep, d)),
        ("Nameserver posture",        lambda: _nameservers(rep, d, skip_asn=skip_asn)),
        ("SOA & zone hygiene",        lambda: _soa(rep, d, rep.data.get("ns_map", {}))),
        ("Core records",              lambda: _records(rep, d)),
        ("DNSSEC",                    lambda: _dnssec(rep, d)),
        ("Email authentication",      lambda: _email(rep, d, dkim_selectors)),
        ("Security posture",          lambda: _security(rep, d)),
    ]
    for name, fn in section_steps:
        try:
            fn()
        except Exception as e:
            rep.add(name, "Section error", "UNKNOWN",
                    f"{type(e).__name__}: {e}",
                    "This section failed to complete. Result is incomplete.")
            rep.degraded.append(name)
    return rep




def run_streaming(domain_input: str, dkim_selectors=None, skip_asn=False):
    """Generator variant of run().

    Yields dict events as each section completes so the web layer can push
    progressive updates to the browser. The final 'complete' event includes
    the fully populated Report — identical to what run() returns — plus the
    computed grade block. CLI and any programmatic caller of run() see no
    change.

    Event shapes:
      {"event":"started",   "domain":..., "punycode":..., "checked_at":...}
      {"event":"normalisation_note", "text":...}                # 0..n
      {"event":"environment", "safe": bool, "notes":[...]}
      {"event":"nxdomain",   "detail":...}                      # terminal
      {"event":"section",    "name":..., "findings":[...]}      # 6 x
      {"event":"complete",   "report":{...}, "grades":{...}}
      {"event":"error",      "type":..., "message":...}         # terminal
    """
    from time import time

    try:
        display, puny, notes = normalize_domain(domain_input)
    except ValueError as e:
        yield {"event": "error", "type": "input", "message": str(e)}
        return

    rep = Report(domain_input=domain_input, domain=display, punycode=puny)

    env = check_environment()
    rep.data["environment"] = env
    if not env["safe_for_per_ns_checks"]:
        rep.degraded.append("per-nameserver probing (environment)")
    for n in notes:
        rep.add("Input", "Normalisation", "INFO", n)

    yield {"event": "started", "domain": display, "punycode": puny,
           "checked_at": rep.checked_at}
    for n in notes:
        yield {"event": "normalisation_note", "text": n}
    yield {"event": "environment",
           "safe": env["safe_for_per_ns_checks"], "notes": env.get("notes", [])}

    d = puny

    exists = dnsmod.domain_exists(d)
    rep.data["exists"] = exists
    if not exists["exists"]:
        rep.add("Registration & delegation", "Domain resolves", "FAIL",
                exists.get("error", "no response"),
                "Domain not found — check spelling or confirm it is registered.")
        yield {"event": "nxdomain", "detail": exists.get("error", "no response")}
        yield {"event": "section", "name": "Registration & delegation",
               "findings": [_f2d(f) for f in rep.section("Registration & delegation")]}
        yield {"event": "complete",
               "report": _report_to_dict(rep), "grades": grade(rep)}
        return

    # Same six steps as run(). Yield the section's findings once each returns.
    section_steps = [
        ("Registration & delegation", lambda: _registration(rep, d)),
        ("Nameserver posture",        lambda: _nameservers(rep, d, skip_asn=skip_asn)),
        ("SOA & zone hygiene",        lambda: _soa(rep, d, rep.data.get("ns_map", {}))),
        ("Core records",              lambda: _records(rep, d)),
        ("DNSSEC",                    lambda: _dnssec(rep, d)),
        ("Email authentication",      lambda: _email(rep, d, dkim_selectors)),
        ("Security posture",          lambda: _security(rep, d)),
    ]
    for name, fn in section_steps:
        t0 = time()
        try:
            fn()
        except Exception as e:
            rep.add(name, "Section error", "UNKNOWN",
                    f"{type(e).__name__}: {e}",
                    "This section failed to complete. Result is incomplete.")
            rep.degraded.append(name)
        yield {"event": "section", "name": name,
               "elapsed_ms": round((time() - t0) * 1000),
               "findings": [_f2d(f) for f in rep.section(name)]}

    yield {"event": "complete",
           "report": _report_to_dict(rep), "grades": grade(rep)}


def _f2d(f):
    return {"section": f.section, "label": f.label, "status": f.status,
            "detail": f.detail, "why": f.why}


def _report_to_dict(rep):
    return {
        "domain_input": rep.domain_input,
        "domain": rep.domain,
        "punycode": rep.punycode,
        "checked_at": rep.checked_at,
        "degraded": list(rep.degraded),
        "findings": [_f2d(f) for f in rep.findings],
    }


# ---------------------------------------------------------------- sections


def _registration(rep: Report, d: str):
    S = "Registration & delegation"
    r = rdap_lookup(d)
    rep.data["rdap_raw"] = r

    if not r["ok"]:
        err = r["error"]
        if err == "no_rdap_for_tld":
            rep.add(S, "RDAP availability", "UNKNOWN",
                    f"No RDAP endpoint published for this TLD",
                    "Registrar data unavailable — WHOIS fallback required (not in prototype).")
        elif err == "not_found":
            rep.add(S, "RDAP record", "WARN", "Registry returned 404",
                    "Domain resolves in DNS but registry has no RDAP object.")
        elif err == "rate_limited":
            rep.add(S, "RDAP record", "UNKNOWN", "Registry rate-limited the request",
                    "Temporarily unable to verify registrar data.")
        else:
            rep.add(S, "RDAP record", "UNKNOWN", f"Lookup failed ({err})", "")
        rep.degraded.append("registration")
        rep.data["rdap"] = None
        return

    p = parse_rdap(r["data"])
    rep.data["rdap"] = p
    rep.data["rdap_endpoint"] = r["endpoint"]
    rep.data["rdap_suffix"] = r["suffix"]

    rep.add(S, "Registrar", "INFO", p["registrar"] or "not disclosed")

    created = p["events"].get("registration")
    expiry = p["events"].get("expiration")
    if created:
        age_days = _days_since(created)
        rep.add(S, "Domain age", "INFO",
                f"{created[:10]}" + (f" ({age_days} days)" if age_days else ""))
    if expiry:
        days_left = _days_until(expiry)
        if days_left is not None and days_left < 30:
            rep.add(S, "Expiry", "FAIL", f"{expiry[:10]} ({days_left} days left)",
                    "Domain expires soon — lapse causes total outage.")
        elif days_left is not None and days_left < 90:
            rep.add(S, "Expiry", "WARN", f"{expiry[:10]} ({days_left} days left)",
                    "Renewal window approaching.")
        else:
            rep.add(S, "Expiry", "PASS", f"{expiry[:10]}")

    statuses = [s.lower() for s in p["status"]]
    # ROOT CAUSE PRINCIPLE (CLAUDE.md): EPP defines a full status-code set
    # per RFC 5731 §2.3. Reading only `transferProhibited` was the shortcut
    # closed by B3 — three additional buckets are product-visible for a
    # BFSI domain audit:
    #   * hold states       → non-resolving domain (FAIL, own finding)
    #   * lifecycle states  → about-to-be-dropped (FAIL, own finding)
    #   * transfer state    → in-flight transfer (WARN, own finding)
    # Each bucket surfaces independently — hold state MUST NOT be masked
    # by a transfer-lock PASS. The status set is normalised to lowercase
    # once above and matched by substring so registries that emit either
    # camelCase (`clientHold`) or space-separated (`client hold`) resolve
    # to the same detection.
    lock = any("transfer prohibited" in s or "transferprohibited" in s for s in statuses)
    rep.add(S, "Transfer lock", "PASS" if lock else "WARN",
            ", ".join(p["status"]) or "no status codes returned",
            "" if lock else "Without a transfer lock the domain is easier to hijack.")

    hold_hits = [s for s in p["status"]
                 if "clienthold" in s.lower() or "serverhold" in s.lower()
                 or "client hold" in s.lower() or "server hold" in s.lower()]
    if hold_hits:
        rep.add(S, "Registry hold", "FAIL", ", ".join(hold_hits),
                "Registry has removed the domain from DNS delegation "
                "(clientHold/serverHold). The domain will not resolve "
                "for anyone until the hold is lifted.")

    lifecycle_hits = [s for s in p["status"]
                      if "redemptionperiod" in s.lower()
                      or "redemption period" in s.lower()
                      or "pendingdelete" in s.lower()
                      or "pending delete" in s.lower()]
    if lifecycle_hits:
        rep.add(S, "Registry lifecycle", "FAIL", ", ".join(lifecycle_hits),
                "Domain has been deleted at the registry and is inside "
                "the grace window before it is dropped and becomes "
                "available for anyone to register. Renew immediately.")

    transfer_hits = [s for s in p["status"]
                     if "pendingtransfer" in s.lower()
                     or "pending transfer" in s.lower()]
    if transfer_hits:
        rep.add(S, "Registry transfer state", "WARN", ", ".join(transfer_hits),
                "A registrar transfer is in progress. Verify it was "
                "authorised — an unauthorised pendingTransfer is a "
                "hijack in progress.")

    if p["redacted"] or not p["registrar"]:
        rep.add(S, "Registrant data", "INFO", "Privacy-protected / redacted",
                "This is normal under privacy rules — not a misconfiguration.")


def _nameservers(rep: Report, d: str, skip_asn=False) -> dict:
    S = "Nameserver posture"
    got = dnsmod.get_ns_and_ips(d)
    if not got["ok"]:
        rep.add(S, "NS lookup", "FAIL", got.get("error", "failed"),
                "Could not retrieve nameservers.")
        rep.degraded.append("nameservers")
        return {}

    ns_map = got["ns"]
    rep.data["ns_map"] = ns_map
    count = len(ns_map)
    rep.add(S, "Nameserver count", "PASS" if count >= 2 else "FAIL",
            f"{count} nameserver(s): " + ", ".join(sorted(ns_map)),
            "" if count >= 2 else "A single nameserver is a single point of failure (RFC 1034 recommends at least two).")

    # Parent-side delegation vs served NS -- this is what a resolver actually
    # uses. RDAP data is a paperwork check only and can lag or be incomplete.
    served = {n.lower().rstrip(".") for n in ns_map}
    parent = dnsmod.parent_delegation(d)
    rep.data["parent_delegation"] = parent
    if parent.get("ok"):
        deleg = set(parent["nameservers"])
        if deleg == served:
            rep.add(S, "Parent delegation vs zone NS", "PASS",
                    f"Match — {len(deleg)} NS delegated at parent match zone NS")
        else:
            only_parent = deleg - served
            only_zone = served - deleg
            det = []
            if only_parent: det.append(f"delegated at parent but not served in zone: {', '.join(sorted(only_parent))}")
            if only_zone:   det.append(f"served in zone but not delegated at parent: {', '.join(sorted(only_zone))}")
            rep.add(S, "Parent delegation vs zone NS", "FAIL", "; ".join(det),
                    "Real delegation mismatch — resolvers using the parent-side NS set "
                    "will hit servers the zone does not list, or miss servers the zone does.")
        if parent.get("consensus") is False and parent.get("views"):
            views = parent["views"]
            summary = "; ".join(f"{h}: {', '.join(v) or '(empty)'}" for h, v in sorted(views.items()))
            rep.add(S, "Parent-side NS agreement", "WARN",
                    f"Parent NSes disagree on delegation — {summary}",
                    "Different parent nameservers return different NS sets for this zone. "
                    "Resolvers hitting the stale server(s) will see out-of-date delegation. "
                    "Ask the parent-zone operator to reconcile.")
    else:
        rep.add(S, "Parent delegation vs zone NS", "UNKNOWN",
                f"Could not query parent zone ({parent.get('error')})",
                "Falling back to RDAP comparison, which is paperwork-only.")

    # RDAP comparison retained as an informational paperwork check only.
    rdap = rep.data.get("rdap")
    if rdap and rdap["nameservers"]:
        registered = {n.lower().rstrip(".") for n in rdap["nameservers"]}
        if registered == served:
            rep.add(S, "RDAP-listed NS vs zone NS", "PASS", "RDAP matches zone")
        else:
            only_reg = registered - served
            only_srv = served - registered
            det = []
            if only_reg: det.append(f"in RDAP only: {', '.join(sorted(only_reg))}")
            if only_srv: det.append(f"in zone only: {', '.join(sorted(only_srv))}")
            # Not a FAIL — RDAP lag or under-reporting is common at some registries.
            rep.add(S, "RDAP-listed NS vs zone NS", "WARN", "; ".join(det),
                    "RDAP record does not match the served zone. Common cause is "
                    "registry RDAP lag; check parent delegation above for the "
                    "authoritative view.")

    # IPv6 on NS
    v6 = [h for h, x in ns_map.items() if x["ipv6"]]
    rep.add(S, "IPv6 (AAAA) on nameservers",
            "PASS" if len(v6) == len(ns_map) and ns_map else ("WARN" if v6 else "WARN"),
            f"{len(v6)}/{len(ns_map)} nameservers have AAAA records",
            "" if len(v6) == len(ns_map) else "IPv6-only clients depend on AAAA-reachable nameservers.",
            hardening=True)

    # per-NS reachability / lame delegation / serial drift
    env = rep.data.get("environment", {})
    if not env.get("safe_for_per_ns_checks", True):
        rep.add(S, "Nameserver reachability", "UNKNOWN",
                "Skipped — network path rewrites DNS responses",
                "; ".join(env.get("notes", []))
                + " Per-nameserver reachability, authority and serial-drift "
                  "checks are suppressed to avoid reporting false findings.")
        return ns_map

    probes = dnsmod.probe_each_ns(d, ns_map)
    rep.data["ns_probes"] = probes
    unreachable = [h for h, r in probes.items() if not r["reachable"]]
    nonauth = [h for h, r in probes.items() if r["reachable"] and r["authoritative"] is False
               and not r.get("serial")]
    if unreachable:
        rep.add(S, "Nameserver reachability", "FAIL",
                f"No response from: {', '.join(unreachable)}",
                "Lame or unreachable delegation degrades resolution reliability.")
    elif nonauth:
        rep.add(S, "Nameserver reachability", "FAIL",
                f"Responded without zone data: {', '.join(nonauth)}",
                "Nameserver is delegated but did not return the zone's SOA — lame delegation.")
    elif any(r["reachable"] and r["authoritative"] is False and r.get("serial")
             for r in probes.values()):
        rep.add(S, "Nameserver reachability", "WARN",
                "All nameservers returned zone data, but without the AA flag set",
                "Correct data is served; the missing AA bit may indicate a proxy in "
                "front of the nameserver (RFC 1035 s4.1.1).")
    else:
        rep.add(S, "Nameserver reachability", "PASS",
                f"All {len(probes)} nameservers responded authoritatively")

    rtts = {h: r["rtt_ms"] for h, r in probes.items() if r.get("rtt_ms") is not None}
    if rtts:
        fastest = min(rtts.values())
        slowest = max(rtts.values())
        rep.add(S, "Nameserver response time", "INFO",
                "; ".join(f"{h} {v}ms" for h, v in sorted(rtts.items(), key=lambda x: x[1]))
                + f"  (fastest {fastest}ms, slowest {slowest}ms)",
                "Single-vantage-point measurement from the machine running this "
                "check — it reflects your network path, NOT global performance. "
                "Multi-region benchmarking is not part of this build.")

    serials = {r["serial"] for r in probes.values() if r["serial"] is not None}
    if len(serials) > 1:
        rep.add(S, "SOA serial consistency", "WARN",
                f"Differing serials across nameservers: {sorted(serials)}",
                "Zone transfer may be lagging — nameservers are serving different zone versions.")
    elif serials:
        rep.add(S, "SOA serial consistency", "PASS", f"All nameservers at serial {serials.pop()}")

    # provider identification via IP RDAP / ASN (labelled as network operator)
    if not skip_asn:
        # One ip_rdap per NS host — the previous code queried twice per host
        # (once for the org string, once for the ASN); one query returns both.
        host_info: dict[str, dict] = {}
        org_owners: dict[str, str] = {}
        asn_owners: dict[str, str] = {}
        for host, ips in ns_map.items():
            ip = (ips["ipv4"] or [None])[0]
            if not ip:
                continue
            info = ip_rdap(ip)
            if not info.get("ok"):
                continue
            host_info[host] = info
            org_owners[host] = info.get("org") or info.get("name") or info.get("handle")
            if info.get("asn"):
                asn_owners[host] = f"AS{info['asn']} ({info['org']})"

        # Prefer ASN-based grouping when Cymru data is available -- IP-range
        # RIR names for leased ranges can still show as "Private Customer".
        owners = asn_owners if asn_owners else org_owners
        rep.data["ns_owners"] = owners
        if owners:
            distinct = {v for v in owners.values() if v}
            rep.add(S, "Nameserver network operator", "INFO",
                    "; ".join(f"{h} → {o}" for h, o in owners.items()),
                    "Identified from IP registry data — this is the network operator, "
                    "which may differ from the customer-facing DNS brand.")
            # Anycast classification runs per-host on the (asn, org) tuple —
            # if ANY host is on a known anycast ASN, the single-operator set
            # is treated as an anycast estate, not a correlated-failure risk.
            big_anycast = any(
                _is_large_anycast_operator(info.get("asn"), info.get("org"))
                for info in host_info.values()
            )
            if len(distinct) > 1:
                rep.add(S, "Network diversity", "PASS",
                        f"{len(distinct)} distinct operator(s): " + "; ".join(sorted(distinct)))
            elif big_anycast:
                rep.add(S, "Network diversity", "INFO",
                        f"Single operator ({'; '.join(sorted(distinct))}) — large anycast network",
                        "Concentrated with one provider, but that provider runs a "
                        "multi-PoP anycast estate; this is an architectural choice, "
                        "not a per-node failure risk.")
            else:
                rep.add(S, "Network diversity", "WARN",
                        f"{len(distinct)} distinct operator(s): " + "; ".join(sorted(distinct)),
                        "All nameservers sit on one operator's network — correlated failure risk.")
    return ns_map


def _soa(rep: Report, d: str, ns_map: dict):
    S = "SOA & zone hygiene"
    soa = dnsmod.get_soa(d)
    rep.data["soa"] = soa
    if not soa["ok"]:
        rep.add(S, "SOA record", "FAIL", soa.get("error", "not found"),
                "Every zone must have an SOA record.")
        return
    rep.add(S, "Primary nameserver (MNAME)", "INFO", soa["mname"])
    rep.add(S, "Zone admin (RNAME)", "INFO", soa["rname"])
    rep.add(S, "Serial", "INFO", str(soa["serial"]))

    # Modernised sanity ranges. RFC 1912 (1996) predates anycast DNS and CDN
    # fronting; large operators (Google, Cloudflare, AWS) legitimately run
    # short refresh/expire/TTL values. Ranges widened to reflect current
    # practice, and low-value warnings suppressed for anycast/CDN operators.
    # NOTE: ns_owners is populated by _nameservers() and must run first.
    # If missing (e.g., _nameservers failed), we conservatively apply standard ranges.
    ns_owners_blob = " ".join(str(v).lower()
                              for v in (rep.data.get("ns_owners") or {}).values())
    big_operator = any(k in ns_owners_blob for k in LARGE_ANYCAST_OPERATORS)

    # (label, value, low, high). For anycast operators, the low bound is
    # dropped to zero -- short timers are a deliberate design choice there.
    checks = [
        ("Refresh", soa["refresh"], (0 if big_operator else 900), 86400),
        ("Retry", soa["retry"], (0 if big_operator else 120), 7200),
        ("Expire", soa["expire"], 604800, 2419200),
        ("Minimum / negative TTL", soa["minimum"], (0 if big_operator else 300), 86400),
    ]
    for label, val, lo, hi in checks:
        if lo <= val <= hi:
            rep.add(S, label, "PASS", f"{val}s")
        else:
            note = "Outside commonly recommended range."
            if big_operator and val < lo:
                note = ("Low value, but this is an anycast/CDN operator where short "
                        "timers are normal — informational only.")
            rep.add(S, label, "WARN" if not (big_operator and val < 900) else "INFO",
                    f"{val}s (typical range {lo}–{hi}s)", note)

    # wildcard detection
    import uuid
    probe = f"{uuid.uuid4().hex[:12]}.{d}"
    res = dnsmod.query(probe, "A")
    if res.get("ok") and res.get("records"):
        rep.add(S, "Wildcard record", "WARN",
                f"Random subdomain resolved to {res['records'][0]}",
                "A wildcard masks NXDOMAIN and can hide typos or aid subdomain abuse.")
    else:
        rep.add(S, "Wildcard record", "PASS", "No wildcard detected")


def _is_bogon_address(addr: str) -> bool:
    """B22: True if `addr` is an IPv4/IPv6 address that should never
    appear as the authoritative apex A/AAAA record for a public-
    facing domain.

    Uses `ipaddress`'s classification attributes rather than
    hand-rolled CIDR lists: `is_private` covers RFC 1918, RFC 4193
    ULA, and IPv4 loopback / link-local / broadcast in one shot;
    `is_loopback`, `is_link_local`, `is_multicast`, `is_reserved`,
    `is_unspecified` cover the rest. Documentation ranges
    (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32) fall
    under `is_reserved` in stdlib. RFC 6598 shared-address space
    (100.64/10) is not in stdlib's `is_private` on all Python
    versions — check it explicitly.

    Returns False on any parse error — a malformed record is a
    separate problem for a separate finding (dnsmod already
    filters syntactically invalid records upstream)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    # RFC 6598 CGN block — not part of `is_private` on Py<3.13.
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in ipaddress.IPv4Network("100.64.0.0/10"):
            return True
    return False


_CAA_LINE_RE = re.compile(r'^\s*(\d+)\s+([A-Za-z][A-Za-z0-9]*)\s+"(.*)"\s*$')


def _parse_caa_record(line: str) -> tuple[int, str, str] | None:
    """B16: parse a single CAA record's `<flags> <tag> "<value>"` wire
    form (RFC 8659 §4.1). Returns (flags, tag_lowercased, value) or
    None when the line does not match — malformed records are handled
    by the caller (they surface as their own WARN finding, not as a
    silent drop)."""
    m = _CAA_LINE_RE.match(line)
    if not m:
        return None
    try:
        flags = int(m.group(1))
    except ValueError:
        return None
    return flags, m.group(2).lower(), m.group(3)


def _records(rep: Report, d: str):
    S = "Core records"
    a = dnsmod.query(d, "A")
    aaaa = dnsmod.query(d, "AAAA")
    mx = dnsmod.query(d, "MX")
    caa = dnsmod.query(d, "CAA")
    cname = dnsmod.query(d, "CNAME")

    rep.data["records"] = {"A": a, "AAAA": aaaa, "MX": mx, "CAA": caa, "CNAME": cname}

    if a.get("ok") and a.get("records"):
        ttl = a.get("ttl")
        rep.add(S, "A record", "PASS", f"{', '.join(a['records'])} (TTL {ttl}s)")
        if ttl is not None and ttl < 60:
            rep.add(S, "A record TTL", "WARN", f"{ttl}s",
                    "Very low TTL increases query volume and resolver load.")
        elif ttl is not None and ttl > 86400:
            rep.add(S, "A record TTL", "WARN", f"{ttl}s",
                    "Very high TTL slows any future cutover or failover.")
    else:
        rep.add(S, "A record", "WARN", "none", "No IPv4 address published at apex.")

    rep.add(S, "AAAA record (IPv6)",
            "PASS" if aaaa.get("records") else "WARN",
            ", ".join(aaaa.get("records", [])) or "none",
            "" if aaaa.get("records") else "No IPv6 address — IPv6-only clients cannot reach the apex directly.",
            hardening=True)

    # B22: bogon / private-space sanity. Apex A/AAAA pointing at
    # RFC 1918, loopback, link-local, ULA, docrange, multicast, or
    # CGN space is almost always a leak from an internal zone or a
    # stale `/etc/hosts`-style copy-paste. FAIL, not WARN — a
    # public client cannot route to any of these.
    a_bogons = [addr for addr in (a.get("records") or [])
                if _is_bogon_address(addr)]
    if a_bogons:
        rep.add(S, "A record bogon check", "FAIL", ", ".join(a_bogons),
                "Apex A record points at private / reserved address space. "
                "Public clients cannot route to this. Almost always a "
                "leak from an internal zone or a stale /etc/hosts entry.")
    aaaa_bogons = [addr for addr in (aaaa.get("records") or [])
                   if _is_bogon_address(addr)]
    if aaaa_bogons:
        rep.add(S, "AAAA record bogon check", "FAIL", ", ".join(aaaa_bogons),
                "Apex AAAA record points at private / reserved IPv6 space "
                "(ULA, link-local, or documentation range). Public clients "
                "cannot route to this.")

    # CNAME at apex is an RFC violation
    if cname.get("ok") and cname.get("records"):
        rep.add(S, "CNAME at apex", "FAIL", ", ".join(cname["records"]),
                "A CNAME must not coexist with other records at the zone apex (RFC 1034 s3.6.2).")

    mx_recs = mx.get("records", []) or []
    null_mx = len(mx_recs) == 1 and mx_recs[0].strip().rstrip(".") in ("0", "0 ")
    if not null_mx and len(mx_recs) == 1:
        parts = mx_recs[0].split()
        null_mx = len(parts) == 2 and parts[0] == "0" and parts[1] == "."
    rep.data["null_mx"] = null_mx
    if null_mx:
        rep.add(S, "MX record", "PASS", "Null MX (0 .) — RFC 7505",
                "Domain explicitly declares it sends and receives no mail. "
                "Inbound mail checks do not apply.")
    else:
        rep.add(S, "MX record", "PASS" if mx_recs else "INFO",
                ", ".join(mx_recs) or "none — domain does not receive mail")

    # B21: MX target sanity. Rule 1 exemption: null-MX (`0 .`) declares
    # "no mail" — target-side checks do not apply. No-MX likewise
    # exempts (not a mail domain). We only run when MX is actually
    # present and non-null.
    if not null_mx and mx_recs:
        ip_literals: list[str] = []
        cname_targets: list[str] = []
        dangling: list[str] = []
        for rec in mx_recs:
            parts = rec.split()
            if len(parts) != 2:
                continue  # malformed record — not our concern here
            target = parts[1].rstrip(".")
            if not target:
                continue
            # RFC 1035 §3.3.9: MX target is a <domain-name>, not an IP.
            try:
                ipaddress.ip_address(target)
                ip_literals.append(target)
                continue
            except ValueError:
                pass
            # RFC 2181 §10.3: CNAME must not be used as MX target.
            tgt_cname = dnsmod.query(target, "CNAME")
            if tgt_cname.get("records"):
                cname_targets.append(target)
                continue
            # Dangling: no A/AAAA on the target hostname.
            tgt_a = dnsmod.query(target, "A")
            tgt_aaaa = dnsmod.query(target, "AAAA")
            if not (tgt_a.get("records") or tgt_aaaa.get("records")):
                dangling.append(target)

        problems: list[str] = []
        if ip_literals:
            problems.append(f"IP literal: {', '.join(ip_literals)}")
        if cname_targets:
            problems.append(
                f"CNAME target (RFC 2181 §10.3 violation): "
                f"{', '.join(cname_targets)}"
            )
        if dangling:
            problems.append(
                f"dangling / does not resolve: {', '.join(dangling)}"
            )
        if problems:
            rep.add(S, "MX target", "FAIL", "; ".join(problems),
                    "MX records with invalid or unroutable targets. "
                    "RFC 1035 §3.3.9 requires a hostname (not an IP); "
                    "RFC 2181 §10.3 forbids a CNAME target; a dangling "
                    "target accepts mail attempts that then fail.")

        if len(mx_recs) == 1:
            rep.add(S, "MX redundancy", "WARN",
                    f"only one MX target ({mx_recs[0]})",
                    "A single MX is valid but has no failover — if the "
                    "sole target is unreachable, inbound mail pauses "
                    "until it recovers.")

    if caa.get("records"):
        rep.add(S, "CAA record", "PASS", ", ".join(caa["records"]),
                hardening=True)
        # B16: parse each CAA record into (flags, tag, value) and
        # surface distinct findings per RFC 8659 tag. Rule 1: this
        # runs only on records that WERE retrieved; malformed lines
        # get their own WARN so a SE can distinguish "no CAA" from
        # "CAA but zone-file typo".
        parsed: list[tuple[int, str, str]] = []
        malformed: list[str] = []
        for rec in caa["records"]:
            p = _parse_caa_record(rec)
            if p is None:
                malformed.append(rec)
            else:
                parsed.append(p)

        issue_nonwild = [v for _, t, v in parsed
                         if t == "issue" and v.strip() != ";"]
        issue_wild = [v for _, t, v in parsed
                      if t == "issuewild" and v.strip() != ";"]
        no_ca = any((t == "issue" and v.strip() == ";") for _, t, v in parsed)
        iodefs = [v for _, t, v in parsed if t == "iodef"]

        if issue_nonwild:
            rep.add(S, "CAA issuers (non-wildcard)", "PASS",
                    ", ".join(issue_nonwild),
                    "Certificate authorities permitted to issue non-"
                    "wildcard certificates for this domain (RFC 8659 "
                    "§4.2 issue tag).",
                    hardening=True)

        if issue_wild:
            rep.add(S, "CAA issuers (wildcard)", "PASS",
                    ", ".join(issue_wild),
                    "Certificate authorities permitted to issue wildcard "
                    "certificates for this domain (RFC 8659 §4.3 "
                    "issuewild tag). Overrides `issue` for `*.` names.",
                    hardening=True)

        if no_ca:
            rep.add(S, "CAA no-issue lockdown", "PASS",
                    'issue ";" — no CA may issue certificates',
                    "RFC 8659 §4.2: `issue \";\"` explicitly forbids all "
                    "CAs from issuing certificates for this domain. "
                    "Deliberate hard lockdown.",
                    hardening=True)

        # iodef reporting is a hardening signal that only makes sense
        # when there is actual issuance policy to report against. If
        # the zone has only iodef and no issue/issuewild/no-ca, the
        # policy is malformed in spirit — no CA restriction means
        # nothing to report — but we still don't want to WARN on that
        # nonsensical case; skip the finding entirely.
        has_policy = bool(issue_nonwild or issue_wild or no_ca)
        if has_policy:
            if iodefs:
                rep.add(S, "CAA iodef reporting", "PASS",
                        ", ".join(iodefs),
                        "CAA iodef endpoint receives reports of "
                        "forbidden-issuance attempts — closes the CAA "
                        "loop (RFC 8659 §4.4).",
                        hardening=True)
            else:
                rep.add(S, "CAA iodef reporting", "WARN", "no iodef tag",
                        "CAA policy has no iodef reporting endpoint; CAs "
                        "cannot notify you when a forbidden issuance is "
                        "attempted. Add `0 iodef \"mailto:...\"`.",
                        hardening=True)

        if malformed:
            rep.add(S, "CAA malformed record", "WARN", ", ".join(malformed),
                    "One or more CAA records do not match the RFC 8659 "
                    "wire format `<flags> <tag> \"<value>\"`. Zone-file "
                    "fix needed.",
                    hardening=True)
    else:
        # RFC 8659 §3: a CA queries the FQDN's CAA, and if empty walks
        # up the tree until it finds a set (stopping short of the root).
        # A subdomain with no CAA whose parent zone publishes CAA IS
        # constrained by that parent policy — reporting "any CA may
        # issue" would be factually wrong and would collapse rule-1
        # "already covered" into "broken". Walk parents ≥2 labels; stop
        # short of the eTLD (a TLD-level CAA is exceedingly rare and
        # not worth the extra query on every check).
        inherited_from = None
        inherited_records: list[str] = []
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            pc = dnsmod.query(parent, "CAA")
            if pc.get("records"):
                inherited_from = parent
                inherited_records = pc["records"]
                break
        if inherited_from:
            rep.add(S, "CAA record", "PASS",
                    f"inherited from {inherited_from}: "
                    f"{', '.join(inherited_records)}",
                    "No CAA at this label; per RFC 8659 §3 issuing CAs "
                    "walk the label tree, so the ancestor's policy applies.",
                    hardening=True)
        else:
            rep.add(S, "CAA record", "WARN", "none",
                    "Without CAA, any public CA may issue certificates for this domain (RFC 8659).",
                    hardening=True)

    # Cross-check: authoritative view vs public-resolver (cached) view.
    ns_map = rep.data.get("ns_map", {})
    if ns_map and rep.data.get("environment", {}).get("safe_for_per_ns_checks", False):
        av = dnsmod.authoritative_vs_cached(d, ns_map)
        rep.data["auth_vs_cached"] = av
        if av.get("checked"):
            if av["agree"]:
                rep.add(S, "Authoritative vs cached view", "PASS",
                        "A/AAAA records match between the authoritative nameserver "
                        "and public resolvers")
            else:
                rep.add(S, "Authoritative vs cached view", "WARN",
                        f"Mismatch on: {', '.join(av['disagreements'])}",
                        "The authoritative nameserver serves different records than "
                        "public resolvers return. Causes: propagation lag, "
                        "split-horizon DNS, or geo-targeted answers.")


def _dnssec(rep: Report, d: str):
    S = "DNSSEC"
    st = dnsmod.dnssec_status(d)
    rep.data["dnssec"] = st
    state = st["state"]
    mapping = {
        "not_configured": ("FAIL", "Not configured",
                           "Zone is unsigned — responses can be spoofed or cache-poisoned."),
        "validating": ("PASS", "Configured and validating", ""),
        "broken": ("FAIL", "Configured but NOT validating",
                   "Worse than unsigned for validating resolvers — they will SERVFAIL."),
        "incomplete": ("WARN", "Zone signed but no DS at parent",
                       "Chain of trust is not anchored — validators treat the zone as unsigned."),
        "unknown": ("UNKNOWN", "Could not determine", ""),
    }
    status, detail, why = mapping[state]
    # Missing `cryptography` produces a UNKNOWN. The generic "Could not
    # determine" copy hides an actionable fact — the operator can restore
    # DNSSEC coverage for every domain by installing one package.
    if st.get("cryptography_available") is False:
        detail = ("cryptography module not installed — DNSSEC validation skipped "
                  "(install the `cryptography` Python package to enable it).")
        why = ("Without the cryptography wheel, DS/DNSKEY digest matching and RRSIG "
               "validation cannot run. All signed zones report as UNKNOWN until the "
               "dependency is available.")
    # State-conditional hardening classification: adoption (`validating`) and
    # deliberate non-adoption (`not_configured`, `unknown`) are hardening
    # signals — never let them tank correctness. `broken` and `incomplete`
    # are genuine misconfigurations (resolvers SERVFAIL) and MUST count in
    # correctness, so hardening=False for those.
    is_hardening = state in ("not_configured", "unknown", "validating")
    rep.add(S, "DNSSEC status", status, detail, why, hardening=is_hardening)

    rep.add(S, "DS at parent", "INFO", "present" if st["ds"] else "absent")
    rep.add(S, "DNSKEY at child", "INFO", "present" if st["dnskey"] else "absent")

    # Surface the three independent validation steps so the verdict is auditable.
    if st.get("self_signed") is not None:
        rep.add(S, "DNSKEY self-signature", "INFO",
                "valid" if st["self_signed"] else "INVALID")
    if st.get("ds_matches_dnskey") is not None:
        rep.add(S, "DS matches DNSKEY (chain anchor)", "INFO",
                "yes — chain anchored at parent" if st["ds_matches_dnskey"]
                else "NO — DS at parent does not match the zone's keys")
    if st.get("ad_authenticated") is not None:
        rep.add(S, "Validating-resolver check (AD bit)", "INFO",
                "authenticated" if st["ad_authenticated"]
                else "not authenticated / SERVFAIL")

    if st["algorithms"]:
        rep.add(S, "Algorithms", "INFO", ", ".join(sorted(set(st["algorithms"]))))
        # FN4: RFC 8624 §3.1 marks SHA-1-based DNSSEC signing algorithms as
        # NOT RECOMMENDED (5, 7) or MUST NOT (1, 3, 6). A signed zone using
        # them is worse than a strong FAIL because it silently erodes the
        # security signal — validators are actively downgrading. Hardening-
        # only so an operator who *did* deploy DNSSEC isn't punished worse
        # than one who never signed at all; the signal is "rotate the key".
        _DEPRECATED_ALGS = {
            "RSAMD5", "DSA", "RSASHA1", "DSANSEC3SHA1", "RSASHA1NSEC3SHA1",
        }
        observed = {a.split(" ", 1)[0] for a in st["algorithms"]}
        deprecated = sorted(observed & _DEPRECATED_ALGS)
        if deprecated:
            rep.add(S, "Algorithm strength", "WARN",
                    f"Deprecated algorithm(s) in use: {', '.join(deprecated)}",
                    "RFC 8624 §3.1 marks SHA-1-based DNSSEC signing algorithms "
                    "as NOT RECOMMENDED (algs 5, 7) or MUST NOT (algs 1, 3, 6). "
                    "Rotate the key material to alg 13 (ECDSAP256SHA256) or "
                    "alg 15 (ED25519) at your DNS provider.",
                    hardening=True)
    for n in st["notes"]:
        rep.add(S, "Note", "INFO", n)
    if state in ("broken", "incomplete"):
        rep.add(S, "Caveat", "INFO",
                "May be a transient key-rollover state — re-check recommended before acting.")


def _email(rep: Report, d: str, dkim_selectors):
    S = "Email authentication"

    # Skip email-authentication checks entirely for domains that do not
    # operate for mail. Reporting FAIL on missing SPF/DMARC for staging,
    # UAT, parked, or infrastructure-only subdomains is a false positive:
    # those domains never send mail, so mail-authentication policies do
    # not apply. Distinguish "not applicable" from "broken" -- same
    # principle as the null-MX handling (RFC 7505) above.
    records = rep.data.get("records", {})
    mx_recs = records.get("MX", {}).get("records") or []
    a_recs  = records.get("A",  {}).get("records") or []
    aaaa    = records.get("AAAA", {}).get("records") or []
    has_mx  = bool(mx_recs) and not rep.data.get("null_mx")
    has_web = bool(a_recs or aaaa)

    if not has_mx and not has_web:
        rep.add(S, "Email authentication", "INFO",
                "Skipped — domain publishes no MX and no A/AAAA at apex",
                "This subdomain does not appear to be operating for mail or web "
                "(no MX, no address records). SPF/DKIM/DMARC checks do not apply.")
        return

    if not has_mx and has_web:
        # Domain has web presence but no MX record. It may still be a
        # sending-only domain (SPF/DMARC useful) but cannot receive mail,
        # so downgrade missing sender-auth to WARN rather than FAIL and
        # skip inbound MTA-STS / TLS-RPT.
        rep.data["_send_only"] = True

    spf = emailauth.evaluate_spf(d)
    rep.data["spf"] = spf
    if spf.get("present") is None:
        rep.add(S, "SPF", "UNKNOWN", "Could not retrieve TXT records",
                spf.get("unretrievable", "") + " Not reported as absent.")
        rep.degraded.append("SPF (unretrievable)")
    elif not spf["present"]:
        # WARN, not FAIL, when the domain has no MX -- it may simply not
        # be sending mail either. Only FAIL when the domain clearly does
        # operate for mail (has MX).
        sev = "FAIL" if has_mx else "WARN"
        why = ("Without SPF, anyone can send mail claiming to be from this domain."
               if has_mx else
               "Domain has no MX record; SPF still recommended if mail is sent from "
               "any service using this domain.")
        rep.add(S, "SPF", sev, "No SPF record", why)
    else:
        if spf.get("multiple"):
            rep.add(S, "SPF", "FAIL", "Multiple SPF records published",
                    "More than one SPF record is a permanent error (RFC 7208 s3.2).")
        else:
            rep.add(S, "SPF", "PASS", spf["record"][:150])
        cnt = spf.get("lookup_count", 0)
        if spf.get("exceeds_limit"):
            rep.add(S, "SPF DNS lookup count", "FAIL", f"{cnt} (limit is 10)",
                    "Exceeding 10 lookups makes SPF fail permanently (RFC 7208 s4.6.4).")
        elif cnt >= 8:
            rep.add(S, "SPF DNS lookup count", "WARN", f"{cnt} of 10",
                    "Close to the RFC limit — adding another sender may break SPF.")
        else:
            rep.add(S, "SPF DNS lookup count", "PASS", f"{cnt} of 10")

        strength = spf.get("all_strength")
        if strength == "hardfail":
            rep.add(S, "SPF 'all' qualifier", "PASS", spf.get("all_qualifier"))
        elif strength == "softfail":
            rep.add(S, "SPF 'all' qualifier", "WARN", spf.get("all_qualifier"),
                    "~all only marks unauthorised mail as soft-fail.")
        else:
            rep.add(S, "SPF 'all' qualifier", "FAIL", spf.get("all_qualifier") or "missing",
                    "Without a restrictive 'all', SPF provides little protection.")

    dkim = emailauth.evaluate_dkim(d, dkim_selectors)
    rep.data["dkim"] = dkim
    if dkim.get("unretrievable"):
        # TXT records were unretrievable (truncated + no TCP, timeout, etc.)
        rep.add(S, "DKIM", "UNKNOWN",
                dkim.get("label", "DKIM check could not complete"),
                dkim.get("unretrievable", "TXT records were unretrievable"))
    elif dkim.get("wildcard"):
        state = dkim.get("key_state")
        rep.add(S, "DKIM", "FAIL" if state == "revoked" else "UNKNOWN",
                dkim["label"],
                "An empty p= value revokes the key (RFC 6376 s3.6.1); a wildcard "
                "_domainkey record makes per-selector probing meaningless.")
    elif dkim["found"]:
        detail = "Found selector(s): " + ", ".join(x["selector"] for x in dkim["selectors"])
        if dkim.get("revoked"):
            detail += " | revoked selector(s): " + ", ".join(
                x["selector"] for x in dkim["revoked"])
        rep.add(S, "DKIM", "PASS", detail)
    else:
        rep.add(S, "DKIM", "UNKNOWN",
                f"Not found under {dkim['probed']} common selectors",
                "DKIM selectors are not discoverable via DNS — this does NOT prove DKIM is absent.")

    dmarc = emailauth.evaluate_dmarc(d)
    rep.data["dmarc"] = dmarc
    if dmarc.get("present") is None:
        rep.add(S, "DMARC", "UNKNOWN", "Could not retrieve _dmarc TXT records",
                dmarc.get("unretrievable", "") + " Not reported as absent.")
        rep.degraded.append("DMARC (unretrievable)")
    elif not dmarc["present"]:
        sev = "FAIL" if has_mx else "WARN"
        why = ("Without DMARC, SPF/DKIM failures have no enforcement policy."
               if has_mx else
               "Domain has no MX record; DMARC still recommended if mail is sent from "
               "any service using this domain.")
        rep.add(S, "DMARC", sev, "No DMARC record", why)
    elif dmarc.get("multiple"):
        # E5: RFC 7489 §6.6.3 — with >1 v=DMARC1 record, receivers apply
        # no DMARC decision. This is a real FAIL: a domain with two
        # DMARC records has effectively no DMARC policy in force, even
        # if each record on its own says p=reject.
        records = dmarc.get("all_records") or []
        rep.add(S, "DMARC", "FAIL",
                f"Multiple DMARC records published ({len(records)})",
                "RFC 7489 §6.6.3: with more than one v=DMARC1 record at "
                "_dmarc.<domain>, receivers apply no DMARC-based decision. "
                "Consolidate to a single record.")
    else:
        strength = dmarc["strength"]
        status = {"strong": "PASS", "moderate": "WARN", "weak": "FAIL"}.get(strength, "WARN")
        why = ""
        if strength == "weak":
            why = "p=none only monitors — it does not block spoofed mail."
        elif strength == "moderate":
            why = "p=quarantine sends failing mail to spam rather than rejecting it."
        rep.add(S, "DMARC policy", status, f"p={dmarc['policy']} (pct={dmarc['pct']})", why)
        rep.add(S, "DMARC reporting", "PASS" if dmarc.get("rua") else "WARN",
                dmarc.get("rua") or "no rua= aggregate reporting address",
                "" if dmarc.get("rua") else "Without rua you get no visibility into who is sending as your domain.",
                hardening=True)

        # FN3: RFC 7489 §7.1 — external rua/ruf destinations must publish
        # <checked>._report._dmarc.<dest> confirming opt-in, or mail
        # receivers refuse to send reports. A domain that looks configured
        # but has an unverified external destination is silently getting
        # no reports.
        if dmarc.get("rua") or dmarc.get("ruf"):
            rpt = emailauth.evaluate_dmarc_reporting(
                d, rua=dmarc.get("rua"), ruf=dmarc.get("ruf"))
            rep.data["dmarc_reporting"] = rpt
            for entry in rpt["destinations"]:
                if not entry["external"]:
                    continue  # same-org destinations need no verification
                label = f"DMARC {entry['tag']} verification: {entry['domain']}"
                if entry.get("parse_error"):
                    rep.add(S, label, "WARN", f"unparseable: {entry['raw']}",
                            "RFC 7489 §7.1 verification requires a mailto: "
                            "URI; other schemes are not verified by this tool.",
                            hardening=True)
                elif entry["unretrievable"]:
                    rep.add(S, label, "UNKNOWN",
                            f"verification lookup unretrievable for "
                            f"{entry['domain']}",
                            "Could not query the ExtDestVerification record "
                            "— NOT evidence the third party has declined.")
                elif entry["verified"]:
                    rep.add(S, label, "PASS",
                            f"{entry['domain']} opted in to receive reports")
                else:
                    rep.add(S, label, "FAIL",
                            f"{entry['domain']} has no ExtDestVerification "
                            f"record",
                            "RFC 7489 §7.1: without a `v=DMARC1` TXT at "
                            f"{d}._report._dmarc.{entry['domain']}, mail "
                            "receivers will not send aggregate reports to "
                            "this address — reporting is silently broken.")

    if rep.data.get("null_mx"):
        rep.add(S, "Inbound mail checks", "INFO",
                "Skipped — domain publishes a null MX (RFC 7505)",
                "MTA-STS and TLS-RPT do not apply to a domain that accepts no mail.")
        return
    if not has_mx:
        # No MX at all: inbound mail policies do not apply. Skipping is
        # honest -- flagging MTA-STS/TLS-RPT absent on a domain that
        # cannot receive mail is a category error.
        return
    sts = emailauth.evaluate_mta_sts(d)
    rep.data["mta_sts"] = sts
    if sts.get("mta_sts") is not None and rep.data.get("records", {}).get("MX", {}).get("records"):
        _emit_mta_sts_findings(rep, S, sts)


def _emit_mta_sts_findings(rep: Report, section: str, sts: dict) -> None:
    """Render MTA-STS and TLS-RPT findings from an ``evaluate_mta_sts``
    result. Split out from ``_email`` so the rule-1 UNKNOWN path for a
    truncated TLS-RPT lookup can be exercised in a unit test without
    stubbing every upstream lookup in the email-auth section."""
    rep.add(section, "MTA-STS", "PASS" if sts["mta_sts"] else "WARN",
            "present" if sts["mta_sts"] else "absent",
            "" if sts["mta_sts"] else "MTA-STS enforces TLS for inbound mail (RFC 8461).",
            hardening=True)
    if sts.get("tls_rpt_unretrievable"):
        # Rule 1: unretrievable is NOT absent. Report as UNKNOWN and
        # attach an explicit "why" so the reader knows the lookup was
        # truncated / TCP/53 blocked, rather than the record being
        # missing from the domain.
        rep.add(section, "TLS-RPT", "UNKNOWN",
                "Could not retrieve _smtp._tls TXT records",
                "TLS-RPT lookup was truncated or TCP/53 was blocked; "
                "not reported as absent (CLAUDE.md rule 1).",
                hardening=True)
        rep.degraded.append("TLS-RPT (unretrievable)")
        return
    rep.add(section, "TLS-RPT", "PASS" if sts["tls_rpt"] else "WARN",
            "present" if sts["tls_rpt"] else "absent",
            hardening=True)


# ---------------------------------------------------------------- grading


def _security(rep: Report, d: str):
    """AXFR (zone transfer) and open-resolver exposure checks."""
    S = "Security posture"
    ns_map = rep.data.get("ns_map", {})
    env = rep.data.get("environment", {})

    if not ns_map:
        rep.add(S, "Security checks", "UNKNOWN",
                "No nameserver IPs available to test", "")
        return

    if not env.get("safe_for_per_ns_checks", False):
        rep.add(S, "Security checks", "UNKNOWN",
                "Skipped — network path is untrusted for direct nameserver tests",
                "AXFR and open-resolver checks query nameservers directly; the "
                "environment self-test flagged this path as unreliable.")
        return

    # --- AXFR / zone transfer -----------------------------------------
    # D6: mirror the TxtUnretrievable symmetry. AXFR is TCP-only; if the
    # env self-test flagged TCP/53 as unavailable, no probe result can
    # be trusted. Short-circuit with an explicit UNKNOWN naming the
    # pre-flight finding — never a false PASS/FAIL from a doomed probe.
    if env.get("tcp53_direct") is False:
        rep.add(S, "Zone transfer (AXFR)", "UNKNOWN",
                "AXFR untestable — TCP/53 unavailable on this network path "
                "(environment self-test blocked TCP/53).",
                "AXFR runs over TCP only; without TCP/53 the check cannot "
                "distinguish 'server refused' from 'we could not reach it'. "
                "Re-run on a network path where TCP/53 is permitted.")
        # Skip only AXFR — open-resolver uses UDP and is still meaningful.
        axfr = None
    else:
        axfr = dnsmod.axfr_open_check(d, ns_map)
        rep.data["axfr"] = axfr
        tested = [h for h, r in axfr["per_ns"].items() if r.get("tested")]
        if axfr["any_open"]:
            leaked = [(h, r.get("records_leaked"))
                      for h, r in axfr["per_ns"].items() if r.get("open")]
            detail = "; ".join(f"{h} leaked {n} records" for h, n in leaked)
            rep.add(S, "Zone transfer (AXFR)", "FAIL", detail,
                    "Nameserver allows anonymous full zone transfer — the entire zone "
                    "(every subdomain and internal host) is exposed to anyone. "
                    "Restrict AXFR to authorised secondaries only.")
        elif tested:
            rep.add(S, "Zone transfer (AXFR)", "PASS",
                    f"Refused by all {len(tested)} tested nameserver(s)")
        else:
            reasons = [r.get("reason") for r in axfr["per_ns"].values() if r.get("reason")]
            timed_out = [r for r in reasons if r == "timeout"]
            if timed_out and len(timed_out) == len(reasons):
                detail = (f"AXFR test timeout on all {len(timed_out)} nameserver(s) "
                          f"after {dnsmod.AXFR_TIMEOUT}s — slow link or unresponsive TCP/53")
            elif timed_out:
                detail = (f"Could not complete AXFR test — {len(timed_out)} of "
                          f"{len(reasons)} nameserver(s) hit timeout after "
                          f"{dnsmod.AXFR_TIMEOUT}s; others failed with: "
                          + ", ".join(sorted(set(r for r in reasons if r != "timeout"))))
            else:
                detail = ("Could not complete AXFR test (TCP/53 may be blocked on this path) "
                          "— reasons: " + ", ".join(sorted(set(reasons)))) if reasons else \
                         "Could not complete AXFR test (TCP/53 may be blocked on this path)"
            rep.add(S, "Zone transfer (AXFR)", "UNKNOWN", detail,
                    "Zone-transfer exposure could not be determined.")

    # --- open recursive resolver --------------------------------------
    openres = dnsmod.open_resolver_check(ns_map)
    rep.data["open_resolver"] = openres
    otested = [h for h, r in openres["per_ns"].items() if r.get("tested")]
    if openres["any_open"]:
        openh = [h for h, r in openres["per_ns"].items() if r.get("open")]
        rep.add(S, "Open recursive resolver", "FAIL",
                f"Recursive for third-party names: {', '.join(openh)}",
                "Authoritative nameserver also answers recursive queries for "
                "arbitrary domains — usable in DNS amplification DDoS attacks. "
                "Authoritative and recursive roles should be separated.")
    elif otested:
        # D5: a server that advertises recursion (RA=1) but refused OUR probes
        # is not necessarily safe — a source-subnet-based ACL may still serve
        # recursion to other clients. Same for divergent behaviour between
        # our two probes. Never collapse "inconclusive" into PASS.
        partial = [h for h, r in openres["per_ns"].items()
                   if r.get("partial_recursion")]
        variance = [h for h, r in openres["per_ns"].items()
                    if r.get("subnet_variance") and not r.get("partial_recursion")]
        if partial:
            rep.add(S, "Open recursive resolver", "WARN",
                    f"Recursion advertised but refused from our vantage on: "
                    f"{', '.join(partial)}",
                    "Nameserver's RA bit is set (recursion is supported) but "
                    "queries from our source were refused. Source-subnet-based "
                    "ACLs may still serve recursion to other client subnets — "
                    "verify from a second vantage or disable recursion entirely "
                    "on authoritative servers.")
        elif variance:
            rep.add(S, "Open recursive resolver", "WARN",
                    f"Inconsistent recursion behaviour across probes on: "
                    f"{', '.join(variance)}",
                    "Different probes elicited different recursion behaviour "
                    "(likely subnet-dependent). Confirm from another vantage.")
        else:
            rep.add(S, "Open recursive resolver", "PASS",
                    f"No open recursion on {len(otested)} tested nameserver(s)")
    else:
        rep.add(S, "Open recursive resolver", "UNKNOWN",
                "Could not complete open-resolver test", "")


def grade(rep: Report, strict: bool = False) -> dict:
    """Per-section band + overall. Overall is worst-weighted, not averaged.

    ``strict``: pre-production audit mode. WARN findings are promoted to
    FAIL for both severity scoring and `has_fail` detection. Classification
    (hardening vs correctness) is unaffected — strict tightens the grade,
    it does not reclassify findings. UNKNOWN is still UNKNOWN.
    """
    # In strict mode, a WARN counts as a FAIL for scoring purposes. We keep
    # `f.status` untouched (the finding text still reads "WARN" in the UI)
    # and only remap the score/has_fail contributions.
    def _score(f):
        if strict and f.status == "WARN":
            return SEVERITY_SCORE["FAIL"]
        return SEVERITY_SCORE[f.status]

    def _is_failing(f):
        return f.status == "FAIL" or (strict and f.status == "WARN")

    out = {}
    for sec in SECTIONS:
        scored = [f for f in rep.section(sec) if f.is_scored]
        if not scored:
            out[sec] = ("—", None)
            continue
        pts = sum(_score(f) for f in scored)
        pct = pts / (2 * len(scored))
        has_fail = any(_is_failing(f) for f in scored)
        band = _band(pct, has_fail)
        out[sec] = (band, pct)

    bands = [b for b, _ in out.values() if b != "—"]
    order = ["A", "B", "C", "D", "F"]
    worst = max((order.index(b) for b in bands), default=0)
    avg = sum(order.index(b) for b in bands) / max(len(bands), 1)
    # worst-weighted: pull toward the worst category
    overall_idx = round((worst * 0.6) + (avg * 0.4))

    # --- correctness vs hardening split -------------------------------
    # A domain that merely LACKS an optional hardening feature (DNSSEC not
    # configured, no CAA, no MTA-STS) is not misconfigured -- most of the
    # internet, including google.com, is in the same position. Scoring that
    # identically to a genuine MISCONFIGURATION (broken DNSSEC, delegation
    # mismatch, open AXFR, expired domain) produced a misleading "D" for
    # google.com. We separate the two:
    #   - correctness_grade: only genuine misconfigurations count as failures
    #   - hardening_grade:   optional-feature adoption
    # Classification lives on each Finding (`f.hardening`) — the emit site
    # is authoritative. There is no global label set to keep in sync; new
    # hardening checks self-declare by passing `hardening=True` to
    # `Report.add()`. See `Finding.hardening` in core.py for the semantics.
    def _is_hardening_absence(f):
        # Hardening findings drag hardening grade only when the feature is
        # unadopted (WARN/FAIL). PASS on a hardening check is credit that
        # also counts toward correctness — adopting an optional feature
        # signals good posture across both dimensions.
        return f.hardening and f.status in ("WARN", "FAIL")

    correctness_findings = [f for f in rep.findings
                            if f.is_scored and not _is_hardening_absence(f)]

    def _grade_set(findings):
        if not findings:
            return "—"
        pts = sum(_score(f) for f in findings)
        pct = pts / (2 * len(findings))
        has_fail = any(_is_failing(f) for f in findings)
        return _band(pct, has_fail)

    correctness_grade = _grade_set(correctness_findings)
    hardening_scored = [f for f in rep.findings if f.hardening and f.is_scored]
    hardening_pts = sum(_score(f) for f in hardening_scored)
    hardening_total = len(hardening_scored)
    # Hardening bucket is graded as a pure adoption ratio (has_fail=False) so
    # a single un-adopted hardening feature doesn't trip the has_fail-driven
    # D/F floor — google.com's 6/7 adoption should stay at B, not fall to D.
    # Strict mode still tightens via _score() promoting WARN→FAIL point values.
    hardening_grade = (_band(hardening_pts / (2 * hardening_total), False)
                       if hardening_total else "—")

    # Overall now tracks correctness (misconfiguration severity), with a
    # small nudge from hardening so full adoption is still rewarded.
    if correctness_grade != "—":
        c_idx = order.index(correctness_grade)
        h_idx = order.index(hardening_grade) if hardening_grade != "—" else c_idx
        overall_idx = round(c_idx * 0.8 + h_idx * 0.2)

    ungraded = [sec for sec, (b, _) in out.items() if b == "—" and rep.section(sec)]
    unknowns = [f.section for f in rep.findings if f.status == "UNKNOWN"]
    provisional = bool(ungraded or unknowns or rep.degraded)

    # L2: name the un-adopted optional features driving the hardening
    # grade. A bare "Hardening: C" letter is opaque; downstream renderers
    # use this list to caption "no MTA-STS, no TLS-RPT" so the letter is
    # decodable rather than mysterious. PASS findings are adopted → not
    # listed. Order is emit order (stable across runs).
    hardening_gaps = [f.label for f in rep.findings
                      if f.hardening and f.status in ("WARN", "FAIL")]

    return {"sections": out, "overall": order[min(overall_idx, 4)],
            "correctness_grade": correctness_grade,
            "hardening_grade": hardening_grade,
            "hardening_gaps": hardening_gaps,
            "provisional": provisional,
            "ungraded_sections": ungraded,
            "unknown_in": sorted(set(unknowns))}


def _band(pct: float, has_fail: bool) -> str:
    if has_fail and pct < 0.5:
        return "F"
    if has_fail and pct < 0.75:
        return "D"
    if pct >= 0.95:
        return "A"
    if pct >= 0.8:
        return "B"
    if pct >= 0.6:
        return "C"
    if pct >= 0.4:
        return "D"
    return "F"


def _days_since(iso: str):
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _days_until(iso: str):
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (dt - datetime.now(timezone.utc)).days
    except Exception:
        return None
