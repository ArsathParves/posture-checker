"""DNS query layer: records, SOA, per-NS delegation, DNSSEC."""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any

import dns.dnssec
import dns.exception

# DNSSEC validation delegates its crypto primitives to `cryptography`.
# When the wheel is missing, `dns.dnssec.validate` and `dns.dnssec.make_ds`
# raise `ImportError` at call time. The old code caught that with a bare
# `except Exception: continue`, silently causing `ds_matches_dnskey=False`
# and reporting the zone as "broken" — a CLAUDE.md rule 1 violation
# (unretrievable collapsed into broken). Detect it up front instead.
try:  # pragma: no cover — import behaviour, not logic
    import cryptography  # noqa: F401
    _HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

TIMEOUT = 5.0
# AXFR runs over TCP and streams the full zone; a 5s cap that suits single
# record lookups is too short for a slow secondary link and produces
# false-alarm UNKNOWNs. Keep AXFR patience separately tunable.
AXFR_TIMEOUT = 10.0
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def _resolver(nameservers=None, dnssec=False) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = nameservers or PUBLIC_RESOLVERS
    r.timeout = TIMEOUT
    r.lifetime = TIMEOUT * 2
    # EDNS0 with a 4096-byte buffer. Without this, large TXT/DNSKEY answers are
    # truncated at 512 bytes and dnspython retries over TCP/53 -- which is
    # blocked in some networks, turning a valid record into a false "absent".
    r.use_edns(0, dns.flags.DO if dnssec else 0, 4096)
    return r


# TTL-aware DNS query cache. OrderedDict + LRU eviction bounds *size*
# (memory), while the per-entry (value, expiry) tuple bounds *freshness*
# (correctness). Both invariants matter and are tested separately.
_QCACHE_MAX = 2048
_qcache: OrderedDict = OrderedDict()


def query(domain: str, rdtype: str, nameservers=None) -> dict:
    """Single record query. Never raises — returns a status dict. Memoised with TTL awareness."""
    key = (domain.lower(), rdtype, tuple(nameservers) if nameservers else None)
    if key in _qcache:
        res, expiry = _qcache[key]
        if time.time() < expiry:
            _qcache.move_to_end(key)  # LRU: mark this key as recently used
            return res
        else:
            # Cache entry expired, remove it
            del _qcache[key]
    res = _query_uncached(domain, rdtype, nameservers)
    # Cache for TTL duration; default to 300s if TTL not available
    ttl = res.get("ttl", 300) if res.get("ok") else 60  # Shorter TTL for errors
    if len(_qcache) >= _QCACHE_MAX:
        _qcache.popitem(last=False)  # evict least-recently-used
    _qcache[key] = (res, time.time() + ttl)
    return res


def _query_uncached(domain: str, rdtype: str, nameservers=None) -> dict:
    # Pre-flight: detect TC (truncation). If the answer is truncated and TCP/53
    # is unavailable, we must report UNRETRIEVABLE -- never "absent". Reporting
    # a large SPF/TXT set as missing is a false FAIL on a real customer domain.
    if rdtype in ("TXT", "DNSKEY", "MX"):
        try:
            q = dns.message.make_query(domain, rdtype, use_edns=0, payload=4096)
            probe = dns.query.udp(q, (nameservers or PUBLIC_RESOLVERS)[0], timeout=TIMEOUT)
            if probe.flags & dns.flags.TC:
                try:
                    dns.query.tcp(q, (nameservers or PUBLIC_RESOLVERS)[0], timeout=TIMEOUT)
                except Exception:
                    return {"ok": False, "error": "TRUNCATED_NO_TCP",
                            "note": "Response exceeded UDP limits and TCP/53 was "
                                    "unavailable — record state is UNKNOWN, not absent."}
        except Exception:
            pass
    try:
        ans = _resolver(nameservers).resolve(domain, rdtype)
        return {"ok": True, "records": [r.to_text() for r in ans],
                "ttl": ans.rrset.ttl if ans.rrset else None}
    except dns.resolver.NXDOMAIN:
        return {"ok": False, "error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"ok": True, "records": [], "ttl": None}
    except dns.resolver.NoNameservers:
        return {"ok": False, "error": "SERVFAIL"}
    except dns.exception.Timeout:
        return {"ok": False, "error": "TIMEOUT"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}


def domain_exists(domain: str) -> dict:
    """Distinguish NXDOMAIN from 'exists but no A record'."""
    for rt in ("SOA", "NS", "A"):
        res = query(domain, rt)
        if res["ok"] and res.get("records"):
            return {"exists": True, "via": rt}
        if res.get("error") == "NXDOMAIN":
            return {"exists": False, "via": rt, "error": "NXDOMAIN"}
    return {"exists": False, "via": None, "error": "no_response"}


def get_ns_and_ips(domain: str) -> dict:
    """Served NS set + their resolved IPs."""
    res = query(domain, "NS")
    if not res["ok"]:
        return {"ok": False, "error": res.get("error"), "ns": {}}
    from concurrent.futures import ThreadPoolExecutor

    hosts = [ns.rstrip(".").lower() for ns in res.get("records", [])]

    def resolve(host):
        v4 = query(host, "A")
        v6 = query(host, "AAAA")
        return host, {
            "ipv4": v4.get("records", []) if v4["ok"] else [],
            "ipv6": v6.get("records", []) if v6["ok"] else [],
        }

    with ThreadPoolExecutor(max_workers=8) as ex:
        out = dict(ex.map(resolve, hosts))
    return {"ok": True, "ns": out, "ttl": res.get("ttl")}


# P4: fan-out for `probe_each_ns`. Cap chosen for the same reason as
# `_PARENT_QUERY_MAX` — don't over-fan on TLDs / anycast pools with
# double-digit NS counts, but always cover the common 4–6-NS domain in
# a single wave. The bound is per-call, not global.
_PER_NS_PROBE_MAX = 8


def _probe_one_ns(domain: str, host: str, ips: dict) -> tuple[str, dict]:
    """Query SOA at one NS. Returns `(host, result_dict)`. Never raises —
    every failure mode is bucketed into the result dict's `error` field
    so the parallel wrapper can iterate cleanly."""
    # E6: fall back to IPv6 when there is no A record. `dns.query.udp`
    # accepts an IPv6 literal directly, so an AAAA-only NS is fully
    # probeable — reporting it as "no_A_record" would collapse a
    # reachable-but-v6-only NS into a FAIL (rule 1 violation).
    ip = (ips.get("ipv4") or [None])[0] or (ips.get("ipv6") or [None])[0]
    if not ip:
        return host, {"reachable": False, "error": "no_address",
                      "authoritative": None, "serial": None, "rtt_ms": None}
    try:
        q = dns.message.make_query(domain, "SOA")
        t0 = time.perf_counter()
        resp = dns.query.udp(q, ip, timeout=TIMEOUT)
        rtt = (time.perf_counter() - t0) * 1000
        aa = bool(resp.flags & dns.flags.AA)
        serial = None
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                serial = rrset[0].serial
        return host, {"reachable": True, "authoritative": aa, "serial": serial,
                      "rtt_ms": round(rtt, 1), "ip": ip, "error": None}
    except dns.exception.Timeout:
        return host, {"reachable": False, "error": "TIMEOUT", "ip": ip,
                      "authoritative": None, "serial": None, "rtt_ms": None}
    except Exception as e:
        return host, {"reachable": False, "error": type(e).__name__, "ip": ip,
                      "authoritative": None, "serial": None, "rtt_ms": None}


def probe_each_ns(domain: str, ns_map: dict) -> dict:
    """Query SOA directly at each NS. Detects lame delegation + serial drift.

    Probes run in parallel across a bounded ThreadPoolExecutor so a
    slow (or unreachable-then-TIMEOUT) NS in the set doesn't serialise
    the whole check. Wall-clock scales with the slowest NS + fan-out
    overhead, not with the sum. Result shape is identical to the
    sequential version — same keys, same error strings — so the emit
    layer in checks.py and any downstream JSON consumer see no change.
    """
    if not ns_map:
        return {}
    from concurrent.futures import ThreadPoolExecutor
    workers = min(_PER_NS_PROBE_MAX, max(1, len(ns_map)))
    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_probe_one_ns, domain, host, ips)
                   for host, ips in ns_map.items()]
        for fut in futures:
            host, res = fut.result()
            results[host] = res
    return results


# How many parent-side NSes we query in parallel to detect divergence.
# The parent zone can itself have inconsistent secondaries — e.g. one NS
# returns a stale delegation while its peers return the current one. A
# single-sample view masks that. Cap avoids over-fanning on TLDs with 13
# root-style servers.
_PARENT_QUERY_MAX = 4


def _is_in_bailiwick(ns_name: str, zone: str) -> bool:
    """B23: an NS is "in-bailiwick" when its own name lives under (or
    equals) the delegated zone. RFC 1034 §4.2.1 requires the parent to
    supply glue A/AAAA for such NSes — a resolver cannot otherwise
    reach the NS to ask about the zone (chicken-and-egg).

    Naive `ns_name.endswith(zone)` would false-positive on suffix
    substring overlaps (`fooexample.com` vs `example.com`). Split into
    labels and compare tail-first, which is DNS's canonical
    containment test."""
    ns_labels = ns_name.lower().rstrip(".").split(".")
    zone_labels = zone.lower().rstrip(".").split(".")
    if len(ns_labels) < len(zone_labels):
        return False
    return ns_labels[-len(zone_labels):] == zone_labels


def _query_parent_ns_view(domain: str, parent_ns_host: str, parent_ip: str
                          ) -> tuple[str, list[str] | None, dict[str, list[str]]]:
    """Ask one parent NS directly for the child's NS records.

    Returns `(host, ns_list, glue)` on success, `(host, None, {})` on
    failure. `glue` maps in-bailiwick NS names to their A/AAAA glue
    from the response's additional section (B23). Never raises."""
    try:
        msg = dns.message.make_query(domain, "NS")
        resp = dns.query.udp(msg, parent_ip, timeout=TIMEOUT)
        ns = []
        for rrset in list(resp.answer) + list(resp.authority):
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    ns.append(str(rr).rstrip(".").lower())
        # B23: glue lives in the additional section. Collect A/AAAA
        # keyed by owner name. A parent that lists in-bailiwick NSes
        # but omits their glue is what we're looking for downstream.
        glue: dict[str, list[str]] = {}
        for rrset in list(resp.additional):
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                name = str(rrset.name).rstrip(".").lower()
                glue.setdefault(name, []).extend(str(rr) for rr in rrset)
        return parent_ns_host, sorted(set(ns)), glue
    except Exception:
        return parent_ns_host, None, {}


def parent_delegation(domain: str) -> dict:
    """Query the parent zone's authoritative NS for the child's NS records.

    This is what a real resolver sees during resolution. RDAP-listed NS can lag
    or be under-reported by the registry (observed on .bank.in via NIXI), which
    would produce a false 'delegation mismatch' FAIL. Parent-side delegation
    is the correct source of truth.

    ROOT CAUSE PRINCIPLE (CLAUDE.md): the parent zone's actual NS delegation
    is the source of truth for delegation questions; RDAP's nameserver list
    is the shortcut. When they disagree, trust the parent.

    Queries up to `_PARENT_QUERY_MAX` parent NSes in parallel. When they all
    agree, `consensus=True` and the shape is backward-compatible. When they
    disagree, `consensus=False` and `views` names the disagreeing hosts so
    downstream can emit a specific divergence finding.
    """
    labels = domain.split(".")
    if len(labels) < 2:
        return {"ok": False, "error": "no_parent"}
    parent = ".".join(labels[1:])
    try:
        parent_ns_res = query(parent, "NS")
        if not parent_ns_res.get("ok") or not parent_ns_res.get("records"):
            return {"ok": False, "error": "parent_ns_lookup_failed"}

        # Resolve up to _PARENT_QUERY_MAX parent NSes to IPs (A preferred, AAAA fallback).
        targets: list[tuple[str, str]] = []
        for ns_name in parent_ns_res["records"]:
            if len(targets) >= _PARENT_QUERY_MAX:
                break
            ns_host = str(ns_name).rstrip(".")
            a_res = query(ns_host, "A")
            if a_res.get("ok") and a_res.get("records"):
                targets.append((ns_host, a_res["records"][0]))
                continue
            aaaa_res = query(ns_host, "AAAA")
            if aaaa_res.get("ok") and aaaa_res.get("records"):
                targets.append((ns_host, aaaa_res["records"][0]))

        if not targets:
            return {"ok": False, "error": "parent_ip_lookup_failed"}

        # Query each parent NS in parallel; each returns its own view of the child's NS set.
        from concurrent.futures import ThreadPoolExecutor
        views: dict[str, list[str]] = {}
        # B23: aggregate glue from every responding parent NS. Glue is
        # part of the delegation, so we take the union across views —
        # a resolver would accept glue from any parent that answered.
        glue: dict[str, list[str]] = {}
        with ThreadPoolExecutor(max_workers=len(targets)) as ex:
            for host, ns_list, view_glue in ex.map(
                lambda t: _query_parent_ns_view(domain, t[0], t[1]), targets
            ):
                if ns_list is not None:
                    views[host] = ns_list
                for name, ips in view_glue.items():
                    existing = set(glue.get(name, []))
                    existing.update(ips)
                    glue[name] = sorted(existing)

        if not views:
            return {"ok": False, "error": "parent_query_failed"}

        # Consensus = every responding parent NS returned the same NS set.
        first_view = next(iter(views.values()))
        consensus = all(v == first_view for v in views.values())
        result = {
            "ok": True,
            "nameservers": first_view,
            "queried_via": sorted(views.keys()),
            "consensus": consensus,
            "glue": glue,
        }
        if not consensus:
            result["views"] = views
        return result
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}


def get_soa(domain: str) -> dict:
    res = query(domain, "SOA")
    if not res["ok"] or not res.get("records"):
        return {"ok": False, "error": res.get("error", "no_soa")}
    parts = res["records"][0].split()
    if len(parts) < 7:
        return {"ok": False, "error": "malformed"}
    return {
        "ok": True, "mname": parts[0].rstrip("."), "rname": parts[1].rstrip("."),
        "serial": int(parts[2]), "refresh": int(parts[3]), "retry": int(parts[4]),
        "expire": int(parts[5]), "minimum": int(parts[6]), "ttl": res.get("ttl"),
    }


# ---------------------------------------------------------------- DNSSEC


def dnssec_status(domain: str) -> dict:
    """Real DNSSEC chain validation, not just a self-signature check.

    Verifies THREE independent things:
      1. The DNSKEY RRset is self-signed by its own KSK (RRSIG validates).
      2. The DS published at the PARENT matches a digest of the child's KSK
         (this is the link that anchors the zone into the global chain --
         a stale/wrong DS here means the zone is broken for every validating
         resolver, even though its self-signature is fine).
      3. A validating resolver from `PUBLIC_RESOLVERS` (Cloudflare 1.1.1.1,
         Google 8.8.8.8, Quad9 9.9.9.9 — tried in order until one responds)
         sets the AD (Authenticated Data) flag when asked without CD -- an
         independent confirmation that the chain to root actually resolves.
         The failover across resolvers means a transient outage at any
         single resolver does not degrade the DNSSEC verdict to
         inconclusive; see `tests/test_dnssec_ad_fallback.py` (B35).

    The old implementation only did (1) and reported "validating", which was
    misleading: a zone can self-sign perfectly and still be completely broken
    at the parent boundary.

    ROOT CAUSE PRINCIPLE (CLAUDE.md): the DNSKEY self-signature is the
    shortcut; full DS→DNSKEY→chain-to-root validation is the real source
    of truth. All three signals above must agree before we emit
    "validating"; any one broken → state = "broken", never PASS.
    """
    out: dict[str, Any] = {
        "ds": False, "dnskey": False, "rrsig": False,
        "self_signed": None,      # DNSKEY RRSIG validates against own KSK
        "ds_matches_dnskey": None,  # DS at parent matches a DNSKEY digest
        "ad_authenticated": None,   # validating resolver sets AD bit
        "validated": None,          # overall: fully anchored + validating
        "algorithms": [], "notes": [], "state": "unknown",
        "cryptography_available": _HAS_CRYPTOGRAPHY,
    }

    # Without `cryptography`, `dns.dnssec.validate` and `make_ds` cannot run;
    # any signed zone would otherwise be reported as broken (CLAUDE.md rule 1
    # violation). Report UNKNOWN with a specific note and skip the network
    # probes — nothing they return can be validated.
    if not _HAS_CRYPTOGRAPHY:
        out["notes"].append(
            "cryptography module not installed — DNSSEC validation skipped. "
            "Install the `cryptography` package to enable full chain validation."
        )
        return out

    name = dns.name.from_text(domain)

    # --- DS at parent -------------------------------------------------
    # L4: we need to know whether the DS query *reached* a resolver at all.
    # A "no DS in answer section" is only meaningful if the resolver replied.
    # If every probe raises (UDP/53 blackholed, iptables, etc.) we must not
    # infer "the zone has no DS" — that would collapse `unretrievable` into
    # `not_configured`, a rule-1 violation on the tool's highest-stakes finding.
    ds_rrset = None
    ds_probe_responded = False
    try:
        q = dns.message.make_query(name, dns.rdatatype.DS, want_dnssec=True)
        resp = dns.query.udp(q, PUBLIC_RESOLVERS[0], timeout=TIMEOUT)
        ds_probe_responded = True
        ds_rrset = next((r for r in resp.answer if r.rdtype == dns.rdatatype.DS), None)
    except Exception as e:
        out["notes"].append(f"DS query failed: {type(e).__name__}")
    out["ds"] = ds_rrset is not None
    if ds_rrset:
        out["ds_records"] = [r.to_text() for r in ds_rrset]

    # --- DNSKEY + RRSIG at child --------------------------------------
    # L4: same reasoning — record whether *any* DNSKEY probe reached
    # a resolver. All-fail means "we don't know", not "zone unsigned".
    dnskey_rrset = None
    rrsig_rrset = None
    dnskey_probe_responded = False
    for resolver_ip in PUBLIC_RESOLVERS:
        try:
            q = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
            resp = dns.query.udp(q, resolver_ip, timeout=TIMEOUT)
            dnskey_probe_responded = True
            dnskey_rrset = next((r for r in resp.answer if r.rdtype == dns.rdatatype.DNSKEY), None)
            rrsig_rrset = next((r for r in resp.answer if r.rdtype == dns.rdatatype.RRSIG), None)
            if dnskey_rrset:
                break
        except Exception:
            continue
    out["dnskey"] = dnskey_rrset is not None
    out["rrsig"] = rrsig_rrset is not None

    if dnskey_rrset:
        for k in dnskey_rrset:
            alg = dns.dnssec.algorithm_to_text(k.algorithm)
            kind = "KSK" if (k.flags & 0x0001) else "ZSK"
            out["algorithms"].append(f"{alg} ({kind})")

    # --- (1) self-signature -------------------------------------------
    if dnskey_rrset and rrsig_rrset:
        try:
            dns.dnssec.validate(dnskey_rrset, rrsig_rrset, {name: dnskey_rrset})
            out["self_signed"] = True
        except dns.dnssec.ValidationFailure as e:
            out["self_signed"] = False
            out["notes"].append(f"DNSKEY self-signature invalid: {e}")
        except Exception as e:
            out["self_signed"] = None
            out["notes"].append(f"self-signature check inconclusive: {type(e).__name__}")

    # --- (2) DS-at-parent matches DNSKEY digest -----------------------
    if ds_rrset and dnskey_rrset:
        matched = False
        for key in dnskey_rrset:
            if not (key.flags & 0x0001):   # only KSKs carry the SEP bit
                continue
            for algo in ("SHA256", "SHA384", "SHA1"):
                try:
                    cand = dns.dnssec.make_ds(name, key, algo)
                    if any(cand == ds for ds in ds_rrset):
                        matched = True
                        break
                except Exception:
                    continue
            if matched:
                break
        out["ds_matches_dnskey"] = matched
        if not matched:
            out["notes"].append("DS at parent does NOT match any DNSKEY digest "
                                 "— chain is broken at the delegation boundary")

    # --- (3) AD-bit confirmation from a validating resolver -----------
    # Retry through multiple resolvers; a single resolver failure shouldn't
    # make the entire DNSSEC check inconclusive.
    ad_checked = False
    for resolver_ip in PUBLIC_RESOLVERS:
        try:
            q = dns.message.make_query(name, dns.rdatatype.A, want_dnssec=True)
            # No CD bit: we want the resolver to validate and tell us via AD.
            resp = dns.query.udp(q, resolver_ip, timeout=TIMEOUT)
            ad_checked = True
            if resp.rcode() == dns.rcode.SERVFAIL:
                out["ad_authenticated"] = False
                out["notes"].append("Validating resolver returned SERVFAIL — a real "
                                     "validating resolver rejects this zone")
            else:
                out["ad_authenticated"] = bool(resp.flags & dns.flags.AD)
            break  # Success, no need to retry
        except Exception:
            continue  # Try next resolver
    if not ad_checked:
        out["notes"].append("AD-bit check inconclusive: no validating resolver responded")

    # --- verdict + state machine (extracted to a pure helper so the
    # branch logic is directly unit-testable without needing to mock
    # the DS/DNSKEY/RRSIG DNS wire path). See `_dnssec_derive_state`.
    state, extra_notes, validated = _dnssec_derive_state(
        ds=out["ds"], dnskey=out["dnskey"],
        self_signed=out["self_signed"],
        ds_matches_dnskey=out["ds_matches_dnskey"],
        ad_authenticated=out["ad_authenticated"],
        ds_probe_responded=ds_probe_responded,
        dnskey_probe_responded=dnskey_probe_responded,
    )
    out["validated"] = validated
    out["state"] = state
    out["notes"].extend(extra_notes)
    return out


def _dnssec_derive_state(
    *,
    ds: bool,
    dnskey: bool,
    self_signed,           # True | False | None
    ds_matches_dnskey,     # True | False | None
    ad_authenticated,      # True | False | None
    ds_probe_responded: bool,
    dnskey_probe_responded: bool,
) -> tuple[str, list[str], bool | None]:
    """Pure state-machine derivation of `(state, notes, validated)`
    from the six atomic DNSSEC signals collected in `dnssec_status`.

    Kept pure and side-effect-free so the branch logic can be tested
    without mocking `dns.query.udp` + `dns.dnssec.validate` + `make_ds`.
    Every branch must match `dnssec_status`'s pre-extraction behaviour
    byte-for-byte — this is a mechanical extraction, not a rewrite.

    Returns:
      state: one of {"validating", "broken", "incomplete",
                     "not_configured", "unknown"}
      notes: additional note strings to append to the caller's notes list
      validated: True | False | None — matches out["validated"]
    """
    notes: list[str] = []

    # Overall crypto verdict: self-signed + DS matches + AD not rejecting.
    validated: bool | None = None
    if self_signed and ds_matches_dnskey:
        if ad_authenticated is False:
            validated = False  # crypto ok but validating resolver rejects
        else:
            validated = True
    elif self_signed is False or ds_matches_dnskey is False:
        validated = False

    # L4 gate: unretrievable probes cannot yield `not_configured`.
    if not ds_probe_responded and not dnskey_probe_responded:
        notes.append(
            "DS and DNSKEY probes unretrievable — UDP/53 may be blocked "
            "or every public resolver was unreachable"
        )
        return "unknown", notes, validated
    if not ds_probe_responded and not dnskey:
        notes.append(
            "DS probe unretrievable — cannot claim zone is unsigned "
            "without a parent-side answer"
        )
        return "unknown", notes, validated

    if not ds and not dnskey:
        return "not_configured", notes, validated
    if validated is True:
        return "validating", notes, validated
    if ds and dnskey and ds_matches_dnskey is False:
        return "broken", notes, validated
    if ds and dnskey and self_signed is False:
        return "broken", notes, validated
    if ad_authenticated is False and ds and dnskey:
        return "broken", notes, validated
    if ds and not dnskey:
        notes.append("DS published at parent but no DNSKEY at child")
        return "broken", notes, validated
    if dnskey and not ds:
        notes.append("Zone is signed but no DS at parent — chain not anchored")
        return "incomplete", notes, validated
    return "unknown", notes, validated


def authoritative_vs_cached(domain: str, ns_map: dict) -> dict:
    """Compare A/AAAA records read from the authoritative NS against the
    public-resolver (cached) view.

    Records shown elsewhere in the tool come from public resolvers, i.e. the
    cached view. That can lag the zone or differ under split-horizon / geo
    steering. A disagreement is itself a useful finding: propagation lag,
    inconsistent nameservers, or geo-targeted answers.

    ROOT CAUSE PRINCIPLE (CLAUDE.md): one recursive resolver's cached
    answer is the shortcut; consensus across resolvers plus an authoritative
    read is the source of truth. This function is the authoritative-read
    leg; the "consensus across resolvers" leg lives in parent_delegation.
    """
    out: dict[str, Any] = {"checked": False, "agree": None, "records": {}}
    ns_ip = None
    for host, ips in ns_map.items():
        if ips.get("ipv4"):
            ns_ip = ips["ipv4"][0]
            break
    if not ns_ip:
        return out

    name = dns.name.from_text(domain)
    disagreements = []
    # B29: extend parity check beyond A/AAAA to MX (mail routing drift),
    # TXT (SPF/DKIM/DMARC drift), CAA (CA policy drift), NS (delegation
    # drift). Each rdtype uses the same `to_text()` shape on both legs
    # so set-equality is a valid comparison.
    for rdtype in ("A", "AAAA", "MX", "TXT", "CAA", "NS"):
        cached = query(domain, rdtype)
        cached_set = set(cached.get("records", [])) if cached.get("ok") else set()
        try:
            q = dns.message.make_query(name, rdtype)
            resp = dns.query.udp(q, ns_ip, timeout=TIMEOUT)
            auth_set = set()
            for rrset in resp.answer:
                if rrset.rdtype == getattr(dns.rdatatype, rdtype):
                    for rr in rrset:
                        auth_set.add(rr.to_text())
        except Exception as e:
            out["records"][rdtype] = {"error": type(e).__name__}
            continue
        agree = cached_set == auth_set
        out["records"][rdtype] = {
            "cached": sorted(cached_set), "authoritative": sorted(auth_set),
            "agree": agree,
        }
        if not agree and (cached_set or auth_set):
            disagreements.append(rdtype)

    out["checked"] = True
    out["agree"] = len(disagreements) == 0
    out["disagreements"] = disagreements
    out["queried_ns"] = ns_ip
    return out


def axfr_open_check(domain: str, ns_map: dict) -> dict:
    """Test whether any authoritative nameserver allows a full zone transfer
    (AXFR) to an anonymous client.

    An open AXFR leaks the entire zone -- every subdomain, internal host,
    and record -- to anyone. It is a classic, serious, and trivially detected
    misconfiguration. A well-configured nameserver refuses AXFR from
    unauthorised clients.
    """
    import dns.zone
    import dns.xfr

    results: dict[str, dict] = {}
    any_open = False
    for host, ips in ns_map.items():
        ip = (ips.get("ipv4") or [None])[0]
        if not ip:
            results[host] = {"tested": False, "reason": "no A record"}
            continue
        try:
            xfr = dns.query.xfr(ip, domain, timeout=AXFR_TIMEOUT, lifetime=AXFR_TIMEOUT * 2)
            z = dns.zone.from_xfr(xfr)
            n = len(z.nodes)
            results[host] = {"tested": True, "open": True, "records_leaked": n}
            any_open = True
        except dns.xfr.TransferError:
            results[host] = {"tested": True, "open": False, "reason": "refused"}
        except (ConnectionResetError, EOFError):
            results[host] = {"tested": True, "open": False, "reason": "refused/reset"}
        except dns.exception.Timeout:
            # Slow link or peer that accepted the TCP connect but did not
            # answer within the budget. Distinct from a hard "port blocked"
            # failure so the downstream finding can be specific.
            results[host] = {"tested": False, "reason": "timeout",
                             "timeout_s": AXFR_TIMEOUT}
        except Exception as e:
            # TCP/53 blocked, refused connection, or another transient failure --
            # cannot conclude either way.
            results[host] = {"tested": False, "reason": type(e).__name__}
    return {"any_open": any_open, "per_ns": results}


# Two probe names — a single static probe (e.g. a cached target) can be
# gamed or coincidentally denied; the pair reduces both false PASS and
# false FAIL from a single unlucky query.
_OPEN_RESOLVER_PROBE_NAMES = ("www.google.com", "www.wikipedia.org")

# EDNS Client Subnet used on probe #2. A single-host tool cannot really
# spoof its source IP, but it CAN tell the target "the client I represent
# lives in this subnet" via ECS. Some resolvers use ECS in their ACL
# decision; even when they do not, distinct ECS values expand the
# observational surface.  203.0.113.0/24 is TEST-NET-3 (RFC 5737).
_OPEN_RESOLVER_ECS_SUBNET = "203.0.113.0"
_OPEN_RESOLVER_ECS_PREFIX = 24


def _open_resolver_probe(ip: str, name: str, ecs: bool = False):
    """Send one recursion probe to `ip` for `name`. Returns
    (ra_flag: bool, answered_foreign: bool, rcode: int) or raises."""
    import dns.edns
    q = dns.message.make_query(name, "A", use_edns=0, payload=4096)
    q.flags |= dns.flags.RD
    if ecs:
        opt = dns.edns.ECSOption(_OPEN_RESOLVER_ECS_SUBNET, _OPEN_RESOLVER_ECS_PREFIX)
        q.use_edns(0, options=[opt], payload=4096)
        q.flags |= dns.flags.RD
    resp = dns.query.udp(q, ip, timeout=TIMEOUT)
    ra = bool(resp.flags & dns.flags.RA)
    answered = any(rr.rdtype == dns.rdatatype.A
                   for rrset in resp.answer for rr in rrset)
    return ra, answered, resp.rcode()


def open_resolver_check(ns_map: dict) -> dict:
    """Test whether a domain's authoritative nameservers also answer as OPEN
    RECURSIVE resolvers for third-party names.

    An authoritative server that recursively resolves arbitrary external
    domains for anyone is an open resolver -- usable in DNS amplification
    DDoS attacks and a sign of misconfiguration (authoritative and recursive
    roles should be separated).

    D5: two probes per NS. Probe A is a bare recursion request; probe B
    attaches an EDNS Client Subnet option naming a documentation prefix
    to represent a client on a different subnet, and uses a different
    probe name. Together they detect:

      - `open`: any probe returned recursion for a foreign name → FAIL.
      - `partial_recursion`: RA=1 but no answer → server supports
        recursion and refused OUR probes; may serve other subnets. WARN.
      - `subnet_variance`: probes disagreed on the classification →
        subnet-dependent behaviour, also WARN.

    Never collapses inconclusive into PASS (CLAUDE.md rule 1).
    """
    results: dict[str, dict] = {}
    any_open = False
    for host, ips in ns_map.items():
        # FN5: probe every address family the NS publishes. A v4-clean
        # NS whose v6 gateway ACL was never wired up is a real misconfig
        # class — probing only v4 declares PASS while v6 leaks. Silently
        # skipping an IPv6-only NS with "no A record" was likewise a lie
        # about the tool's coverage.
        v4 = ips.get("ipv4") or []
        v6 = ips.get("ipv6") or []
        probe_ips = []
        if v4:
            probe_ips.append(v4[0])
        if v6:
            probe_ips.append(v6[0])
        if not probe_ips:
            results[host] = {"tested": False, "reason": "no address"}
            continue
        probe_a = _OPEN_RESOLVER_PROBE_NAMES[0]
        probe_b = _OPEN_RESOLVER_PROBE_NAMES[1]
        probes = []
        errors = []
        # Probe each address family with both probe variants (plain + ECS).
        # Worst-case aggregation across the full probe set below.
        for ip in probe_ips:
            for name, use_ecs in ((probe_a, False), (probe_b, True)):
                try:
                    probes.append(_open_resolver_probe(ip, name, ecs=use_ecs))
                except Exception as e:
                    errors.append(type(e).__name__)
        if not probes:
            # No probe returned — cannot conclude anything.
            results[host] = {"tested": False, "reason": errors[0] if errors else "unknown"}
            continue
        # Aggregate across probes: worst-case wins for openness detection.
        any_answered = any(p[1] for p in probes)
        any_ra = any(p[0] for p in probes)
        any_open_probe = any(p[0] and p[1] and p[2] == dns.rcode.NOERROR for p in probes)
        # partial_recursion: any probe advertised recursion but refused to answer.
        partial_recursion = any(p[0] and not p[1] for p in probes)
        # subnet_variance: RA or answered flags differ across the probe
        # set. Extended in FN5 to cover the ≥2-probe case (v4+v6 duals
        # yield 4 probes) — any disagreement is a signal that ACL
        # behaviour depends on the probing vantage.
        subnet_variance = False
        if len(probes) >= 2:
            subnet_variance = (
                len({p[0] for p in probes}) > 1
                or len({p[1] for p in probes}) > 1
            )
        results[host] = {
            "tested": True,
            "open": bool(any_open_probe),
            "ra_flag": any_ra,
            "answered_foreign": any_answered,
            "partial_recursion": bool(partial_recursion and not any_open_probe),
            "subnet_variance": bool(subnet_variance),
            "probes_run": len(probes),
        }
        if errors:
            results[host]["partial_errors"] = errors
        if any_open_probe:
            any_open = True
    return {"any_open": any_open, "per_ns": results}


def nsec_type(domain: str) -> dict:
    """Detect NSEC vs NSEC3 denial-of-existence proofs (B24).

    Send a query for a name that almost certainly does not exist under
    the zone (random label). A signed zone must return the negative
    answer authenticated by either an NSEC record (RFC 4034 §4 — walkable
    linked list) or an NSEC3 record (RFC 5155 — hashed owner names).
    The presence of NSEC in the authority section marks the zone as
    walkable; NSEC3 records also expose their iteration count, which
    RFC 9276 constrains.

    Returns:
      - {ok: True, type: "NSEC"}
      - {ok: True, type: "NSEC3", iterations: int}
      - {ok: True, type: "none"}    — no denial-of-existence record seen
                                       (unsigned zone, or probe missed)
      - {ok: False, error: str}     — query failed; downstream emits UNKNOWN

    Never raises. Callers must not collapse ok=False into type=none —
    CLAUDE.md rule 1.
    """
    import os
    probe_label = "_nsec-probe-" + os.urandom(4).hex()
    probe_name = f"{probe_label}.{domain.rstrip('.')}"
    q = dns.message.make_query(probe_name, "A", use_edns=0, payload=4096)
    q.want_dnssec(True)
    last_err = "no resolvers configured"
    for res in PUBLIC_RESOLVERS:
        try:
            resp = dns.query.udp(q, res, timeout=TIMEOUT)
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            continue
        nsec_seen = False
        nsec3_iters: int | None = None
        for rrset in resp.authority:
            if rrset.rdtype == dns.rdatatype.NSEC:
                nsec_seen = True
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                for rr in rrset:
                    nsec3_iters = int(rr.iterations)
                    break
        if nsec3_iters is not None:
            return {"ok": True, "type": "NSEC3",
                    "iterations": nsec3_iters}
        if nsec_seen:
            return {"ok": True, "type": "NSEC"}
        return {"ok": True, "type": "none"}
    return {"ok": False, "error": last_err}
