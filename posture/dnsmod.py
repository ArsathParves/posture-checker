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


def probe_each_ns(domain: str, ns_map: dict) -> dict:
    """Query SOA directly at each NS. Detects lame delegation + serial drift."""
    results: dict[str, dict] = {}
    for host, ips in ns_map.items():
        ip = (ips.get("ipv4") or [None])[0]
        if not ip:
            results[host] = {"reachable": False, "error": "no_A_record",
                             "authoritative": None, "serial": None, "rtt_ms": None}
            continue
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
            results[host] = {"reachable": True, "authoritative": aa, "serial": serial,
                             "rtt_ms": round(rtt, 1), "ip": ip, "error": None}
        except dns.exception.Timeout:
            results[host] = {"reachable": False, "error": "TIMEOUT", "ip": ip,
                             "authoritative": None, "serial": None, "rtt_ms": None}
        except Exception as e:
            results[host] = {"reachable": False, "error": type(e).__name__, "ip": ip,
                             "authoritative": None, "serial": None, "rtt_ms": None}
    return results


# How many parent-side NSes we query in parallel to detect divergence.
# The parent zone can itself have inconsistent secondaries — e.g. one NS
# returns a stale delegation while its peers return the current one. A
# single-sample view masks that. Cap avoids over-fanning on TLDs with 13
# root-style servers.
_PARENT_QUERY_MAX = 4


def _query_parent_ns_view(domain: str, parent_ns_host: str, parent_ip: str) -> tuple[str, list[str] | None]:
    """Ask one parent NS directly for the child's NS records.

    Returns (host, ns_list) on success, (host, None) on failure. Never raises."""
    try:
        msg = dns.message.make_query(domain, "NS")
        resp = dns.query.udp(msg, parent_ip, timeout=TIMEOUT)
        ns = []
        for rrset in list(resp.answer) + list(resp.authority):
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    ns.append(str(rr).rstrip(".").lower())
        return parent_ns_host, sorted(set(ns))
    except Exception:
        return parent_ns_host, None


def parent_delegation(domain: str) -> dict:
    """Query the parent zone's authoritative NS for the child's NS records.

    This is what a real resolver sees during resolution. RDAP-listed NS can lag
    or be under-reported by the registry (observed on .bank.in via NIXI), which
    would produce a false 'delegation mismatch' FAIL. Parent-side delegation
    is the correct source of truth.

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
        with ThreadPoolExecutor(max_workers=len(targets)) as ex:
            for host, ns_list in ex.map(
                lambda t: _query_parent_ns_view(domain, t[0], t[1]), targets
            ):
                if ns_list is not None:
                    views[host] = ns_list

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
      3. A validating resolver (8.8.8.8) sets the AD (Authenticated Data)
         flag when asked without CD -- an independent confirmation that the
         chain to root actually resolves.

    The old implementation only did (1) and reported "validating", which was
    misleading: a zone can self-sign perfectly and still be completely broken
    at the parent boundary.
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
    ds_rrset = None
    try:
        q = dns.message.make_query(name, dns.rdatatype.DS, want_dnssec=True)
        resp = dns.query.udp(q, PUBLIC_RESOLVERS[0], timeout=TIMEOUT)
        ds_rrset = next((r for r in resp.answer if r.rdtype == dns.rdatatype.DS), None)
    except Exception as e:
        out["notes"].append(f"DS query failed: {type(e).__name__}")
    out["ds"] = ds_rrset is not None
    if ds_rrset:
        out["ds_records"] = [r.to_text() for r in ds_rrset]

    # --- DNSKEY + RRSIG at child --------------------------------------
    dnskey_rrset = None
    rrsig_rrset = None
    for resolver_ip in PUBLIC_RESOLVERS:
        try:
            q = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True)
            resp = dns.query.udp(q, resolver_ip, timeout=TIMEOUT)
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

    # --- overall verdict ----------------------------------------------
    # Fully validated requires: self-signed AND DS matches AND (AD confirms OR
    # AD inconclusive but the cryptographic chain checks out).
    if out["self_signed"] and out["ds_matches_dnskey"]:
        if out["ad_authenticated"] is False:
            out["validated"] = False  # crypto looks fine but resolver rejects
        else:
            out["validated"] = True
    elif out["self_signed"] is False or out["ds_matches_dnskey"] is False:
        out["validated"] = False

    # --- state machine ------------------------------------------------
    if not out["ds"] and not out["dnskey"]:
        out["state"] = "not_configured"
    elif out["validated"] is True:
        out["state"] = "validating"
    elif out["ds"] and out["dnskey"] and out["ds_matches_dnskey"] is False:
        out["state"] = "broken"
    elif out["ds"] and out["dnskey"] and out["self_signed"] is False:
        out["state"] = "broken"
    elif out["ad_authenticated"] is False and out["ds"] and out["dnskey"]:
        out["state"] = "broken"
    elif out["ds"] and not out["dnskey"]:
        out["state"] = "broken"
        out["notes"].append("DS published at parent but no DNSKEY at child")
    elif out["dnskey"] and not out["ds"]:
        out["state"] = "incomplete"
        out["notes"].append("Zone is signed but no DS at parent — chain not anchored")
    else:
        out["state"] = "unknown"

    return out


def authoritative_vs_cached(domain: str, ns_map: dict) -> dict:
    """Compare A/AAAA records read from the authoritative NS against the
    public-resolver (cached) view.

    Records shown elsewhere in the tool come from public resolvers, i.e. the
    cached view. That can lag the zone or differ under split-horizon / geo
    steering. A disagreement is itself a useful finding: propagation lag,
    inconsistent nameservers, or geo-targeted answers.
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
    for rdtype in ("A", "AAAA"):
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


def open_resolver_check(ns_map: dict) -> dict:
    """Test whether a domain's authoritative nameservers also answer as OPEN
    RECURSIVE resolvers for third-party names.

    An authoritative server that recursively resolves arbitrary external
    domains for anyone is an open resolver -- usable in DNS amplification
    DDoS attacks and a sign of misconfiguration (authoritative and recursive
    roles should be separated).
    """
    probe = "www.google.com"
    results: dict[str, dict] = {}
    any_open = False
    for host, ips in ns_map.items():
        ip = (ips.get("ipv4") or [None])[0]
        if not ip:
            results[host] = {"tested": False, "reason": "no A record"}
            continue
        try:
            q = dns.message.make_query(probe, "A")
            q.flags |= dns.flags.RD          # request recursion
            resp = dns.query.udp(q, ip, timeout=TIMEOUT)
            # Open resolver = recursion available AND it actually answered for
            # a domain it is not authoritative for.
            ra = bool(resp.flags & dns.flags.RA)
            answered = any(rr.rdtype == dns.rdatatype.A
                           for rrset in resp.answer for rr in rrset)
            is_open = ra and answered and resp.rcode() == dns.rcode.NOERROR
            results[host] = {"tested": True, "open": is_open,
                             "ra_flag": ra, "answered_foreign": answered}
            if is_open:
                any_open = True
        except Exception as e:
            results[host] = {"tested": False, "reason": type(e).__name__}
    return {"any_open": any_open, "per_ns": results}
