"""Environment self-test.

A posture checker that queries nameservers through a transparent DNS proxy will
silently produce WRONG results: every nameserver appears reachable, AA flags are
rewritten, and lame delegation becomes undetectable. This module detects that
condition BEFORE any checks run, so the tool can degrade honestly.

Discovered during prototyping: the build sandbox intercepted UDP/53 to
unrouted addresses and blocked TCP/53 entirely, which produced a false
"nameserver not authoritative" finding against a known-good zone.
"""
from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.resolver

# RFC 5737 / RFC 1918 addresses that must never answer DNS.
BLACKHOLE_PROBES = ["192.0.2.1", "203.0.113.99", "198.51.100.42"]


def check_environment(timeout: float = 4.0) -> dict:
    """Returns capability flags for the current network environment."""
    out = {
        "udp53_direct": None,
        "tcp53_direct": None,
        "intercepted": False,
        "aa_flag_trustworthy": None,
        "notes": [],
        "safe_for_per_ns_checks": False,
    }

    # 1. interception test — do unrouted IPs "answer"?
    responded = []
    for ip in BLACKHOLE_PROBES:
        q = dns.message.make_query("example.com", "A")
        try:
            dns.query.udp(q, ip, timeout=timeout)
            responded.append(ip)
        except Exception:
            pass
    if responded:
        out["intercepted"] = True
        out["notes"].append(
            f"UDP/53 is intercepted: {len(responded)}/{len(BLACKHOLE_PROBES)} "
            "unrouted addresses returned DNS answers. Per-nameserver results "
            "cannot be trusted in this environment."
        )

    # 2. can we reach a real authoritative server directly, and is AA set?
    try:
        ip = dns.resolver.resolve("ns1.google.com", "A")[0].address
        q = dns.message.make_query("google.com", "SOA")
        r = dns.query.udp(q, ip, timeout=timeout)
        out["udp53_direct"] = True
        aa = bool(r.flags & dns.flags.AA)
        ra = bool(r.flags & dns.flags.RA)
        out["aa_flag_trustworthy"] = aa
        if not aa:
            out["notes"].append(
                "Control query to a known authoritative-only server returned "
                "without the AA flag"
                + (" and with RA set" if ra else "")
                + " — responses are being rewritten in transit."
            )
    except dns.exception.Timeout:
        out["udp53_direct"] = False
        out["notes"].append("Direct UDP/53 to an authoritative server timed out.")
    except Exception as e:
        out["udp53_direct"] = False
        out["notes"].append(f"UDP/53 control query failed: {type(e).__name__}")

    # 3. TCP/53 (needed for large responses, DNSSEC, and AXFR-adjacent checks)
    try:
        ip = dns.resolver.resolve("ns1.google.com", "A")[0].address
        q = dns.message.make_query("google.com", "SOA")
        dns.query.tcp(q, ip, timeout=timeout)
        out["tcp53_direct"] = True
    except Exception:
        out["tcp53_direct"] = False
        out["notes"].append(
            "TCP/53 is blocked — truncated/large responses cannot be retried over TCP."
        )

    out["safe_for_per_ns_checks"] = bool(
        not out["intercepted"] and out["aa_flag_trustworthy"]
    )
    return out
