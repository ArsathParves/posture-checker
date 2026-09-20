"""Environment self-test.

A posture checker that queries nameservers through a transparent DNS proxy will
silently produce WRONG results: every nameserver appears reachable, AA flags are
rewritten, and lame delegation becomes undetectable. This module detects that
condition BEFORE any checks run, so the tool can degrade honestly.

Discovered during prototyping: the build sandbox intercepted UDP/53 to
unrouted addresses and blocked TCP/53 entirely, which produced a false
"nameserver not authoritative" finding against a known-good zone.

B33 — the control leg used to resolve `ns1.google.com` and probe that
one IP. Two SPOFs there: (a) it depended on a recursive resolver being
healthy to characterise the very network that recursive resolver lives
on, and (b) one flaky NS could tank the whole self-test. Both are fixed
by rotating through the IANA root-server set: static IPs (no resolver
needed) with a quorum-of-N vote for AA-flag trust.
"""
from __future__ import annotations

import random

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.resolver

# RFC 5737 / RFC 1918 addresses that must never answer DNS.
BLACKHOLE_PROBES = ["192.0.2.1", "203.0.113.99", "198.51.100.42"]


# B33 — rotating control-probe set. IANA root-server IPs are stable,
# independently operated, and universally reachable; using them as the
# control-probe target removes both the resolver-lookup SPOF and the
# single-NS SPOF that motivated this fix.
#
# IPv6 not included: the self-test speaks IPv4 first (the tool's
# baseline audience is on IPv4-only networks a large fraction of the
# time). Adding a v6 sample would strengthen the check on dual-stack
# hosts; that is out of scope for the SPOF fix.
_ROOT_SERVERS_V4: list[tuple[str, str]] = [
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "170.247.170.2"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
    ("e.root-servers.net", "192.203.230.10"),
    ("f.root-servers.net", "192.5.5.241"),
    ("g.root-servers.net", "192.112.36.4"),
    ("h.root-servers.net", "198.97.190.53"),
    ("i.root-servers.net", "192.36.148.17"),
    ("j.root-servers.net", "192.58.128.30"),
    ("k.root-servers.net", "193.0.14.129"),
    ("l.root-servers.net", "199.7.83.42"),
    ("m.root-servers.net", "202.12.27.33"),
]

# Number of roots to probe per invocation. Small enough that the
# self-test stays quick on slow networks; large enough that a single
# root being down cannot regress the SPOF fix.
_CONTROL_PROBE_COUNT = 3
# Minimum successful AA-set responses required to trust the wire path.
# A single success is not a quorum — a lucky-path middlebox could still
# be masking failure elsewhere.
_CONTROL_PROBE_MIN_AA_SUCCESS = 2


def _control_probes() -> list[tuple[str, str]]:
    """Return a random sample of `_CONTROL_PROBE_COUNT` root servers.
    Extracted as a module-level function so tests can pin the sample
    without touching the RNG."""
    return random.sample(_ROOT_SERVERS_V4,
                         min(_CONTROL_PROBE_COUNT, len(_ROOT_SERVERS_V4)))


def check_environment(timeout: float = 4.0) -> dict:
    """Returns capability flags for the current network environment."""
    out: dict = {
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

    # 2. Rotating control probes against IANA root servers. Every root
    # is authoritative for `.` and answers SOA queries with AA=1 when
    # the wire path is intact. A middlebox that terminates DNS will
    # strip AA (and typically sets RA); a broken UDP path will time out.
    probes = _control_probes()
    udp_success = 0
    aa_success = 0
    saw_ra_without_aa = False
    last_error: tuple[str, str] | None = None  # (kind, root name)
    for name, ip in probes:
        q = dns.message.make_query(".", "SOA")
        try:
            r = dns.query.udp(q, ip, timeout=timeout)
        except dns.exception.Timeout:
            last_error = ("timeout", name)
            continue
        except Exception as e:
            last_error = (type(e).__name__, name)
            continue
        udp_success += 1
        aa = bool(r.flags & dns.flags.AA)
        ra = bool(r.flags & dns.flags.RA)
        if aa:
            aa_success += 1
        elif ra:
            saw_ra_without_aa = True

    if udp_success == 0:
        out["udp53_direct"] = False
        if last_error and last_error[0] == "timeout":
            out["notes"].append(
                f"Direct UDP/53 to authoritative servers timed out "
                f"across all {len(probes)} probed roots."
            )
        else:
            kind = last_error[0] if last_error else "unknown"
            out["notes"].append(
                f"UDP/53 control query failed: {kind} across all "
                f"{len(probes)} probed roots."
            )
    else:
        out["udp53_direct"] = True
        # Quorum: aa_success >= min. One good response isn't enough,
        # because a single well-behaved server on a broken path is
        # exactly the confusing case this check is meant to spot.
        out["aa_flag_trustworthy"] = aa_success >= _CONTROL_PROBE_MIN_AA_SUCCESS
        if not out["aa_flag_trustworthy"]:
            stripped = udp_success - aa_success
            out["notes"].append(
                f"Control queries to {stripped}/{udp_success} "
                "authoritative-only servers returned without the AA flag"
                + (" and with RA set" if saw_ra_without_aa else "")
                + " — responses are being rewritten in transit."
            )

    # 3. TCP/53 (needed for large responses, DNSSEC, and AXFR-adjacent
    # checks). One successful TCP handshake to any probed root is
    # enough — this leg only tests reachability of TCP/53 as a
    # transport, not authoritativeness.
    tcp_ok = False
    for name, ip in probes:
        q = dns.message.make_query(".", "SOA")
        try:
            dns.query.tcp(q, ip, timeout=timeout)
            tcp_ok = True
            break
        except Exception:
            continue
    out["tcp53_direct"] = tcp_ok
    if not tcp_ok:
        out["notes"].append(
            "TCP/53 is blocked — truncated/large responses cannot be retried over TCP."
        )

    out["safe_for_per_ns_checks"] = bool(
        not out["intercepted"] and out["aa_flag_trustworthy"]
    )
    return out
