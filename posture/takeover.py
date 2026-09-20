"""Subdomain takeover / dangling-record detection (B20).

Two threat classes are surfaced here:

1. NAMESERVER PARENT-ZONE HIJACK — full zone takeover. If a domain
   delegates to `ns1.foo-hosting.example` and the parent
   `foo-hosting.example` is NXDOMAIN, any attacker who registers that
   parent can attach a nameserver of the same hostname and control
   DNS for the target zone. Same-zone glue (`ns1.example.com` for
   `example.com`) does not apply — that risk is handled by the glue
   / delegation checks.

2. DANGLING CNAME — the input domain (usually a subdomain; apex
   CNAMEs violate RFC 1912 §2.4 but occur in the wild via ALIAS
   flattening) resolves via CNAME to a target that has no A/AAAA.
   Two sub-cases:

   - Target under a known takeover-vulnerable service suffix
     (`*.s3.amazonaws.com`, `*.github.io`, `*.azurewebsites.net`, …):
     an attacker can claim the tenant name on that service and serve
     arbitrary content on the delegator's FQDN. This is the CRITICAL
     branch, because the attack requires nothing but a free account.

   - Target NOT under a known takeover service: still dangling, still
     FAIL (broken DNS pointing at nothing), but not CRITICAL — the
     attack surface depends on whether an attacker can claim the
     target name, which is not universally available.

Every probe here goes through `dnsmod.query` / `dnsmod.domain_exists`
so behaviour is uniform with the rest of the checker and the module
is network-free-testable via `monkeypatch`.

Rule 1 (CLAUDE.md): a probe timeout or resolver error must NOT fire
a finding. Every "UNKNOWN takeover risk" in the wild costs a
Solutions Engineer a conversation with a customer; we do not do that.
"""
from __future__ import annotations

from typing import Iterable

from . import dnsmod


# Suffix table for the "someone can claim this tenant name" case.
# Source: EdOverflow/can-i-take-over-xyz + projectdiscovery/subzy
# signatures — services where a public sign-up flow lets any user
# attach content to an arbitrary hostname under the suffix.
#
# Membership in this table does NOT itself mean a finding fires — the
# finding requires the target to also be dangling. Membership only
# lifts an already-dangling CNAME from FAIL to CRITICAL.
TAKEOVER_SERVICE_SUFFIXES: tuple[str, ...] = (
    ".s3.amazonaws.com",
    ".s3-website.amazonaws.com",
    ".s3-website-us-east-1.amazonaws.com",
    ".azurewebsites.net",
    ".cloudapp.net",
    ".cloudapp.azure.com",
    ".trafficmanager.net",
    ".github.io",
    ".herokuapp.com",
    ".herokudns.com",
    ".cloudfront.net",
    ".fastly.net",
    ".pantheonsite.io",
    ".readthedocs.io",
    ".ghost.io",
    ".surge.sh",
    ".shopify.com",
    ".myshopify.com",
    ".unbouncepages.com",
    ".zendesk.com",
    ".freshdesk.com",
)

_CNAME_MAX_HOPS = 8


def _parent_zone(hostname: str) -> str:
    """Drop the leftmost label. `ns1.foo.example` → `foo.example`.

    The parent-zone-hijack model checks the immediate parent because
    that is the zone an attacker must register to attach an NS record
    with the target hostname. Walking further up (`.example`, `.`) is
    not the attack — attackers cannot register TLDs.
    """
    parts = hostname.rstrip(".").split(".")
    return ".".join(parts[1:]) if len(parts) > 1 else hostname.rstrip(".")


def _is_under_zone(hostname: str, zone: str) -> bool:
    h = hostname.rstrip(".").lower()
    z = zone.rstrip(".").lower()
    return h == z or h.endswith("." + z)


def nameserver_parent_zone_check(target_domain: str,
                                 ns_hostnames: Iterable[str]) -> dict:
    """For each nameserver hostname, verify its parent zone exists.

    Args:
        target_domain: the zone under audit; NSes inside its own
            bailiwick are skipped as same-zone glue.
        ns_hostnames: NS hostnames from the delegation set.

    Returns:
        {"ok": True,
         "per_ns": {hostname: {"parent": str|None,
                               "status": "same_zone"|"ok"|"unregistered"|"error",
                               "error": str (only for "error")}},
         "any_hijackable": bool}
    """
    per_ns: dict[str, dict] = {}
    any_hijackable = False
    for host in ns_hostnames:
        host_clean = host.rstrip(".").lower()
        if _is_under_zone(host_clean, target_domain):
            per_ns[host_clean] = {"parent": None, "status": "same_zone"}
            continue
        parent = _parent_zone(host_clean)
        res = dnsmod.domain_exists(parent)
        if res.get("exists"):
            per_ns[host_clean] = {"parent": parent, "status": "ok"}
        elif res.get("error") == "NXDOMAIN":
            per_ns[host_clean] = {"parent": parent, "status": "unregistered"}
            any_hijackable = True
        else:
            per_ns[host_clean] = {"parent": parent, "status": "error",
                                  "error": res.get("error")}
    return {"ok": True, "per_ns": per_ns, "any_hijackable": any_hijackable}


def _matches_takeover_service(target: str) -> str | None:
    t = "." + target.rstrip(".").lower()
    for suffix in TAKEOVER_SERVICE_SUFFIXES:
        if t.endswith(suffix):
            return suffix
    return None


def _follow_cname_chain(domain: str) -> tuple[str, list[str], str | None]:
    """Walk the CNAME chain from `domain`.

    Returns:
        (final, chain, err) where:
          - `chain` is the ordered list of CNAME targets followed
            (empty if `domain` has no CNAME).
          - `final` is the last name in the chain (or `domain` if
            chain is empty).
          - `err`:
              None            → chain terminated normally (target
                                exists at the resolver level; A/AAAA
                                state to be checked by the caller).
              "NXDOMAIN"      → chain ended because a hop returned
                                NXDOMAIN. Dangling by construction.
              "LOOP"          → too many hops; treat as UNKNOWN.
              other string    → resolver error at the CNAME step;
                                UNKNOWN.
    """
    chain: list[str] = []
    current = domain
    for _ in range(_CNAME_MAX_HOPS):
        res = dnsmod.query(current, "CNAME")
        if not res["ok"]:
            if res.get("error") == "NXDOMAIN":
                return current, chain, "NXDOMAIN"
            return current, chain, res.get("error") or "ERROR"
        if not res.get("records"):
            return current, chain, None
        target = res["records"][0].rstrip(".").lower()
        chain.append(target)
        current = target
    return current, chain, "LOOP"


def cname_takeover_check(domain: str) -> dict:
    """Detect a dangling CNAME on `domain`.

    Returns:
        {"cname_present": bool,
         "chain": list[str],
         "dangling": bool,
         "takeover_service": str | None,   # matching suffix if any
         "error": str | None}              # for observability only

    Rule 1: an inconclusive probe (`error` set with `cname_present`
    False) MUST NOT set `dangling`. Callers only fire findings on
    `dangling=True`.
    """
    final, chain, err = _follow_cname_chain(domain)
    if not chain:
        # No CNAME on the input; nothing to check. If the initial
        # query errored (before we saw a CNAME), report as
        # cname_present=False, dangling=False — an UNKNOWN outcome
        # for the caller.
        return {"cname_present": False, "chain": [], "dangling": False,
                "takeover_service": None, "error": err if err else None}

    if err == "NXDOMAIN":
        dangling = True
    elif err is None:
        # Chain terminated normally; the last name exists at the
        # resolver level. Check A/AAAA — a name that exists but has
        # no A/AAAA is dangling from a takeover perspective (nothing
        # to serve the request).
        a = dnsmod.query(final, "A")
        aaaa = dnsmod.query(final, "AAAA")
        a_empty = a["ok"] and not a.get("records")
        aaaa_empty = aaaa["ok"] and not aaaa.get("records")
        a_nx = a.get("error") == "NXDOMAIN"
        aaaa_nx = aaaa.get("error") == "NXDOMAIN"
        dangling = (a_empty and aaaa_empty) or (a_nx and aaaa_nx)
    else:
        # LOOP or resolver error at the CNAME step. Rule 1: do not
        # fire a finding on inconclusive data.
        return {"cname_present": True, "chain": chain, "dangling": False,
                "takeover_service": None, "error": err}

    takeover_service = _matches_takeover_service(final) if dangling else None
    return {"cname_present": True, "chain": chain, "dangling": dangling,
            "takeover_service": takeover_service, "error": err}
