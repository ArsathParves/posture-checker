"""Core: normalization, RDAP bootstrap + lookup, shared types."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_IP_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json"
# S9: outbound HTTP must name the tool + version + a contact URL.
# Third parties (IANA, ARIN, NIXI, DNS/RDAP registries) get our traffic;
# a distinctive UA lets them rate-limit our tool specifically instead
# of an entire IP block, and gives them a way to reach us if the tool's
# traffic pattern is problematic.
UA = "posture-checker/0.5 (+https://github.com/vergecloud/posture-checker)"
HEADERS = {"Accept": "application/rdap+json", "User-Agent": UA}
# For non-RDAP outbound calls (IANA bootstrap, follow-up JSON fetches
# where the server is not necessarily an RDAP endpoint).
UA_HEADERS = {"User-Agent": UA}

# ---------------------------------------------------------------- findings


@dataclass
class Finding:
    """A single posture observation. severity drives grading + display."""

    section: str
    label: str
    status: str  # PASS | WARN | FAIL | INFO | UNKNOWN
    detail: str = ""
    why: str = ""  # why it matters (shown to user)
    # True when this finding represents adoption/absence of an optional
    # hardening feature (DNSSEC signing, CAA, MTA-STS, IPv6, DMARC rua, ...)
    # rather than a real misconfiguration. Read by `checks.grade`:
    #   - PASS + hardening=True → credit in both correctness and hardening buckets
    #   - WARN/FAIL + hardening=True → hardening bucket only (does not drag correctness)
    #   - hardening=False → correctness bucket regardless of status
    # Emit-site is authoritative — the classification lives with the check
    # that knows the answer, not in a global label set in grade().
    hardening: bool = False
    # T2 severity tier: "" (default, ordinary) or "CRITICAL". A CRITICAL
    # FAIL/WARN floors its section grade to F and the overall grade to F —
    # a full-zone AXFR leak or a registry-hold state cannot be diluted by
    # surrounding PASSes on other checks. CRITICAL PASS is legal but has
    # no floor effect (you passed the critical check). CRITICAL UNKNOWN
    # does NOT floor (rule 1: unretrievable stays unretrievable).
    # Orthogonal to `hardening`: a CRITICAL marker overrides the
    # hardening classification for grading purposes to prevent a
    # "hardening hides critical" false negative.
    severity: str = ""
    # T5 confidence tier: informational, UI-only. Never fed into grading —
    # if it were, callers would be tempted to downgrade a broken finding to
    # `low` to soften the report. Tiers:
    #   "high"   — authoritative-server read, multi-vantage consensus, or a
    #              validated cryptographic computation (DS→DNSKEY chain).
    #   "medium" — single-resolver answer, cached response, or a single-
    #              probe result agreeing with the tool's expectation.
    #   "low"    — indirect/inferred signal, or a partial-probe result.
    #   ""       — default; the caller made no claim.
    # Migration of specific emit sites to declare `confidence=` is
    # follow-up work (same shape as T2's mechanism-first pattern).
    confidence: str = ""
    # T1 stable identifier: display-independent handle for external
    # consumers (JSON --output, SPA remediation lookups, cross-run
    # diffs). Grading MUST NOT read this field — if it did, external
    # callers could steer grades by injecting IDs, and rewording a
    # display label would break grading (the exact bug this field
    # exists to prevent). Empty string is the pre-T1 default; migration
    # of specific emit sites is follow-up work (mechanism-first, same
    # shape as T2 severity and T5 confidence).
    finding_id: str = ""

    @property
    def is_scored(self) -> bool:
        return self.status in {"PASS", "WARN", "FAIL"}

    @property
    def is_critical(self) -> bool:
        return self.severity == "CRITICAL"


# ---------------------------------------------------------------- remediation
#
# B36 — remediation guidance is a two-field structure, not a plain string.
#
# CLAUDE.md rule 7 forbids the pattern "every remediation is a VergeCloud
# sales line" because a tool where every finding routes to "switch
# vendors" reads as a funnel and burns the credibility the tool exists
# for. The neutrality mandate is easier to hold if the type system
# enforces it — a plain-string remediation column lets someone add a
# vendor-first line six months from now and no test catches it, but a
# `Remediation(general, vendor)` type forces every new entry to answer
# "what is the general RFC / protocol fix?" before adding vendor-
# specific augmentation.
#
# The renderer's job is to emit `general` first (primary text) and
# `vendor`, if present, as a secondary rider. Tests in
# `test_remediation_vendor_neutrality.py` lock the contract.


@dataclass(frozen=True)
class Remediation:
    """Remediation guidance for a single finding label.

    `general` — the RFC / protocol / vendor-agnostic fix. Required.
        This is the primary text the reader acts on regardless of
        their DNS provider.
    `vendor` — an OPTIONAL VergeCloud-specific rider naming the
        product capability that addresses the same issue. Rendered
        secondary to `general`, visually distinct.

    Frozen so entries can be reused across renderers without a caller
    accidentally mutating the general-fix text at runtime.
    """
    general: str
    vendor: str = ""


@dataclass
class Report:
    domain_input: str
    domain: str = ""
    punycode: str = ""
    checked_at: float = field(default_factory=time.time)
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    degraded: list[str] = field(default_factory=list)  # modules that failed

    def add(self, section, label, status, detail="", why="",
            hardening=False, severity="", confidence="", finding_id=""):
        self.findings.append(Finding(section, label, status, detail, why,
                                     hardening, severity, confidence,
                                     finding_id))

    def section(self, name: str) -> list[Finding]:
        return [f for f in self.findings if f.section == name]


# ---------------------------------------------------------------- normalize


def normalize_domain(raw: str) -> tuple[str, str, list[str]]:
    """Return (display_domain, punycode_domain, notes)."""
    notes: list[str] = []
    d = raw.strip().lower()

    # Reject IP addresses upfront
    if re.match(r"^\d+(\.\d+){3}$", d):  # IPv4
        raise ValueError("Enter a domain name, not an IP address")
    if ":" in d and re.match(r"^[0-9a-f:]+$", d):  # IPv6
        raise ValueError("Enter a domain name, not an IP address")

    # strip scheme / path / port / userinfo
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1]
    d = d.split(":")[0]
    d = d.rstrip(".")

    if d.startswith("www."):
        d = d[4:]
        notes.append("Stripped leading 'www.' — checking the apex domain")

    if not d or "." not in d:
        raise ValueError(f"'{raw}' does not look like a domain name")

    # IDN handling: keep both forms. Homograph safety = always show punycode.
    try:
        puny = d.encode("idna").decode("ascii")
    except Exception:
        # IDNA2003 codec rejects some valid labels; fall back per-label
        try:
            puny = ".".join(
                lbl.encode("idna").decode("ascii") if not lbl.isascii() else lbl
                for lbl in d.split(".")
            )
        except Exception:
            raise ValueError(f"'{raw}' contains characters that are not a valid domain")

    if puny != d:
        notes.append(f"Internationalised domain — punycode form is {puny}")

    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", puny):
        raise ValueError(f"'{raw}' is not a syntactically valid domain")

    # RFC 1035 §2.3.4: total name length must be 253 octets or less
    # (excluding the trailing dot). Checked before per-label so operators
    # see the more informative diagnostic on grossly oversized input.
    if len(puny) > 253:
        raise ValueError(
            f"Domain total length {len(puny)} exceeds 253 octets (RFC 1035 §2.3.4)"
        )

    # RFC 1035: labels must be 63 octets or less
    labels = puny.split(".")
    for lbl in labels:
        if len(lbl) > 63:
            raise ValueError(f"Label '{lbl}' exceeds 63 octets (RFC 1035)")

    # RFC requirement: TLDs must be at least 2 characters
    if labels[-1] and len(labels[-1]) < 2:
        raise ValueError(f"TLD '{labels[-1]}' must be at least 2 characters")

    return d, puny, notes


# ---------------------------------------------------------------- RDAP

def _extract_vcard_fn(vcard: list) -> str | None:
    """Safely extract FN (formatted name) from vCard component.

    RFC 6350: vCard structure varies by tool; FN component may have different formats.
    This function safely extracts the text value without assumptions about indexing.

    E7: The returned string is NFC-normalised and whitespace-stripped so
    that two RDAP responses containing the same visible name are byte-
    identical (an NFD payload from one registry and an NFC payload from
    another must not dedupe as different) and so that stray CR/LF or
    padding from malformed payloads never propagates into findings.
    A non-string value (some vCard emitters ship a list at item[3])
    returns None rather than raising or leaking a list downstream.
    """
    import unicodedata

    if not vcard or len(vcard) < 2:
        return None
    try:
        for item in vcard[1]:  # vCard components are in [1]
            if item and len(item) >= 4 and item[0] == "fn":
                value = item[3]
                if not isinstance(value, str):
                    return None
                normalised = unicodedata.normalize("NFC", value).strip()
                return normalised or None
    except (IndexError, TypeError):
        pass
    return None


_bootstrap_cache: dict[str, dict] = {}


def _load_bootstrap() -> dict[str, str]:
    """Load RDAP bootstrap data with 24-hour TTL."""
    if "dns" in _bootstrap_cache:
        data, expiry = _bootstrap_cache["dns"]
        if time.time() < expiry:
            return data
        # Cache expired, remove it
        del _bootstrap_cache["dns"]

    r = requests.get(RDAP_BOOTSTRAP_URL, headers=UA_HEADERS, timeout=20)
    r.raise_for_status()
    j = r.json()
    mapping: dict[str, str] = {}
    for svc in j.get("services", []):
        tlds, urls = svc[0], svc[1]
        base = next((u for u in urls if u.startswith("https")), urls[0])
        for t in tlds:
            mapping[t.lower()] = base.rstrip("/") + "/"
    # Cache for 24 hours
    _bootstrap_cache["dns"] = (mapping, time.time() + 86400)
    return mapping


def rdap_endpoint_for(domain: str) -> tuple[str | None, str | None]:
    """Walk labels right-to-left. Returns (endpoint, matched_suffix).

    Needed because bootstrap keys on the delegated TLD only: 'co.in' has no
    entry of its own, it must resolve via the '.in' entry.
    """
    mapping = _load_bootstrap()
    labels = domain.split(".")
    for i in range(len(labels) - 1, -1, -1):
        suffix = ".".join(labels[i:])
        if suffix in mapping:
            return mapping[suffix], suffix
    return None, None


def rdap_lookup(domain: str) -> dict:
    """Returns dict with keys: ok, status, data|error, endpoint, suffix."""
    ep, suffix = rdap_endpoint_for(domain)
    if not ep:
        return {
            "ok": False,
            "error": "no_rdap_for_tld",
            "endpoint": None,
            "suffix": None,
            "status": None,
        }
    url = f"{ep}domain/{domain}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=25, allow_redirects=True)
    except requests.RequestException as e:
        return {"ok": False, "error": f"transport:{type(e).__name__}", "endpoint": ep,
                "suffix": suffix, "status": None}

    if r.status_code == 404:
        return {"ok": False, "error": "not_found", "endpoint": ep, "suffix": suffix,
                "status": 404}
    if r.status_code == 429:
        return {"ok": False, "error": "rate_limited", "endpoint": ep, "suffix": suffix,
                "status": 429}
    if r.status_code != 200:
        return {"ok": False, "error": f"http_{r.status_code}", "endpoint": ep,
                "suffix": suffix, "status": r.status_code}
    try:
        return {"ok": True, "data": r.json(), "endpoint": ep, "suffix": suffix,
                "status": 200}
    except ValueError:
        return {"ok": False, "error": "bad_json", "endpoint": ep, "suffix": suffix,
                "status": 200}


def parse_rdap(j: dict) -> dict:
    """Extract the fields we display from an RDAP domain object."""
    out: dict[str, Any] = {
        "registrar": None,
        "registrar_iana_id": None,
        "nameservers": [],
        "status": j.get("status", []) or [],
        "events": {},
        "redacted": False,
        "entity_roles": [],
    }
    for ns in j.get("nameservers", []) or []:
        name = ns.get("ldhName") or ns.get("unicodeName")
        if name:
            out["nameservers"].append(name.lower().rstrip("."))

    for ev in j.get("events", []) or []:
        act = ev.get("eventAction")
        if act:
            out["events"][act] = ev.get("eventDate")

    for ent in j.get("entities", []) or []:
        roles = ent.get("roles", []) or []
        out["entity_roles"].extend(roles)
        if "registrar" in roles:
            # vCard fn is the registrar name
            vcard = ent.get("vcardArray")
            out["registrar"] = _extract_vcard_fn(vcard)
            for pid in ent.get("publicIds", []) or []:
                if "IANA" in str(pid.get("type", "")).upper():
                    out["registrar_iana_id"] = pid.get("identifier")
            if not out["registrar"]:
                out["registrar"] = ent.get("handle")

    # redaction signalling: ICANN redaction extension, or literal markers
    if "redacted" in str(j.get("rdapConformance", "")).lower() or j.get("redacted"):
        out["redacted"] = True

    return out


# ---------------------------------------------------------------- IP RDAP / ASN

_ip_bootstrap: dict[str, Any] = {}

# --- ASN lookup via Team Cymru DNS whois (free, no auth, no rate limit) -----
# IP-range RDAP registrant is unreliable for leased ranges — it returns the
# maintainer or "Private Customer" instead of the actual network operator,
# which fabricates network diversity when multiple ranges share one ASN.
# ASN ownership is the correct grain for the "who runs this NS" question.
def cymru_asn(ip: str) -> dict:
    """Look up (ASN, ASN owner) for an IP via Team Cymru DNS whois.

    Retries through multiple public resolvers to avoid SPOF on a single resolver.
    """
    import dns.resolver

    # List of resolvers to try (includes more than just Cloudflare and Google)
    resolvers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"]

    for resolver_ip in resolvers:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [resolver_ip]
        r.timeout = 4
        r.lifetime = 8
        try:
            rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
            ans = r.resolve(rev, "TXT")
            parts = [p.strip() for p in str(ans[0]).strip('"').split("|")]
            # Cymru's origin.asn TXT can carry multiple ASNs (multi-origin
            # IPs). Take the first, coerce to int at THE BOUNDARY — every
            # downstream table (LARGE_ANYCAST_ASNS) is keyed on int and
            # would silently miss a string here.
            asn_token = parts[0].split()[0]
            asn = int(asn_token)
            try:
                ans2 = r.resolve(f"AS{asn}.asn.cymru.com", "TXT")
                owner = [p.strip() for p in str(ans2[0]).strip('"').split("|")][-1]
            except Exception:
                owner = f"AS{asn}"
            return {"ok": True, "asn": asn, "prefix": parts[1] if len(parts) > 1 else None,
                    "cc": parts[2] if len(parts) > 2 else None, "owner": owner}
        except Exception:
            continue  # Try next resolver

    return {"ok": False, "error": "all_resolvers_failed"}



def _ip_endpoints(ip: str) -> list[str]:
    """Resolve the authoritative RIR endpoint via IANA bootstrap.

    rdap.org is a redirector and is a single point of failure; querying the
    owning RIR directly is both faster and more reliable.
    """
    import ipaddress

    urls = []
    try:
        # Load IP bootstrap with 24-hour TTL
        if "ipv4" not in _ip_bootstrap:
            r = requests.get(RDAP_IP_BOOTSTRAP_URL, headers=UA_HEADERS, timeout=20)
            r.raise_for_status()
            data = r.json()
            _ip_bootstrap["ipv4"] = (data, time.time() + 86400)
        elif isinstance(_ip_bootstrap["ipv4"], tuple):
            data, expiry = _ip_bootstrap["ipv4"]
            if time.time() >= expiry:
                # Cache expired, reload
                r = requests.get(RDAP_IP_BOOTSTRAP_URL, headers=UA_HEADERS, timeout=20)
                r.raise_for_status()
                data = r.json()
                _ip_bootstrap["ipv4"] = (data, time.time() + 86400)
        else:
            # Handle legacy non-tuple format
            data = _ip_bootstrap["ipv4"]

        addr = ipaddress.ip_address(ip)
        bootstrap_data = data if isinstance(data, dict) else _ip_bootstrap["ipv4"]
        for svc in bootstrap_data.get("services", []):
            for cidr in svc[0]:
                try:
                    if addr in ipaddress.ip_network(cidr):
                        base = next((u for u in svc[1] if u.startswith("https")), svc[1][0])
                        urls.append(base.rstrip("/") + f"/ip/{ip}")
                except ValueError:
                    continue
    except Exception:
        pass
    urls.append(f"https://rdap.org/ip/{ip}")
    return urls


def ip_rdap(ip: str) -> dict:
    """Look up network/ASN owner for an IP.

    Preference order:
      1. Team Cymru IP-to-ASN + AS-name lookup (authoritative for operator ID)
      2. RIR-direct RDAP via IANA bootstrap (fills in netname, country)
      3. rdap.org redirector (last resort)

    ASN owner beats IP-range registrant: a leased /24 shows "Private Customer"
    in RIR whois but resolves to the operating AS via Cymru.
    """
    cymru = cymru_asn(ip)
    if cymru.get("ok"):
        # Optional secondary RDAP for netname/country enrichment; do not let it
        # override the operator identity from Cymru.
        base = {"ok": True, "asn": cymru["asn"], "prefix": cymru.get("prefix"),
                "country": cymru.get("cc"), "org": cymru["owner"],
                "source": "cymru_asn"}
        return base

    # Cymru failed — fall back to RDAP for at least a partial answer.
    j = None
    last = None
    for url in _ip_endpoints(ip):
        try:
            r = requests.get(url, headers=HEADERS, timeout=15)
            if r.status_code == 200:
                j = r.json()
                break
            last = f"http_{r.status_code}"
        except requests.RequestException as e:
            last = f"transport:{type(e).__name__}"
    if j is None:
        return {"ok": False, "error": last or "no_endpoint"}
    try:
        name = j.get("name")
        handle = j.get("handle")
        country = j.get("country")
        # Entity ordering is NOT role ordering. Taking entities[0] picks up
        # maintainer (-mnt) and incident-response (IRT-) objects and reports
        # them as the operator, which fabricates network diversity.

        def _is_object_handle(v):
            if not v:
                return True
            low = v.lower()
            return (low.endswith("-mnt") or low.startswith("irt-")
                    or low.startswith("mnt-") or low.endswith("-mntner"))

        org = None
        ents = j.get("entities", []) or []
        for wanted in ("registrant", "administrative", "technical"):
            for ent in ents:
                if wanted in (ent.get("roles") or []):
                    cand = _extract_vcard_fn(ent.get("vcardArray"))
                    if not _is_object_handle(cand):
                        org = cand
                        break
            if org:
                break
        # net name (e.g. VERGE-IN) is a better fallback than a maintainer handle
        if not org:
            org = name or handle
        return {"ok": True, "name": name, "handle": handle, "country": country,
                "org": org, "source": "rir_rdap"}
    except Exception as e:
        return {"ok": False, "error": f"parse:{type(e).__name__}"}
