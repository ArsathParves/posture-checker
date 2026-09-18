"""Core: normalization, RDAP bootstrap + lookup, shared types."""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_IP_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json"
UA = "vergecloud-posture-checker/0.1 (prototype)"
HEADERS = {"Accept": "application/rdap+json", "User-Agent": UA}

# ---------------------------------------------------------------- findings


@dataclass
class Finding:
    """A single posture observation. severity drives grading + display."""

    section: str
    label: str
    status: str  # PASS | WARN | FAIL | INFO | UNKNOWN
    detail: str = ""
    why: str = ""  # why it matters (shown to user)

    @property
    def is_scored(self) -> bool:
        return self.status in {"PASS", "WARN", "FAIL"}


@dataclass
class Report:
    domain_input: str
    domain: str = ""
    punycode: str = ""
    checked_at: float = field(default_factory=time.time)
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    degraded: list[str] = field(default_factory=list)  # modules that failed

    def add(self, section, label, status, detail="", why=""):
        self.findings.append(Finding(section, label, status, detail, why))

    def section(self, name: str) -> list[Finding]:
        return [f for f in self.findings if f.section == name]


# ---------------------------------------------------------------- normalize


def normalize_domain(raw: str) -> tuple[str, str, list[str]]:
    """Return (display_domain, punycode_domain, notes)."""
    notes: list[str] = []
    d = raw.strip().lower()

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

    return d, puny, notes


# ---------------------------------------------------------------- RDAP

_bootstrap_cache: dict[str, dict] = {}


def _load_bootstrap() -> dict[str, str]:
    if "dns" in _bootstrap_cache:
        return _bootstrap_cache["dns"]
    r = requests.get(RDAP_BOOTSTRAP_URL, timeout=20)
    r.raise_for_status()
    j = r.json()
    mapping: dict[str, str] = {}
    for svc in j.get("services", []):
        tlds, urls = svc[0], svc[1]
        base = next((u for u in urls if u.startswith("https")), urls[0])
        for t in tlds:
            mapping[t.lower()] = base.rstrip("/") + "/"
    _bootstrap_cache["dns"] = mapping
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
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        out["registrar"] = item[3]
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
    """Look up (ASN, ASN owner) for an IP via Team Cymru DNS whois."""
    import dns.resolver
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ["1.1.1.1", "8.8.8.8"]
    r.timeout = 4
    r.lifetime = 8
    try:
        rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        ans = r.resolve(rev, "TXT")
        parts = [p.strip() for p in str(ans[0]).strip('"').split("|")]
        asn = parts[0].split()[0]
        try:
            ans2 = r.resolve(f"AS{asn}.asn.cymru.com", "TXT")
            owner = [p.strip() for p in str(ans2[0]).strip('"').split("|")][-1]
        except Exception:
            owner = f"AS{asn}"
        return {"ok": True, "asn": asn, "prefix": parts[1] if len(parts) > 1 else None,
                "cc": parts[2] if len(parts) > 2 else None, "owner": owner}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}



def _ip_endpoints(ip: str) -> list[str]:
    """Resolve the authoritative RIR endpoint via IANA bootstrap.

    rdap.org is a redirector and is a single point of failure; querying the
    owning RIR directly is both faster and more reliable.
    """
    import ipaddress

    urls = []
    try:
        if "ipv4" not in _ip_bootstrap:
            r = requests.get(RDAP_IP_BOOTSTRAP_URL, timeout=20)
            r.raise_for_status()
            _ip_bootstrap["ipv4"] = r.json()
        addr = ipaddress.ip_address(ip)
        for svc in _ip_bootstrap["ipv4"].get("services", []):
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
        def _fn(ent):
            vcard = ent.get("vcardArray")
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        return item[3]
            return None

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
                    cand = _fn(ent)
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
