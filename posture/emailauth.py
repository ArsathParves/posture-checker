"""SPF / DKIM / DMARC evaluation."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .dnsmod import query

# RFC 7208 s4.6.4: these mechanisms cost a DNS lookup; limit is 10.
LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}


class TxtUnretrievable(Exception):
    """TXT data could not be retrieved. NOT the same as the record being absent.

    ROOT CAUSE PRINCIPLE (CLAUDE.md rule 1): three states — not-applicable /
    unretrievable / broken — must never collapse into each other. This
    exception is how the wire layer signals "unretrievable" so SPF / DKIM /
    DMARC / MTA-STS / TLS-RPT callers can propagate UNKNOWN cleanly instead
    of reporting `absent` (which is `broken`).
    """

# DKIM has no discoverable selector list in DNS — we can only probe known ones.
# Result must always be labelled "not found under common selectors".
# Includes major Western and India-region ESPs.
COMMON_SELECTORS = [
    # Generic
    "default", "selector1", "selector2", "k1", "k2", "k3",
    "mail", "dkim", "s1", "s2", "smtp", "sig1",
    "s2048",  # Yahoo/AOL legacy + generic 2048-bit key marker (FN2)
    # Western ESPs
    "google", "mandrill", "everlytickey1", "mailjet", "sendgrid",
    "zoho", "zmail", "pm", "postmarkapp",  # Postmark ships both `pm` and `postmarkapp` (FN2)
    "litesrv", "protonmail", "amazonses",
    "hs1", "hs2", "mimecast20220101",
    "ml1", "ml2",  # MailerLite (FN2)
    "mxvault",     # Mailgun shared-IP selector (FN2)
    "salesforce",  # Salesforce marketing cloud (FN2)
    # India-region ESPs (BFSI focus)
    "netcore", "pepipost", "zeptomail", "kaleyra", "gupshup",
]


def _txt_records(domain: str) -> list[str]:
    res = query(domain, "TXT")
    if not res.get("ok"):
        error = res.get("error") or "UNKNOWN"
        # NXDOMAIN is the one legitimate absence signal — the domain
        # does not exist, so the record cannot exist either. Everything
        # else (SERVFAIL, TIMEOUT, TRUNCATED_NO_TCP, generic transport
        # exceptions) means the answer was unobtainable, NOT confirmed
        # absent, and MUST raise so downstream (SPF/DMARC/MTA-STS/TLS-
        # RPT/DKIM) doesn't collapse "unretrievable" into "broken".
        if error == "NXDOMAIN":
            return []
        raise TxtUnretrievable(f"{error}: {res.get('note') or error}")
    out = []
    for r in res.get("records", []):
        # dnspython quotes TXT chunks; join split strings
        joined = "".join(part.strip('"') for part in r.split('" "'))
        out.append(joined.strip('"'))
    return out


# ---------------------------------------------------------------- SPF


def _count_spf_lookups(record: str, domain: str, depth=0, seen=None) -> tuple[int, list]:
    """Recursively count DNS-querying mechanisms. Returns (count, trace).

    RFC 7208 compliance (§4.6.4):
    - The "10 DNS-lookup limit" counts each DNS-term mechanism
      (include, a, mx, ptr, exists) and the redirect modifier as exactly 1.
      Exceeding 10 total forces permerror.
    - The A/AAAA lookups triggered by an mx or ptr mechanism have their
      own secondary cap (>10 targets → permerror) but do NOT add to the
      primary 10-term budget. So ``mx = 1`` here, matching mxtoolbox,
      dmarcian, opendmarc, and every other RFC-compliant validator.
    - §6.1: redirect= is ignored if a terminal 'all' mechanism is present.
    """
    if seen is None:
        seen = frozenset()
    if depth > 10 or domain in seen:
        return 0, []
    # B12: cycle-detect per call chain, not globally. Copy-on-add
    # (frozenset) so a shared dependency (`a → c` and `b → c`) is
    # counted afresh in each branch — RFC 7208 §4.6.4 counts each
    # DNS-term mechanism as one lookup per appearance, regardless of
    # whether a sibling branch already visited the target. A global
    # `seen` short-circuit undercounts and lets truly over-limit
    # records grade PASS.
    seen = seen | {domain}

    # Check if record has 'all' mechanism (RFC 7208 §6.1)
    has_all = any(term.lower().endswith("all") for term in record.split())

    count = 0
    trace = []
    for term in record.split():
        t = term.lower().lstrip("+-~?")
        if t.startswith("include:"):
            target = term.split(":", 1)[1]
            count += 1
            trace.append(f"include:{target}")
            # B13: recurse as far as the entry guard allows (`depth > 10`).
            # The previous `depth < 5` gate silently truncated count and
            # trace for real chains — a 10-deep include chain graded as
            # 6 lookups and RFC-compliant when it was actually at the
            # limit. Cycle protection is handled by the per-path `seen`
            # frozenset (B12); runaway depth is bounded by `depth > 10`.
            sub = get_spf(target)
            if sub.get("record"):
                c, tr = _count_spf_lookups(sub["record"], target, depth + 1, seen)
                count += c
                trace.extend(f"  {x}" for x in tr)
        elif t.startswith("redirect="):
            # RFC 7208 §6.1: redirect is ignored if 'all' is present
            if not has_all:
                target = term.split("=", 1)[1]
                count += 1
                trace.append(f"redirect={target}")
                sub = get_spf(target)
                if sub.get("record"):
                    c, tr = _count_spf_lookups(sub["record"], target, depth + 1, seen)
                    count += c
                    trace.extend(f"  {x}" for x in tr)
        elif t == "mx" or t.startswith("mx:"):
            # RFC 7208 §4.6.4: mx counts as one DNS-term toward the 10-limit.
            # Nested A/AAAA lookups on MX targets have their own separate cap
            # (>10 targets → permerror) and do NOT add to the primary budget.
            count += 1
            trace.append(term)
        else:
            base = t.split(":")[0].split("=")[0]
            if base in LOOKUP_MECHANISMS:
                count += 1
                trace.append(term)
    return count, trace


def get_spf(domain: str) -> dict:
    try:
        txts = [t for t in _txt_records(domain) if t.lower().startswith("v=spf1")]
    except TxtUnretrievable as e:
        return {"present": None, "record": None, "unretrievable": str(e)}
    if not txts:
        return {"present": False, "record": None}
    if len(txts) > 1:
        return {"present": True, "record": txts[0], "multiple": True, "all_records": txts}
    return {"present": True, "record": txts[0], "multiple": False}


def evaluate_spf(domain: str) -> dict:
    r = get_spf(domain)
    out: dict[str, Any] = dict(r)
    if not r["present"]:
        return out
    rec = r["record"]
    count, trace = _count_spf_lookups(rec, domain)
    out["lookup_count"] = count
    out["lookup_trace"] = trace
    out["exceeds_limit"] = count > 10

    # qualifier on 'all'
    qual = None
    for term in rec.split():
        if term.lower().endswith("all"):
            qual = term
    out["all_qualifier"] = qual
    if qual:
        if qual.startswith("-"):
            out["all_strength"] = "hardfail"
        elif qual.startswith("~"):
            out["all_strength"] = "softfail"
        elif qual.startswith("?") or qual.startswith("+"):
            out["all_strength"] = "neutral_or_pass"
    else:
        out["all_strength"] = "missing"
    return out


# ---------------------------------------------------------------- DKIM


def _dkim_key_state(record: str) -> str:
    """RFC 6376 s3.6.1: an empty p= means the key is REVOKED, not present."""
    low = record.lower().replace(" ", "")
    if "v=dkim1" not in low and "p=" not in low:
        return "not_dkim"
    for part in record.split(";"):
        if part.strip().lower().startswith("p="):
            value = part.split("=", 1)[1].strip()
            return "revoked" if not value else "valid"
    return "malformed"


def evaluate_dkim(domain: str, extra_selectors=None) -> dict:
    import uuid

    # Wildcard guard: if a random selector answers, *._domainkey is wildcarded
    # and every probe will "succeed". Without this, example.com reports DKIM
    # found under all 26 selectors when it is actually publishing a revoked key.
    canary = f"probe{uuid.uuid4().hex[:10]}"
    try:
        cres_recs = _txt_records(f"{canary}._domainkey.{domain}")
        if cres_recs:
            joined = " ".join(cres_recs)
            state = _dkim_key_state(joined)
            return {
                "found": False,
                "selectors": [],
                "probed": 0,
                "wildcard": True,
                "key_state": state,
                "label": ("Wildcard _domainkey publishing a REVOKED key (empty p=)"
                          if state == "revoked"
                          else "Wildcard _domainkey record present — per-selector "
                               "results are not meaningful"),
            }
    except TxtUnretrievable as e:
        # TXT records are unretrievable (truncated + no TCP, timeout, etc.)
        # Cannot complete DKIM check
        return {
            "found": None,
            "selectors": [],
            "probed": 0,
            "wildcard": None,
            "unretrievable": str(e),
            "label": f"DKIM check could not complete: {e}",
        }

    selectors = list(COMMON_SELECTORS)
    if extra_selectors:
        selectors = list(extra_selectors) + selectors
    def probe(sel):
        try:
            res_recs = _txt_records(f"{sel}._domainkey.{domain}")
            if res_recs:
                joined = " ".join(res_recs)
                state = _dkim_key_state(joined)
                if state in ("valid", "revoked"):
                    return {"selector": sel, "record": joined[:120], "state": state}
        except TxtUnretrievable:
            # If any selector is unretrievable, mark the whole check unretrievable
            return {"unretrievable": True}
        return None

    with ThreadPoolExecutor(max_workers=12) as ex:
        results = list(ex.map(probe, selectors))

    if any(r and r.get("unretrievable") for r in results):
        return {
            "found": None,
            "selectors": [],
            "probed": len(selectors),
            "wildcard": False,
            "unretrievable": "Some DKIM selectors could not be retrieved",
            "label": "DKIM check incomplete: one or more selectors unretrievable",
        }

    found = [r for r in results if r]
    valid = [f for f in found if f["state"] == "valid"]
    revoked = [f for f in found if f["state"] == "revoked"]
    return {
        "found": bool(valid),
        "selectors": valid,
        "revoked": revoked,
        "probed": len(selectors),
        "wildcard": False,
        # critical: never report absence as fact
        "label": ("Found" if valid else "Not found under common selectors"),
    }


# ---------------------------------------------------------------- DMARC


def evaluate_dmarc(domain: str) -> dict:
    try:
        txts = [t for t in _txt_records(f"_dmarc.{domain}")
                if t.lower().startswith("v=dmarc1")]
    except TxtUnretrievable as e:
        return {"present": None, "unretrievable": str(e)}
    if not txts:
        return {"present": False}
    rec = txts[0]
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p", "none").lower()
    strength = {"reject": "strong", "quarantine": "moderate", "none": "weak"}.get(
        policy, "unknown")
    # E5: RFC 7489 §6.6.3 — if more than one v=DMARC1 record is present,
    # receivers apply NO DMARC-based decision. Silently picking txts[0]
    # (v0.5 behaviour) reports a policy that validators are ignoring.
    # Surface `multiple` + `all_records` so the emit layer can FAIL and
    # enumerate the offending records.
    return {
        "present": True, "record": rec, "policy": policy, "strength": strength,
        "subdomain_policy": tags.get("sp"), "pct": tags.get("pct", "100"),
        "rua": tags.get("rua"), "ruf": tags.get("ruf"),
        "alignment_dkim": tags.get("adkim", "r"), "alignment_spf": tags.get("aspf", "r"),
        "multiple": len(txts) > 1,
        "all_records": txts if len(txts) > 1 else None,
    }


def _parse_dmarc_uri(raw: str) -> tuple[str | None, str | None]:
    """Return `(scheme, host)` for a DMARC rua/ruf URI, or `(None, None)`
    if unparseable. RFC 7489 allows any URI but only `mailto:` gets
    verification here — other schemes are surfaced as parse_error so
    the operator sees them."""
    raw = raw.strip()
    if not raw.lower().startswith("mailto:"):
        return None, None
    addr = raw[len("mailto:"):]
    if "@" not in addr:
        return "mailto", None
    _, host = addr.rsplit("@", 1)
    # rua supports `!<size>` suffix (RFC 7489 §6.2) — strip it.
    host = host.split("!", 1)[0].strip().rstrip(".")
    return "mailto", host.lower() if host else None


def evaluate_dmarc_reporting(domain: str,
                             rua: str | None = None,
                             ruf: str | None = None) -> dict:
    """RFC 7489 §7.1 External Destination Verification.

    For each rua/ruf mailto: destination whose host domain differs from
    the DMARC-record's domain, query the verification TXT at
    `<record-domain>._report._dmarc.<destination-domain>`. Presence of
    a `v=DMARC1` TXT is opt-in; anything else means mail receivers
    will refuse to send reports there.

    Returns `{"destinations": [...]}`. Each entry:
      - `tag`: "rua" | "ruf"
      - `raw`: original URI as published in the DMARC record
      - `domain`: extracted host (may be None on parse error)
      - `external`: True if host != checked domain
      - `verified`: True | False | None (None ⇒ unretrievable)
      - `unretrievable`: True if verification query failed transport
      - `parse_error`: True on unparseable / non-mailto: URIs
    """
    dest: list[dict] = []
    checked = domain.lower().rstrip(".")

    for tag, val in (("rua", rua), ("ruf", ruf)):
        if not val:
            continue
        for raw in val.split(","):
            raw = raw.strip()
            if not raw:
                continue
            scheme, host = _parse_dmarc_uri(raw)
            if scheme is None or host is None:
                dest.append({
                    "tag": tag, "raw": raw, "domain": None,
                    "external": False, "verified": None,
                    "unretrievable": False, "parse_error": True,
                })
                continue
            external = host != checked
            entry: dict = {
                "tag": tag, "raw": raw, "domain": host,
                "external": external, "parse_error": False,
                "unretrievable": False,
            }
            if not external:
                entry["verified"] = True  # same-org — no probe needed
                dest.append(entry)
                continue
            verify_name = f"{checked}._report._dmarc.{host}"
            try:
                txts = _txt_records(verify_name)
            except TxtUnretrievable:
                entry["verified"] = None
                entry["unretrievable"] = True
                dest.append(entry)
                continue
            entry["verified"] = any(
                t.lower().lstrip().startswith("v=dmarc1") for t in txts)
            dest.append(entry)

    return {"destinations": dest}


def evaluate_mta_sts(domain: str) -> dict:
    try:
        sts_records = _txt_records(f"_mta-sts.{domain}")
    except TxtUnretrievable:
        return {"mta_sts": None, "tls_rpt": None, "unretrievable": True}
    txts = [t for t in sts_records if t.lower().startswith("v=stsv1")]
    # TLS-RPT lives at a different name (_smtp._tls.<domain>) so its
    # retrievability is independent of the MTA-STS record. CLAUDE.md
    # rule 1: if this lookup is truncated / TCP/53 is blocked, the
    # correct state is "unknown", NOT "absent" — a False here would
    # render "TLS-RPT: absent" for a domain that in fact publishes one.
    try:
        tlsrpt_records = _txt_records(f"_smtp._tls.{domain}")
    except TxtUnretrievable:
        return {"mta_sts": bool(txts), "tls_rpt": None,
                "tls_rpt_unretrievable": True}
    tlsrpt = [t for t in tlsrpt_records if t.lower().startswith("v=tlsrptv1")]
    return {"mta_sts": bool(txts), "tls_rpt": bool(tlsrpt)}
