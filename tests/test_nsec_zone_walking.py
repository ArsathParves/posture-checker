"""B24 — NSEC vs NSEC3 zone-enumeration exposure.

DNSSEC's denial-of-existence proofs come in two forms (RFC 4034 §4 vs
RFC 5155): NSEC returns *the next existing name* in the zone,
producing a linked list an attacker can walk to enumerate every
owner name in the zone; NSEC3 hashes owner names, so enumeration
requires an offline hash-guessing attack (feasible only with weak
salts/iterations).

For BFSI customers, a walkable zone is a real information-disclosure
risk: `internetbanking-uat.$victim`, `swift.$victim`, `hsm.$victim`
are the exact hostnames a targeted attacker wants to discover.

RFC 9276 (Aug 2022) additionally recommends **iterations = 0** for
NSEC3 and formally deprecates high iteration counts (previously
common; a legacy signer defaulting to 100 no longer meets current
guidance). Above 100 is discouraged; above 150 is a WARN-worthy
misconfiguration on modern infrastructure.

Rule 1 sanity:
  - Unsigned zone → not applicable (no denial-of-existence proofs
    exist at all); no finding.
  - Signed zone whose denial-of-existence probe timed out or was
    intercepted → UNKNOWN (never absent).
  - NSEC → WARN + hardening=False (real, exploitable disclosure).
  - NSEC3 iterations 0 → PASS.
  - NSEC3 iterations ≤ 100 → PASS (legacy but within contemporary
    interpretation of RFC 9276).
  - NSEC3 iterations > 100 → WARN + hardening=True (deprecated per
    RFC 9276 — a hardening-bucket signal, not a correctness failure).
"""
from __future__ import annotations

import dns.message
import dns.rdatatype
import dns.rrset

from posture import dnsmod, checks as c
from posture.core import Report


# --------------------------------------------------------------------- unit: dnsmod.nsec_type

def _mk_nsec_response():
    """Synthesise a DNS response containing an NSEC record in the
    authority section — the shape a signed zone returns for NXDOMAIN."""
    resp = dns.message.QueryMessage()
    resp.authority.append(dns.rrset.from_text_list(
        "example.com.", 3600, "IN", "NSEC",
        ["a.example.com. A NS SOA MX AAAA RRSIG NSEC DNSKEY"],
    ))
    return resp


def _mk_nsec3_response(iterations: int, flags: int = 0):
    """Synthesise a DNS response with an NSEC3 authority record.
    RFC 5155 §3.2 wire format: `hash-alg flags iterations salt
    next-hashed [type-bits]`. dnspython's from_text_list parses the
    display representation.

    dnspython accepts NSEC3 tokens; the exact `next-hashed` value is
    arbitrary here — we only exercise the iterations field the tool
    reads."""
    resp = dns.message.QueryMessage()
    salt = "-"  # no salt
    # A synthetic next-hashed label — dnspython accepts any base32-hex.
    next_hashed = "1234567890abcdefghijklmnopqrstuv"
    resp.authority.append(dns.rrset.from_text_list(
        "example.com.", 3600, "IN", "NSEC3",
        [f"1 {flags} {iterations} {salt} {next_hashed} A RRSIG"],
    ))
    return resp


def test_nsec_type_detects_nsec(monkeypatch):
    """Load-bearing: a zone using NSEC must be surfaced as `NSEC`.
    The tool has no visibility on this without direct wire inspection
    of the authority section."""
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: _mk_nsec_response())
    result = dnsmod.nsec_type("example.com")
    assert result["ok"] is True
    assert result["type"] == "NSEC", (
        f"expected NSEC; got {result}"
    )


def test_nsec_type_detects_nsec3_and_iterations(monkeypatch):
    """NSEC3 detection must also extract the iterations field so
    downstream can enforce RFC 9276."""
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: _mk_nsec3_response(iterations=50))
    result = dnsmod.nsec_type("example.com")
    assert result["ok"] is True
    assert result["type"] == "NSEC3"
    assert result["iterations"] == 50


def test_nsec_type_reports_neither_when_absent(monkeypatch):
    """A zone with no NSEC or NSEC3 in the authority section (either
    unsigned, or the probe missed) yields `type=none`. Downstream
    treats this as UNKNOWN (rule 1: never collapse into absent)."""
    resp = dns.message.QueryMessage()
    monkeypatch.setattr(dnsmod.dns.query, "udp",
                        lambda *a, **kw: resp)
    result = dnsmod.nsec_type("example.com")
    assert result["ok"] is True
    assert result["type"] == "none"


def test_nsec_type_handles_query_failure(monkeypatch):
    """Timeout / socket error / etc. must return `ok=False`, never
    raise. Rule 1: unretrievable stays unretrievable, downstream
    emits UNKNOWN — must not fall through to `type=none`."""
    def _boom(*a, **kw):
        raise Exception("simulated network failure")
    monkeypatch.setattr(dnsmod.dns.query, "udp", _boom)
    result = dnsmod.nsec_type("example.com")
    assert result["ok"] is False


# --------------------------------------------------------------------- integration: _dnssec emission

def _run_dnssec(monkeypatch, dnssec_out, nsec_out):
    """Drive `_dnssec` with a stubbed `dnssec_status` and stubbed
    `nsec_type` so we can assert on the specific finding shape."""
    monkeypatch.setattr(c.dnsmod, "dnssec_status", lambda d: dnssec_out)
    monkeypatch.setattr(c.dnsmod, "nsec_type", lambda d: nsec_out)
    rep = Report(domain_input="example.com", domain="example.com")
    c._dnssec(rep, "example.com")
    return rep


def _findings(rep, label):
    return [f for f in rep.findings if f.label == label]


def _validating_status():
    """Minimal validating-state dict — matches `dnssec_status`
    contract shape."""
    return {
        "state": "validating", "ds": True, "dnskey": True,
        "rrsig": True, "self_signed": True, "ds_matches_dnskey": True,
        "ad_authenticated": True, "algorithms": [], "notes": [],
        "cryptography_available": True,
    }


def test_nsec_on_signed_zone_produces_warn(monkeypatch):
    """The load-bearing case: a signed zone using NSEC is walkable.
    Must emit `Zone-walking exposure` WARN with hardening=False (real,
    exploitable disclosure — not just an adoption-of-hardening gap)."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": True, "type": "NSEC"})
    findings = _findings(rep, "Zone-walking exposure")
    assert findings, (
        f"expected `Zone-walking exposure` finding; got labels: "
        f"{[f.label for f in rep.findings]}"
    )
    f = findings[0]
    assert f.status == "WARN"
    assert f.hardening is False, (
        "NSEC walkability is a real disclosure risk, not a hardening "
        "adoption gap — must not slip into the hardening bucket where "
        "it wouldn't count against correctness"
    )
    assert "NSEC" in f.detail
    assert "walk" in f.detail.lower() or "enumerat" in f.detail.lower()


def test_nsec3_low_iterations_is_pass(monkeypatch):
    """NSEC3 with iterations ≤ 100 is contemporary interpretation of
    RFC 9276. Emit a PASS so operators can see the zone was checked."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": True, "type": "NSEC3", "iterations": 10})
    findings = _findings(rep, "Zone-walking exposure")
    assert findings
    assert findings[0].status == "PASS"


def test_nsec3_zero_iterations_is_pass(monkeypatch):
    """RFC 9276 §3.1 explicitly recommends iterations = 0. Must PASS."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": True, "type": "NSEC3", "iterations": 0})
    findings = _findings(rep, "Zone-walking exposure")
    assert findings
    assert findings[0].status == "PASS"


def test_nsec3_high_iterations_is_warn_hardening(monkeypatch):
    """NSEC3 with iterations > 100 is deprecated per RFC 9276. Emit a
    WARN + hardening=True so operators see the signal without dragging
    correctness. This is a hardening-adoption gap (rotate signer
    config), not a broken-zone bug."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": True, "type": "NSEC3", "iterations": 500})
    findings = _findings(rep, "Zone-walking exposure")
    assert findings
    f = findings[0]
    assert f.status == "WARN"
    assert f.hardening is True
    assert "500" in f.detail
    assert "RFC 9276" in f.detail or "9276" in f.detail


def test_unsigned_zone_no_finding(monkeypatch):
    """Rule 1: an unsigned zone has no denial-of-existence proofs to
    grade. Emitting anything here would violate not-applicable /
    unretrievable / broken separation."""
    unsigned = _validating_status()
    unsigned["state"] = "not_configured"
    unsigned["ds"] = False
    unsigned["dnskey"] = False
    unsigned["self_signed"] = None
    rep = _run_dnssec(monkeypatch, unsigned,
                      {"ok": True, "type": "none"})
    findings = _findings(rep, "Zone-walking exposure")
    assert not findings, (
        "unsigned zone must not emit a zone-walking finding — not "
        "applicable, not broken. "
        f"got: {[(f.status, f.detail) for f in findings]}"
    )


def test_probe_failed_produces_unknown(monkeypatch):
    """Signed zone but the NSEC probe itself failed → UNKNOWN. Rule 1:
    unretrievable never collapses into 'no exposure'."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": False, "error": "timeout"})
    findings = _findings(rep, "Zone-walking exposure")
    assert findings
    assert findings[0].status == "UNKNOWN"


def test_broken_dnssec_still_probes_nsec(monkeypatch):
    """Even a broken chain (state="broken") may still return NSEC/NSEC3
    records for the denial-of-existence proof — the walkability signal
    is orthogonal to whether the chain validates. Must still probe
    and emit the exposure finding."""
    broken = _validating_status()
    broken["state"] = "broken"
    rep = _run_dnssec(monkeypatch, broken,
                      {"ok": True, "type": "NSEC"})
    findings = _findings(rep, "Zone-walking exposure")
    assert findings
    assert findings[0].status == "WARN"
