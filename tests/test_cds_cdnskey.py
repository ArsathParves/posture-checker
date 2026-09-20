"""B25 — CDS/CDNSKEY (RFC 7344 / 8078) automated-rollover signalling.

RFC 7344 defines CDS (type 59) and CDNSKEY (type 60) records at the
child zone apex. They tell an RFC-8078-aware parent registrar / DPS
what DS record to publish, enabling **automated** DS rollover without
an out-of-band EPP touch. A signed zone that never publishes
CDS/CDNSKEY is stuck on manual DS updates — a well-known operational
foot-gun during key rollovers (the parent DS ages out before the
operator remembers to update it).

RFC 8078 §4 additionally reserves the "delete" signal: a CDS record
with algorithm 0 (and CDNSKEY with algorithm 0) tells the parent to
REMOVE the DS entirely, taking the zone unsigned in a coordinated way.
Presence of that signal is not a bug, but is worth surfacing — an
operator staring at "why did my zone go bogus" wants to see it.

Rule 1 sanity:
  - Unsigned zone (state == "not_configured") → not applicable
    (no rollover to automate); no finding emitted.
  - CDS/CDNSKEY query failed → UNKNOWN (never absent).
  - Signed zone with CDS/CDNSKEY published → INFO / PASS "automated
    rollover supported"; hardening signal, not correctness.
  - Signed zone with none → INFO / WARN hardening=True (adoption gap).
  - Delete signal (alg 0) → INFO surfacing the pending unsign.
"""
from __future__ import annotations

from posture import dnsmod, checks as c
from posture.core import Report


# --------------------------------------------------------------------- unit: dnsmod.cds_cdnskey_status

def test_cds_cdnskey_detects_both_records(monkeypatch):
    """Load-bearing: both CDS and CDNSKEY at the apex must be surfaced
    with their key-tag / algorithm / digest-type identifiers.

    CDS wire format (RFC 7344 §3.1 / RFC 4034 §5): key-tag alg
    digest-type digest-hex. CDNSKEY wire format: flags protocol alg
    public-key-b64 (same as DNSKEY)."""
    def _fake_query(domain, rdtype, **kw):
        if rdtype == "CDS":
            return {"ok": True, "records": ["12345 13 2 " + "a" * 64]}
        if rdtype == "CDNSKEY":
            return {"ok": True, "records": ["257 3 13 " + "b" * 44]}
        return {"ok": False}
    monkeypatch.setattr(dnsmod, "query", _fake_query)
    result = dnsmod.cds_cdnskey_status("example.com")
    assert result["ok"] is True
    assert result["has_cds"] is True
    assert result["has_cdnskey"] is True
    assert result["delete_signal"] is False


def test_cds_cdnskey_detects_delete_signal(monkeypatch):
    """RFC 8078 §4: a CDS with algorithm 0 (and digest-type 0, digest
    "00") signals that the parent should REMOVE the DS. Must be
    surfaced separately — the zone is signalling a pending unsign."""
    def _fake_query(domain, rdtype, **kw):
        if rdtype == "CDS":
            return {"ok": True, "records": ["0 0 0 00"]}
        if rdtype == "CDNSKEY":
            return {"ok": True, "records": ["0 3 0 AA=="]}
        return {"ok": False}
    monkeypatch.setattr(dnsmod, "query", _fake_query)
    result = dnsmod.cds_cdnskey_status("example.com")
    assert result["ok"] is True
    assert result["delete_signal"] is True


def test_cds_cdnskey_absent(monkeypatch):
    """No CDS or CDNSKEY records is the common case for zones with
    manual DS management. Must return `ok=True` with both flags false —
    downstream distinguishes this from a probe failure."""
    def _fake_query(domain, rdtype, **kw):
        return {"ok": True, "records": []}
    monkeypatch.setattr(dnsmod, "query", _fake_query)
    result = dnsmod.cds_cdnskey_status("example.com")
    assert result["ok"] is True
    assert result["has_cds"] is False
    assert result["has_cdnskey"] is False


def test_cds_cdnskey_handles_query_failure(monkeypatch):
    """Timeout / socket error / SERVFAIL on both probes must return
    `ok=False` — rule 1: unretrievable stays unretrievable, must not
    fall through to has_cds=False (which would misreport 'no automated
    rollover' as a real signal)."""
    def _fake_query(domain, rdtype, **kw):
        return {"ok": False, "error": "timeout"}
    monkeypatch.setattr(dnsmod, "query", _fake_query)
    result = dnsmod.cds_cdnskey_status("example.com")
    assert result["ok"] is False


# --------------------------------------------------------------------- integration: _dnssec emission

def _run_dnssec(monkeypatch, dnssec_out, nsec_out, cds_out):
    """Drive `_dnssec` with stubbed sub-checks to isolate the CDS/
    CDNSKEY emission path."""
    monkeypatch.setattr(c.dnsmod, "dnssec_status", lambda d: dnssec_out)
    monkeypatch.setattr(c.dnsmod, "nsec_type", lambda d: nsec_out)
    monkeypatch.setattr(c.dnsmod, "cds_cdnskey_status", lambda d: cds_out)
    rep = Report(domain_input="example.com", domain="example.com")
    c._dnssec(rep, "example.com")
    return rep


def _findings(rep, label):
    return [f for f in rep.findings if f.label == label]


def _validating_status():
    return {
        "state": "validating", "ds": True, "dnskey": True,
        "rrsig": True, "self_signed": True, "ds_matches_dnskey": True,
        "ad_authenticated": True, "algorithms": [], "notes": [],
        "cryptography_available": True,
    }


def test_cds_cdnskey_published_emits_pass(monkeypatch):
    """The load-bearing hardening signal: automated DS rollover is
    supported. PASS surfaces it in the DNSSEC section without dragging
    correctness."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": True, "type": "NSEC3", "iterations": 0},
                      {"ok": True, "has_cds": True, "has_cdnskey": True,
                       "delete_signal": False})
    findings = _findings(rep, "Automated DS rollover")
    assert findings, (
        f"expected `Automated DS rollover` finding; got labels: "
        f"{[f.label for f in rep.findings]}"
    )
    assert findings[0].status == "PASS"


def test_cds_cdnskey_absent_on_signed_zone_is_hardening_gap(monkeypatch):
    """A signed zone with no CDS/CDNSKEY is stuck on manual DS updates.
    Not broken, so must not tank correctness — hardening=True marks it
    as an adoption gap. WARN (not INFO) so it surfaces without
    ceremony."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": True, "type": "NSEC3", "iterations": 0},
                      {"ok": True, "has_cds": False, "has_cdnskey": False,
                       "delete_signal": False})
    findings = _findings(rep, "Automated DS rollover")
    assert findings
    f = findings[0]
    assert f.status == "WARN"
    assert f.hardening is True, (
        "manual DS rollover is an operational-risk hardening gap, "
        "not a correctness failure — must not slip into correctness"
    )
    assert "RFC 7344" in f.detail or "7344" in f.detail


def test_cds_delete_signal_emits_info(monkeypatch):
    """RFC 8078 §4 delete signal: zone is telling the parent to remove
    DS. Must be surfaced so an operator investigating a broken chain
    sees the pending unsign was requested, not accidental."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": True, "type": "NSEC3", "iterations": 0},
                      {"ok": True, "has_cds": True, "has_cdnskey": True,
                       "delete_signal": True})
    findings = _findings(rep, "CDS/CDNSKEY delete signal")
    assert findings, (
        f"expected delete-signal finding; got: "
        f"{[f.label for f in rep.findings]}"
    )
    assert findings[0].status == "INFO"
    assert "8078" in findings[0].detail or "delete" in findings[0].detail.lower()


def test_unsigned_zone_no_cds_finding(monkeypatch):
    """Rule 1: unsigned zone has no rollover to automate. Emitting a
    finding here would collapse not-applicable into WARN — the exact
    class of false-positive CLAUDE.md forbids."""
    unsigned = _validating_status()
    unsigned["state"] = "not_configured"
    unsigned["ds"] = False
    unsigned["dnskey"] = False
    unsigned["self_signed"] = None
    rep = _run_dnssec(monkeypatch, unsigned,
                      {"ok": True, "type": "none"},
                      {"ok": True, "has_cds": False, "has_cdnskey": False,
                       "delete_signal": False})
    findings = _findings(rep, "Automated DS rollover")
    assert not findings, (
        "unsigned zone must not emit an automated-rollover finding — "
        "not applicable, not a hardening gap. "
        f"got: {[(f.status, f.detail) for f in findings]}"
    )


def test_cds_probe_failed_produces_unknown(monkeypatch):
    """Signed zone but CDS/CDNSKEY probe itself failed → UNKNOWN. Rule
    1: unretrievable never collapses into 'no rollover configured'."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": True, "type": "NSEC3", "iterations": 0},
                      {"ok": False, "error": "timeout"})
    findings = _findings(rep, "Automated DS rollover")
    assert findings
    assert findings[0].status == "UNKNOWN"


def test_cds_only_no_cdnskey_still_counts_as_published(monkeypatch):
    """RFC 7344 §4.1: a parent MAY accept either CDS or CDNSKEY. Having
    just one is enough to enable automated rollover in an 8078-compliant
    ecosystem — must not WARN 'no rollover' when the zone published
    one of the two."""
    rep = _run_dnssec(monkeypatch,
                      _validating_status(),
                      {"ok": True, "type": "NSEC3", "iterations": 0},
                      {"ok": True, "has_cds": True, "has_cdnskey": False,
                       "delete_signal": False})
    findings = _findings(rep, "Automated DS rollover")
    assert findings
    assert findings[0].status == "PASS"
