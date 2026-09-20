"""B37 — cross-resolver DNSKEY consensus.

CLAUDE.md rule: "consensus across resolvers + authoritative read"
is one of the four real sources of truth. Existing checks read
consensus at the delegation boundary (`parent_delegation`, D2) and
at the A/AAAA layer (`authoritative_vs_cached`, D5), but the
DNSKEY set itself — the anchor for the entire DNSSEC chain —
was only read from the FIRST resolver that responded (see
`dnssec_status`, line ~431: `if dnskey_rrset: break`).

That break-on-first is correct for the state-derivation code
(we just need a valid DNSKEY set to run the chain check) but it
leaves a real attack class unobserved: if one of the three big
public resolvers is cache-poisoned or serving a stale zone, the
tool would not notice — the "one resolver's cached answer" trap
CLAUDE.md warns about.

Cross-resolver DNSKEY consensus closes the gap. Three resolvers
disagreeing on DNSKEY is a red flag every time — either a
cache-poisoning event is in progress, the zone is mid-rollover
in a way the parent hasn't caught up to, or a resolver is lame.

The check emits an INFORMATIONAL finding (not a section-grading
signal) with a T5 confidence tier so the UI can show "3/3 agree
(high)" vs "2/3 agree (medium)". Because it's hardening=True,
disagreements don't tank correctness — the reader can decide.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from posture import checks as c
from posture import dnsmod
from posture.core import Report


# --------------------------------------------------------------------- helper primitive

def test_cross_resolver_dnskey_helper_exists():
    """The helper lives in `dnsmod` — same layer as `dnssec_status`
    and `parent_delegation`. Rule 4: one primitive per check, testable
    in isolation."""
    assert hasattr(dnsmod, "cross_resolver_dnskey"), (
        "dnsmod.cross_resolver_dnskey must exist as a mockable "
        "primitive so the check can be pinned without live DNS"
    )


def test_cross_resolver_dnskey_returns_per_resolver_map():
    """Return contract: a dict keyed by resolver IP. Each value is
    either a comparable keyset (agreement basis) or a sentinel for
    'this resolver didn't return DNSKEY'. Downstream reads len(set)
    to decide consensus."""
    def _fake_udp(query, ip, timeout=None):
        msg = MagicMock()
        msg.answer = []  # no DNSKEY records
        return msg
    with patch.object(dnsmod.dns.query, "udp", _fake_udp):
        result = dnsmod.cross_resolver_dnskey("example.com")
    assert isinstance(result, dict)
    assert set(result.keys()) == set(dnsmod.PUBLIC_RESOLVERS)


# --------------------------------------------------------------------- emission

def _install_dnssec_stubs(monkeypatch, state="validating",
                         per_resolver=None):
    """Patch the DNSSEC probe chain so `_dnssec` runs a signed-zone
    path with the specified cross-resolver view."""
    monkeypatch.setattr(c.dnsmod, "dnssec_status", lambda d: {
        "state": state,
        "ds": True, "dnskey": True, "algorithms": [],
        "notes": [], "self_signed": None,
        "ds_matches_dnskey": None, "ad_authenticated": None,
        "cryptography_available": True,
    })
    monkeypatch.setattr(c.dnsmod, "nsec_type",
                        lambda d: {"ok": True, "type": "NSEC3",
                                   "iterations": 0})
    monkeypatch.setattr(c.dnsmod, "cds_cdnskey_status",
                        lambda d: {"ok": False, "error": "n/a"})
    if per_resolver is None:
        per_resolver = {ip: "K1" for ip in dnsmod.PUBLIC_RESOLVERS}
    monkeypatch.setattr(c.dnsmod, "cross_resolver_dnskey",
                        lambda d: per_resolver)


def _consensus_finding(rep):
    return next((f for f in rep.findings
                 if f.label == "Cross-resolver DNSKEY consensus"), None)


def test_dnssec_emits_consensus_pass_when_all_resolvers_agree(monkeypatch):
    """3/3 resolvers return the same DNSKEY set → PASS with
    confidence=high. This is the strongest possible affirmation
    the tool can offer — three independent recursive vantages
    saw the same zone."""
    _install_dnssec_stubs(
        monkeypatch,
        per_resolver={ip: "SAMEKEY" for ip in dnsmod.PUBLIC_RESOLVERS},
    )
    rep = Report(domain_input="example.com", domain="example.com")
    c._dnssec(rep, "example.com")
    f = _consensus_finding(rep)
    assert f is not None, "consensus finding must be emitted for signed zones"
    assert f.status == "PASS"
    assert f.confidence == "high"


def test_dnssec_emits_consensus_warn_when_resolvers_disagree(monkeypatch):
    """Two resolvers see keyset A, one sees keyset B → WARN with
    confidence=medium. This is the load-bearing case: divergence
    is the signal that cache poisoning / lameness may be in play.
    Hardening=True so correctness isn't dragged."""
    _install_dnssec_stubs(
        monkeypatch,
        per_resolver={"1.1.1.1": "KEY_A",
                      "8.8.8.8": "KEY_A",
                      "9.9.9.9": "KEY_B"},
    )
    rep = Report(domain_input="example.com", domain="example.com")
    c._dnssec(rep, "example.com")
    f = _consensus_finding(rep)
    assert f is not None
    assert f.status == "WARN"
    assert f.confidence == "medium"
    assert f.hardening is True, (
        "consensus disagreement must be hardening=True so a "
        "resolver hiccup doesn't tank correctness"
    )


def test_dnssec_emits_consensus_unknown_when_too_few_resolvers_respond(monkeypatch):
    """Only 1/3 resolvers returned DNSKEY. Consensus of 1 is not
    consensus — rule 1 says UNKNOWN, not PASS. Confidence is empty
    because the tool made no claim."""
    _install_dnssec_stubs(
        monkeypatch,
        per_resolver={"1.1.1.1": "KEY", "8.8.8.8": None, "9.9.9.9": None},
    )
    rep = Report(domain_input="example.com", domain="example.com")
    c._dnssec(rep, "example.com")
    f = _consensus_finding(rep)
    assert f is not None
    assert f.status == "UNKNOWN"
    assert f.confidence == ""


def test_dnssec_no_consensus_finding_when_zone_unsigned(monkeypatch):
    """Unsigned zone → no DNSKEY to compare → emitting the check
    would be a rule-1 violation (not-applicable collapsed into a
    finding). The check must NOT run."""
    _install_dnssec_stubs(monkeypatch, state="not_configured")
    rep = Report(domain_input="example.com", domain="example.com")
    c._dnssec(rep, "example.com")
    assert _consensus_finding(rep) is None, (
        "unsigned zones must not emit a DNSKEY consensus finding"
    )


def test_dnssec_no_consensus_finding_when_state_unknown(monkeypatch):
    """State=unknown → the tool couldn't tell if the zone is signed.
    Running the consensus check on top would compound uncertainty.
    Skip cleanly."""
    _install_dnssec_stubs(monkeypatch, state="unknown")
    rep = Report(domain_input="example.com", domain="example.com")
    c._dnssec(rep, "example.com")
    assert _consensus_finding(rep) is None


# --------------------------------------------------------------------- rule 1

def test_consensus_finding_is_hardening_never_correctness(monkeypatch):
    """The check is a hardening signal by design. Downstream
    grading must NOT treat a disagreement as a misconfiguration —
    only the zone owner can decide whether the divergence is a
    real problem or a benign rollover artefact."""
    _install_dnssec_stubs(
        monkeypatch,
        per_resolver={"1.1.1.1": "A", "8.8.8.8": "A", "9.9.9.9": "B"},
    )
    rep = Report(domain_input="example.com", domain="example.com")
    c._dnssec(rep, "example.com")
    f = _consensus_finding(rep)
    assert f.hardening is True
