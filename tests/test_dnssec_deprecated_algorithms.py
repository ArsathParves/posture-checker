"""Regression tests for FN4 — deprecated DNSSEC algorithms not flagged.

Contract:
  RFC 8624 §3.1 gives per-algorithm status for DNSSEC signing:

    Alg 1  RSAMD5             MUST NOT
    Alg 3  DSA                MUST NOT
    Alg 5  RSASHA1            NOT RECOMMENDED
    Alg 6  DSANSEC3SHA1       MUST NOT
    Alg 7  RSASHA1NSEC3SHA1   NOT RECOMMENDED
    Alg 8  RSASHA256          MUST (baseline modern)
    Alg 13 ECDSAP256SHA256    MUST
    Alg 15 ED25519            RECOMMENDED

  The v0.5 tool lists observed algorithms as an INFO row and stops there —
  a zone signed with alg 5 grades identically to a zone signed with alg 13,
  which is wrong: validators are actively downgrading or refusing SHA-1
  signatures. Weak crypto in a signed zone is worse than a strong FAIL
  because it silently erodes the security signal the operator paid for.

Fix: when the observed algorithm set contains any RFC 8624 deprecated
signing algorithm, emit an additional `Algorithm strength` finding with
status WARN. Hardening-only (rule: don't tank correctness for a hardening
feature that IS being adopted — CLAUDE.md rule 1's spirit). The finding's
`why` names the specific algorithms and points to alg 13 / 15 rotation.

The `_dnssec` function reads `st["algorithms"]` — a list of strings
formatted `"{alg_name} ({KSK|ZSK})"` — so the test suite can monkey-patch
`dnsmod.dnssec_status` to return a synthetic dict and assert on the
findings emitted, without any network dependency.
"""
from __future__ import annotations

import pytest

from posture import checks
from posture import dnsmod
from posture.core import Report


def _run_dnssec_with_algs(monkeypatch, algorithms: list[str]) -> Report:
    """Drive `checks._dnssec` with a synthetic algorithm list."""
    def fake_status(_domain):
        return {
            "ds": True, "dnskey": True, "rrsig": True,
            "self_signed": True, "ds_matches_dnskey": True,
            "ad_authenticated": True, "validated": True,
            "algorithms": algorithms, "notes": [], "state": "validating",
            "cryptography_available": True,
        }
    monkeypatch.setattr(dnsmod, "dnssec_status", fake_status)
    rep = Report(domain_input="example.com", domain="example.com")
    checks._dnssec(rep, "example.com")
    return rep


# ------------------------------------------------------------- deprecated

def test_rsasha1_ksk_emits_algorithm_strength_warn(monkeypatch):
    """Alg 5 (RSASHA1) is the canonical FN4 case — RFC 8624 marks it
    NOT RECOMMENDED and modern validators are downgrading."""
    rep = _run_dnssec_with_algs(monkeypatch, ["RSASHA1 (KSK)", "RSASHA1 (ZSK)"])
    strength = [f for f in rep.findings if f.label == "Algorithm strength"]
    assert strength, "expected an 'Algorithm strength' finding for RSASHA1"
    assert strength[0].status == "WARN"
    assert "RSASHA1" in strength[0].detail
    # Actionable remediation must name a modern replacement — the
    # operator should not have to look up RFC 8624 themselves.
    assert any(name in strength[0].why for name in ("ECDSAP256SHA256", "ED25519", "alg 13", "alg 15")), \
        f"remediation must recommend a modern alg; got: {strength[0].why!r}"


def test_rsasha1nsec3sha1_emits_warn(monkeypatch):
    """Alg 7 is also SHA-1-based (NOT RECOMMENDED per RFC 8624)."""
    rep = _run_dnssec_with_algs(monkeypatch, ["RSASHA1NSEC3SHA1 (KSK)"])
    strength = [f for f in rep.findings if f.label == "Algorithm strength"]
    assert strength and strength[0].status == "WARN"
    assert "RSASHA1NSEC3SHA1" in strength[0].detail


def test_rsamd5_emits_warn(monkeypatch):
    """Alg 1 (RSAMD5) — MUST NOT per RFC 8624 §3.1. If a real zone still
    ships this, the tool must not stay silent."""
    rep = _run_dnssec_with_algs(monkeypatch, ["RSAMD5 (KSK)"])
    strength = [f for f in rep.findings if f.label == "Algorithm strength"]
    assert strength and strength[0].status == "WARN"


def test_dsa_and_dsansec3sha1_emit_warn(monkeypatch):
    """Algs 3 and 6 — both MUST NOT (DSA-based)."""
    for alg in ("DSA (KSK)", "DSANSEC3SHA1 (KSK)"):
        rep = _run_dnssec_with_algs(monkeypatch, [alg])
        strength = [f for f in rep.findings if f.label == "Algorithm strength"]
        assert strength and strength[0].status == "WARN", \
            f"deprecated algorithm {alg} must emit an Algorithm strength WARN"


# ------------------------------------------------------------- modern

def test_rsasha256_alone_does_not_emit_warn(monkeypatch):
    """Alg 8 (RSASHA256) is MUST per RFC 8624 — the modern RSA baseline.
    A zone signed exclusively with 8 must NOT get a WARN."""
    rep = _run_dnssec_with_algs(monkeypatch, ["RSASHA256 (KSK)", "RSASHA256 (ZSK)"])
    strength = [f for f in rep.findings if f.label == "Algorithm strength"]
    assert not strength, (
        f"RSASHA256 is a modern alg — no WARN expected; got: {strength}"
    )


def test_ecdsap256sha256_does_not_emit_warn(monkeypatch):
    """Alg 13 is the current-recommended default. Must not warn."""
    rep = _run_dnssec_with_algs(monkeypatch, ["ECDSAP256SHA256 (KSK)"])
    strength = [f for f in rep.findings if f.label == "Algorithm strength"]
    assert not strength


def test_ed25519_does_not_emit_warn(monkeypatch):
    """Alg 15 (ED25519) — RECOMMENDED per RFC 8624."""
    rep = _run_dnssec_with_algs(monkeypatch, ["ED25519 (KSK)"])
    strength = [f for f in rep.findings if f.label == "Algorithm strength"]
    assert not strength


def test_empty_algorithm_list_does_not_emit_warn(monkeypatch):
    """No observed DNSKEYs (e.g., unsigned zone or DNSKEY fetch failed).
    Silence is correct here — we have no basis to warn."""
    rep = _run_dnssec_with_algs(monkeypatch, [])
    strength = [f for f in rep.findings if f.label == "Algorithm strength"]
    assert not strength


# ------------------------------------------------------------- mixed sets

def test_mixed_deprecated_and_modern_still_warns(monkeypatch):
    """During an algorithm rollover a zone may briefly publish both an
    old and a new KSK. The WARN must fire — until the deprecated key is
    retired, validators are still consuming the weak signature path."""
    rep = _run_dnssec_with_algs(monkeypatch,
                                 ["RSASHA1 (KSK)", "ECDSAP256SHA256 (KSK)"])
    strength = [f for f in rep.findings if f.label == "Algorithm strength"]
    assert strength and strength[0].status == "WARN"
    assert "RSASHA1" in strength[0].detail
    # But the modern alg should not be listed as the offender.
    assert "ECDSAP256SHA256" not in strength[0].detail, (
        "the modern alg must not appear in the 'deprecated' finding text"
    )


# ------------------------------------------------------------- grade impact

def test_deprecated_algorithm_is_hardening_only(monkeypatch):
    """CLAUDE.md rule 1's spirit: DNSSEC adoption is a hardening signal,
    even when the chosen algorithm is weak — the operator DID sign the
    zone. The finding must be hardening=True so it lands in the hardening
    bucket only and doesn't tank the correctness sub-grade.

    (An unsigned zone at least gets the honest 'not configured' story;
    a signed-with-alg-5 zone should not grade WORSE than unsigned. The
    signal we want is: 'signed, but rotate your key material'.)"""
    rep = _run_dnssec_with_algs(monkeypatch, ["RSASHA1 (KSK)"])
    strength = [f for f in rep.findings if f.label == "Algorithm strength"]
    assert strength
    assert strength[0].hardening is True, (
        "Algorithm strength must be hardening=True — signed-but-weak is "
        "still adoption, we just want the operator to rotate."
    )
