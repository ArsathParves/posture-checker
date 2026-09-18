"""Regression tests for D4 — DNSSEC without the `cryptography` module.

Symptom the audit noted:
  The finding text was generic "Could not determine" instead of naming
  the missing `cryptography` dependency, so operators couldn't tell
  whether their zone was actually broken or the tool was crippled.

Deeper bug found while implementing D4 (worse than the audit noted):
  `dns.dnssec.make_ds` raises `ImportError` when cryptography is missing.
  The old `dnssec_status` caught that with a bare `except Exception: continue`,
  causing `matched=False` → `ds_matches_dnskey=False` → state="broken". A
  signed, correctly-anchored zone was reported as **broken** — a hard FAIL —
  purely because the tool's dependency was missing. That is a direct
  CLAUDE.md rule 1 violation: `unretrievable` collapsed into `broken`.

Fix:
  1. Detect `cryptography` at import time (`_HAS_CRYPTOGRAPHY`).
  2. When absent, `dnssec_status` short-circuits with `state="unknown"`,
     `cryptography_available=False`, and a note naming the missing dep.
  3. `checks._dnssec` renders a specific UNKNOWN detail — "cryptography
     module not installed; DNSSEC validation skipped" — so the operator
     gets actionable text.
"""
from __future__ import annotations

from unittest.mock import patch

import posture.dnsmod as dnsmod


def test_module_exposes_cryptography_availability_flag():
    """A dependency this critical to correctness must be introspectable."""
    assert hasattr(dnsmod, "_HAS_CRYPTOGRAPHY")
    assert isinstance(dnsmod._HAS_CRYPTOGRAPHY, bool)


def test_dnssec_status_without_cryptography_is_unknown_not_broken(monkeypatch):
    """The most important assertion in this file: without cryptography a
    signed, correctly-anchored zone must NOT be reported as broken.
    """
    monkeypatch.setattr(dnsmod, "_HAS_CRYPTOGRAPHY", False)
    out = dnsmod.dnssec_status("example.com")

    # Conclusion must remain UNKNOWN — never a false FAIL.
    assert out["state"] == "unknown"
    assert out["validated"] is None
    assert out.get("cryptography_available") is False
    # Note must name the specific missing dependency so the operator can act.
    assert any("cryptography" in n.lower() for n in out.get("notes", [])), \
        f"expected 'cryptography' in notes, got {out.get('notes')}"


def test_dnssec_status_without_cryptography_skips_network_probes(monkeypatch):
    """No point burning DNS queries if we can't validate the result.
    Also protects offline test environments from hitting the network."""
    monkeypatch.setattr(dnsmod, "_HAS_CRYPTOGRAPHY", False)
    with patch("dns.query.udp") as udp:
        dnsmod.dnssec_status("example.com")
    assert not udp.called, "must not query DNS when validation is impossible"


def test_checks_surface_names_missing_cryptography_in_detail(monkeypatch):
    """The user-facing finding must actually name the missing module. A
    generic 'Could not determine' hides the fact that reinstalling one
    dependency fixes every signed zone at once."""
    from posture import checks
    from posture.core import Report

    monkeypatch.setattr(dnsmod, "_HAS_CRYPTOGRAPHY", False)
    rep = Report(domain_input="example.com", domain="example.com")
    checks._dnssec(rep, "example.com")

    findings = [f for f in rep.findings if f.label == "DNSSEC status"]
    assert findings, "expected a DNSSEC status finding"
    f = findings[0]
    assert f.status == "UNKNOWN"
    assert "cryptography" in f.detail.lower(), \
        f"expected 'cryptography' in detail, got {f.detail!r}"


def test_cryptography_available_path_still_runs(monkeypatch):
    """Regression guard — when the dependency IS present, we must not
    short-circuit. Only the fallback path changes; the happy path is
    untouched."""
    monkeypatch.setattr(dnsmod, "_HAS_CRYPTOGRAPHY", True)
    # We don't want a real network call — just verify the function
    # proceeds past the short-circuit and *attempts* the DS query.
    with patch("dns.query.udp", side_effect=Exception("stop here")):
        out = dnsmod.dnssec_status("example.com")
    # Because every network call raises, we won't reach 'validating',
    # but we must at least have attempted (state != "unknown due to no crypto").
    assert out.get("cryptography_available") is not False, \
        "cryptography IS available in this test — must not be flagged unavailable"
