"""Regression tests for E4 — DKIM wildcard _domainkey handling.

CLAUDE.md ground-truth: `example.com` publishes `*._domainkey.example.com`
with an empty `p=` (a REVOKED key per RFC 6376 §3.6.1). Any tool that
probes N common selectors and reports "DKIM found under all N" is
producing a false PASS — validators receiving a message from that domain
will see the empty `p=` and reject the signature.

`evaluate_dkim` guards against this by first probing a random canary
selector (`probe<uuid>._domainkey.<domain>`). If the wildcard responds,
we know every subsequent per-selector probe would also "succeed" and
per-selector results are therefore not meaningful. We short-circuit
with `wildcard=True` and report the key_state derived from the
wildcard record.

These tests pin that short-circuit and the two labels it produces
(revoked key vs generic wildcard).
"""
from __future__ import annotations

from unittest.mock import patch

from posture import emailauth


REVOKED_WILDCARD_RECORD = ["v=DKIM1; p="]
VALID_WILDCARD_RECORD = ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"]


def test_wildcard_with_empty_p_reports_revoked():
    """example.com pattern: `*._domainkey` exists and publishes empty p=.

    Must NOT report DKIM as found; must short-circuit with
    wildcard=True and key_state='revoked' so the emit layer can
    surface the revocation, not a false PASS."""
    with patch.object(emailauth, "_txt_records",
                      return_value=REVOKED_WILDCARD_RECORD):
        out = emailauth.evaluate_dkim("example.com")
    assert out["wildcard"] is True, (
        f"wildcard _domainkey with empty p= must set wildcard=True; got {out!r}"
    )
    assert out["found"] is False, (
        f"revoked wildcard is not the same as 'DKIM found'; got found={out['found']!r}"
    )
    assert out.get("key_state") == "revoked"
    assert "revoked" in out["label"].lower(), (
        f"label must name 'revoked' so operators see the RFC 6376 §3.6.1 "
        f"state, not just 'wildcard'; got label={out['label']!r}"
    )


def test_wildcard_with_valid_key_is_flagged_as_ambiguous():
    """A wildcard that publishes a real key is still ambiguous — per-selector
    probes cannot distinguish which selectors are actually in use. The
    canary short-circuit must fire and the label must warn that the
    results are 'not meaningful'."""
    with patch.object(emailauth, "_txt_records",
                      return_value=VALID_WILDCARD_RECORD):
        out = emailauth.evaluate_dkim("example.com")
    assert out["wildcard"] is True
    assert out.get("key_state") == "valid"
    assert "not meaningful" in out["label"].lower() or \
           "wildcard" in out["label"].lower(), (
        f"label must flag ambiguity; got label={out['label']!r}"
    )


def test_wildcard_short_circuit_skips_selector_probing():
    """Belt-and-braces: when the canary probe answers, the 30+ per-selector
    lookups must NOT run. That's the whole point of the canary — every
    one of them would also "succeed" against the wildcard and clutter
    the output with false selectors.

    The `probed` counter is the load-bearing signal: canary path sets
    it to 0, the per-selector path sets it to len(COMMON_SELECTORS)."""
    calls: list[str] = []

    def fake_txt(name):
        calls.append(name)
        # First call is the canary probe — return the wildcard record.
        # Any subsequent call would be a real selector, which shouldn't
        # happen once the canary fires.
        return REVOKED_WILDCARD_RECORD

    with patch.object(emailauth, "_txt_records", side_effect=fake_txt):
        out = emailauth.evaluate_dkim("example.com")

    assert out["wildcard"] is True
    assert out["probed"] == 0, (
        f"canary path must set probed=0 to signal 'per-selector results "
        f"were not attempted'; got probed={out['probed']!r}"
    )
    assert len(calls) == 1, (
        f"only the canary probe should run when wildcard is detected; "
        f"got {len(calls)} DNS calls: {calls!r}"
    )
    assert "probe" in calls[0], (
        f"the one call must be the canary probe; got {calls[0]!r}"
    )


def test_no_wildcard_and_real_selector_found():
    """Negative-space test: when the canary returns empty but a real
    selector answers, we take the normal per-selector path and report
    found=True, wildcard=False. Guards against a regression where the
    canary short-circuit fires on the wrong condition."""
    real_key = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ"

    def fake_txt(name):
        if name.startswith("probe"):
            return []  # canary miss — no wildcard
        if name.startswith("default._domainkey."):
            return [real_key]
        return []

    with patch.object(emailauth, "_txt_records", side_effect=fake_txt):
        out = emailauth.evaluate_dkim("example.com")

    assert out["wildcard"] is False
    assert out["found"] is True
    assert out["probed"] > 0, "per-selector path must report probed count"
    assert any(s["selector"] == "default" for s in out["selectors"])


def test_no_wildcard_and_no_selectors_gives_never_report_absence():
    """CLAUDE.md rule 1: absence of records under common selectors is
    NOT the same as 'DKIM not published' — an operator could be using
    an uncommon selector name. The label must reflect that uncertainty."""
    with patch.object(emailauth, "_txt_records", return_value=[]):
        out = emailauth.evaluate_dkim("example.com")
    assert out["wildcard"] is False
    assert out["found"] is False
    assert "not found under common selectors" in out["label"].lower(), (
        f"label must qualify 'not found' with 'under common selectors' "
        f"so it doesn't collapse into 'DKIM absent'; got {out['label']!r}"
    )
