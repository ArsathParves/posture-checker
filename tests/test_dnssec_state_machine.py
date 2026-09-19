"""T5 — Full-chain DNSSEC state derivation.

Existing tests cover slices:
  - `test_dnssec_ad_fallback.py`      — AD-bit resolver fallback
  - `test_dnssec_probe_unretrievable.py` — L4 gates (unknown vs broken)
  - `test_dnssec_no_cryptography.py`  — cryptography-missing → unknown
  - `test_dnssec_deprecated_algorithms.py` — algorithm hardening WARN

What was NOT pinned is the state machine itself — the map from
`(ds, dnskey, self_signed, ds_matches_dnskey, ad_authenticated,
ds_probe_responded, dnskey_probe_responded)` to
`{validating, broken, incomplete, not_configured, unknown}`.

CLAUDE.md ground truth:
  - `cloudflare.com` → validating (all six signals green)
  - `dnssec-failed.org` → broken (DS present, DNSKEY absent OR
    ds_matches_dnskey=False OR AD-bit=False)
  - `google.com` → not_configured (both queries answered "absent")

Any refactor of `dnssec_status`'s state derivation that keeps the
outer function's shape but rearranges the ladder could silently
promote a broken zone to not_configured (a rule-1 violation on the
tool's highest-stakes finding) or demote not_configured to broken.
This file locks the ladder branch-by-branch.

The state machine is extracted to `_dnssec_derive_state` — a pure
function taking the six atomic signals and returning
`(state, notes, validated)`. That extraction is a mechanical
refactor; the branch logic must match the pre-extraction
`dnssec_status` byte-for-byte.
"""
from __future__ import annotations

import pytest

from posture.dnsmod import _dnssec_derive_state


# --------------------------------------------------------------------- helpers

def _derive(**overrides):
    """All-green defaults; override just the fields the test cares about."""
    kwargs = dict(
        ds=True, dnskey=True,
        self_signed=True, ds_matches_dnskey=True, ad_authenticated=True,
        ds_probe_responded=True, dnskey_probe_responded=True,
    )
    kwargs.update(overrides)
    return _dnssec_derive_state(**kwargs)


# --------------------------------------------------------------------- validating

def test_all_signals_green_is_validating():
    """The cloudflare.com posture: DS present, DNSKEY present, self-sig
    validates, DS matches a DNSKEY digest, resolver AD-bit confirms."""
    state, notes, validated = _derive()
    assert state == "validating"
    assert validated is True
    assert notes == []


def test_ad_inconclusive_but_crypto_ok_is_still_validating():
    """The AD-bit probe can fail transiently (resolver flap, EDNS
    weirdness). If the cryptographic chain is intact and AD is only
    inconclusive (None), the zone is still validating — we do not
    demote a signed zone to broken on a soft signal."""
    state, _, validated = _derive(ad_authenticated=None)
    assert state == "validating"
    assert validated is True


# --------------------------------------------------------------------- broken

def test_ds_present_dnskey_missing_is_broken():
    """The `dnssec-failed.org` failure mode CLAUDE.md guards against:
    parent publishes a DS pointing at nothing. Resolvers SERVFAIL."""
    state, notes, validated = _derive(dnskey=False, self_signed=None,
                                       ds_matches_dnskey=None,
                                       ad_authenticated=False)
    assert state == "broken"
    # Note names the parent-child boundary specifically.
    assert any("DS published at parent" in n and "no DNSKEY" in n for n in notes), (
        f"broken-because-no-DNSKEY must name the boundary; got {notes!r}"
    )


def test_ds_does_not_match_dnskey_is_broken():
    """DS at parent points at a DNSKEY digest that no live DNSKEY
    matches — a chain-of-trust break at the delegation boundary. This
    is the OTHER form of dnssec-failed: DS+DNSKEY both present but
    they don't hash-match. Distinct from the AD-bit reject path."""
    state, _, validated = _derive(ds_matches_dnskey=False,
                                   ad_authenticated=False)
    assert state == "broken"
    assert validated is False


def test_self_signature_invalid_is_broken():
    """DNSKEY RRSIG does not validate against the DNSKEY set — a
    genuine crypto failure at the child. Distinct from a DS/DNSKEY
    mismatch (which is a parent-child boundary bug)."""
    state, _, validated = _derive(self_signed=False,
                                   ds_matches_dnskey=True,
                                   ad_authenticated=False)
    assert state == "broken"
    assert validated is False


def test_ad_rejects_despite_crypto_ok_is_broken():
    """AD-bit=False from a validating resolver overrides a green
    cryptographic chain — the resolver is telling us it rejected the
    signature. A signed zone that fails validation at real resolvers
    is broken for its users regardless of what our crypto lib says."""
    state, _, validated = _derive(ad_authenticated=False)
    assert state == "broken"
    assert validated is False


# --------------------------------------------------------------------- incomplete

def test_dnskey_present_no_ds_is_incomplete():
    """Child signs its zone but no DS at parent — the chain isn't
    anchored to root, so validating resolvers treat the zone as
    insecure. Distinct from `not_configured` (no signing at all) and
    from `broken` (chain wired up but broken)."""
    state, notes, validated = _derive(ds=False, ds_matches_dnskey=None)
    assert state == "incomplete"
    assert any("no DS at parent" in n for n in notes), (
        f"incomplete must name the missing anchor; got {notes!r}"
    )


# --------------------------------------------------------------------- not_configured

def test_no_ds_no_dnskey_with_both_probes_responding_is_not_configured():
    """The google.com posture: both queries returned NoAnswer, so we
    have positive evidence the zone is unsigned. This is the ONLY
    input shape that legitimately produces `not_configured` — matches
    the L4 fix's contract that unretrievable never collapses here."""
    state, notes, validated = _derive(
        ds=False, dnskey=False, self_signed=None,
        ds_matches_dnskey=None, ad_authenticated=None,
    )
    assert state == "not_configured"
    assert validated is None
    assert notes == []


# --------------------------------------------------------------------- unknown (L4 gates)

def test_both_probes_unretrievable_is_unknown():
    """CLAUDE.md rule 1: unretrievable never collapses into
    not_configured. When neither DS nor DNSKEY reached a resolver,
    state must be unknown — regardless of the atomic-signal defaults."""
    state, notes, _ = _derive(
        ds=False, dnskey=False, self_signed=None,
        ds_matches_dnskey=None, ad_authenticated=None,
        ds_probe_responded=False, dnskey_probe_responded=False,
    )
    assert state == "unknown"
    assert any("unretrievable" in n.lower() or "unreachable" in n.lower()
               for n in notes), notes


def test_ds_probe_unretrievable_and_dnskey_absent_is_unknown():
    """Half-blocked: DS probe never got an answer, DNSKEY probe
    replied 'no records'. We cannot claim not_configured — DS state
    is unknown. Rule-1 half-gate."""
    state, notes, _ = _derive(
        ds=False, dnskey=False, self_signed=None,
        ds_matches_dnskey=None, ad_authenticated=None,
        ds_probe_responded=False, dnskey_probe_responded=True,
    )
    assert state == "unknown"
    assert any("DS probe unretrievable" in n for n in notes), notes


# --------------------------------------------------------------------- classification precedence

def test_ds_matches_False_takes_precedence_over_ad_authenticated_True():
    """If DS/DNSKEY hashing disagrees but a resolver happened to
    return AD=True (buggy resolver / cache poisoning window), the
    zone is still broken. The crypto verdict wins over the resolver
    verdict when they disagree, because we own the crypto and can be
    sure of it."""
    state, _, validated = _derive(ds_matches_dnskey=False,
                                   ad_authenticated=True)
    assert state == "broken", (
        f"crypto-fail must win over resolver-AD; got {state!r}"
    )
    assert validated is False


def test_self_signed_False_takes_precedence_over_ad_authenticated_True():
    """Same principle as above but for the self-signature. If we can
    prove the RRSIG doesn't cover the DNSKEY set, an AD=True from a
    downstream resolver is either a bug in the resolver or a stale
    cache — we do not trust it against our own crypto."""
    state, _, validated = _derive(self_signed=False,
                                   ad_authenticated=True)
    assert state == "broken"
    assert validated is False


# --------------------------------------------------------------------- pure-function invariants

def test_helper_is_side_effect_free():
    """The helper must not mutate any inputs. If a test passes a list
    as `notes` (which it doesn't — inputs are all bools/tri-states),
    the helper must not append to caller state. This is a design
    contract: the caller merges the returned notes list; the helper
    does not touch the caller's list."""
    args = dict(ds=True, dnskey=True, self_signed=True,
                ds_matches_dnskey=True, ad_authenticated=True,
                ds_probe_responded=True, dnskey_probe_responded=True)
    before = dict(args)
    _dnssec_derive_state(**args)
    assert args == before, "helper mutated its input kwargs"


def test_no_uncovered_input_shape_returns_none_state():
    """Combinatorial guard: every branch of the state machine returns
    one of the five states. A None or empty string leaking out would
    break the checks.py renderer which switches on `state`."""
    from itertools import product
    valid_states = {"validating", "broken", "incomplete",
                    "not_configured", "unknown"}
    for ds in (True, False):
        for dnskey in (True, False):
            for ss in (True, False, None):
                for dm in (True, False, None):
                    for ad in (True, False, None):
                        for dsr in (True, False):
                            for dkr in (True, False):
                                state, _, _ = _dnssec_derive_state(
                                    ds=ds, dnskey=dnskey,
                                    self_signed=ss,
                                    ds_matches_dnskey=dm,
                                    ad_authenticated=ad,
                                    ds_probe_responded=dsr,
                                    dnskey_probe_responded=dkr,
                                )
                                assert state in valid_states, (
                                    f"unmapped input shape produced "
                                    f"{state!r} for ds={ds} dnskey={dnskey} "
                                    f"ss={ss} dm={dm} ad={ad} "
                                    f"dsr={dsr} dkr={dkr}"
                                )
