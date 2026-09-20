"""Regression tests for FN3 — RFC 7489 §7.1 External Destination
Verification.

A DMARC record like `rua=mailto:reports@third-party.example` at
`example.com` only works if `third-party.example` opts in by
publishing a TXT record at:

    example.com._report._dmarc.third-party.example

containing at minimum `v=DMARC1;`. Without that opt-in, RFC 7489 §7.1
requires mail receivers to NOT send aggregate reports to that address.
So a domain that publishes an external rua whose destination has not
verified is effectively getting no reports — the DMARC deployment
looks configured but is silently broken.

Pre-FN3 the tool only checked whether `rua=` was present; it did not
walk the external destinations. A domain with a typo'd or expired
third-party reporting endpoint was reported as PASS.

Fix contract:
  - Parse `rua=` (and `ruf=` if published) into individual mailto:
    addresses; extract their host domains.
  - Same-org destinations (host == checked domain) are trusted —
    no verification query, no finding.
  - External destinations are verified via
    `<checked>._report._dmarc.<destination>` TXT lookup.
  - Verified (a `v=DMARC1` TXT is present) → PASS, one finding per
    verified external destination.
  - Not-verified (query succeeded, no record OR record without
    `v=DMARC1`) → FAIL. Aggregate reports will not be delivered.
  - Unretrievable (TxtUnretrievable) → UNKNOWN, degraded. Rule 1:
    an unreachable verification query is NOT evidence that the third
    party has failed to opt in.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from posture.emailauth import TxtUnretrievable, evaluate_dmarc_reporting


def _stub_txt(mapping: dict):
    """Return a `patch` context that stubs `_txt_records` — the mapping
    is name→(list[str] | Exception). Missing keys return []."""
    def fake(name):
        if name in mapping:
            v = mapping[name]
            if isinstance(v, Exception):
                raise v
            return v
        return []
    return patch("posture.emailauth._txt_records", side_effect=fake)


def test_internal_rua_needs_no_verification():
    """RFC 7489 §7.1 explicitly exempts destinations in the same
    Organizational Domain as the DMARC record. `mailto:reports@example.com`
    at `example.com` is internal and needs no verification query."""
    with _stub_txt({}):
        out = evaluate_dmarc_reporting(
            "example.com", rua="mailto:reports@example.com")
    external = [d for d in out["destinations"] if d["external"]]
    assert not external, (
        f"internal rua must not appear as an external destination. Got {out}"
    )


def test_external_rua_verified_is_pass():
    """External rua where the receiving domain publishes the
    ExtDestVerification record must surface a PASS destination."""
    verification = ["v=DMARC1;"]
    with _stub_txt({
        "example.com._report._dmarc.reports.thirdparty.example": verification,
    }):
        out = evaluate_dmarc_reporting(
            "example.com",
            rua="mailto:agg@reports.thirdparty.example")

    ext = [d for d in out["destinations"] if d["external"]]
    assert len(ext) == 1
    assert ext[0]["verified"] is True
    assert ext[0]["domain"] == "reports.thirdparty.example"


def test_external_rua_unverified_is_fail():
    """External rua where the verification TXT is absent must surface
    as unverified. Mail receivers will NOT send reports to this address
    — the DMARC deployment looks configured but reports are dropped."""
    with _stub_txt({}):  # verification lookup returns []
        out = evaluate_dmarc_reporting(
            "example.com",
            rua="mailto:agg@third-party.example")

    ext = [d for d in out["destinations"] if d["external"]]
    assert len(ext) == 1
    assert ext[0]["verified"] is False
    assert ext[0].get("unretrievable") in (False, None)


def test_external_rua_verification_unretrievable_is_unknown():
    """RFC 7489 §7.1 verification lookup was unretrievable (SERVFAIL,
    TIMEOUT, ...). Per rule 1 we must NOT collapse 'could not verify'
    into 'not verified'. Must surface as unretrievable=True."""
    with _stub_txt({
        "example.com._report._dmarc.third-party.example":
            TxtUnretrievable("SERVFAIL"),
    }):
        out = evaluate_dmarc_reporting(
            "example.com",
            rua="mailto:agg@third-party.example")

    ext = [d for d in out["destinations"] if d["external"]]
    assert len(ext) == 1
    assert ext[0]["unretrievable"] is True
    assert ext[0]["verified"] is None, (
        "verified must be None (unknown), not False (confirmed not verified). "
        f"Got {ext[0]}"
    )


def test_verification_txt_without_v_dmarc1_is_unverified():
    """A TXT at the verification name that does NOT start with `v=DMARC1`
    does not count as a valid opt-in per §7.1 — the ExtDestVerification
    record format is specifically `v=DMARC1;`. A stray TXT (SPF, random
    marker) is not verification."""
    with _stub_txt({
        "example.com._report._dmarc.third-party.example":
            ['"random note"', '"v=spf1 -all"'],
    }):
        out = evaluate_dmarc_reporting(
            "example.com",
            rua="mailto:agg@third-party.example")

    ext = [d for d in out["destinations"] if d["external"]]
    assert len(ext) == 1
    assert ext[0]["verified"] is False


def test_multiple_rua_destinations_are_all_checked():
    """A DMARC record can list multiple rua addresses, comma-separated
    (`mailto:a@x,mailto:b@y`). Every external destination must be
    verified independently — mixing verified + unverified must surface
    both statuses so the operator knows which reporting stream works."""
    with _stub_txt({
        "example.com._report._dmarc.opted-in.example": ["v=DMARC1;"],
        # opted-out.example has no verification record
    }):
        out = evaluate_dmarc_reporting(
            "example.com",
            rua="mailto:a@opted-in.example,mailto:b@opted-out.example")

    by_domain = {d["domain"]: d for d in out["destinations"]
                 if d["external"]}
    assert by_domain["opted-in.example"]["verified"] is True
    assert by_domain["opted-out.example"]["verified"] is False


def test_ruf_destinations_also_verified():
    """RFC 7489 §7.1 verification applies to both `rua=` and `ruf=`.
    A domain with a valid rua but a broken external ruf still has a
    reporting problem — forensic reports won't flow."""
    with _stub_txt({}):
        out = evaluate_dmarc_reporting(
            "example.com",
            rua="mailto:agg@example.com",  # internal, no issue
            ruf="mailto:forensic@third-party.example")

    ext = [d for d in out["destinations"] if d["external"]]
    assert len(ext) == 1
    assert ext[0]["tag"] == "ruf"
    assert ext[0]["verified"] is False


def test_no_rua_no_destinations():
    """Sanity: a DMARC record with no `rua=` and no `ruf=` produces an
    empty destinations list — the check just does nothing."""
    with _stub_txt({}):
        out = evaluate_dmarc_reporting("example.com", rua=None, ruf=None)
    assert out["destinations"] == []


def test_malformed_rua_is_skipped():
    """A `rua=` value that isn't a `mailto:` URI (e.g. `https://...`
    which RFC 7489 allows but the tool doesn't verify) must not crash
    — it just isn't verified. Malformed / unparseable entries are
    reported as `parse_error=True` so the CLI can surface them."""
    with _stub_txt({}):
        out = evaluate_dmarc_reporting(
            "example.com",
            rua="not-a-url,mailto:reports@example.com")

    parse_errors = [d for d in out["destinations"]
                    if d.get("parse_error")]
    assert len(parse_errors) == 1
    assert parse_errors[0]["raw"] == "not-a-url"
