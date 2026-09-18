"""Regression tests for evaluate_dmarc — RFC 7489 tag parsing."""
from __future__ import annotations

from unittest.mock import patch

import posture.emailauth as ea


def _fake_txt(records):
    def _f(domain):
        return records
    return _f


def test_reject_policy_maps_to_strong():
    with patch.object(ea, "_txt_records",
                      side_effect=_fake_txt(["v=DMARC1; p=reject; rua=mailto:d@x"])):
        r = ea.evaluate_dmarc("example.com")
    assert r["present"] is True
    assert r["policy"] == "reject"
    assert r["strength"] == "strong"


def test_quarantine_maps_to_moderate():
    with patch.object(ea, "_txt_records",
                      side_effect=_fake_txt(["v=DMARC1; p=quarantine"])):
        r = ea.evaluate_dmarc("example.com")
    assert r["strength"] == "moderate"


def test_none_maps_to_weak():
    with patch.object(ea, "_txt_records",
                      side_effect=_fake_txt(["v=DMARC1; p=none"])):
        r = ea.evaluate_dmarc("example.com")
    assert r["strength"] == "weak"


def test_absent_record_reports_present_false():
    with patch.object(ea, "_txt_records", side_effect=_fake_txt([])):
        r = ea.evaluate_dmarc("example.com")
    assert r["present"] is False


def test_unretrievable_reports_none_not_false():
    """N2 pattern: unretrievable != absent."""
    def _raise(_domain):
        raise ea.TxtUnretrievable("truncated")
    with patch.object(ea, "_txt_records", side_effect=_raise):
        r = ea.evaluate_dmarc("example.com")
    assert r["present"] is None
    assert "unretrievable" in r


def test_subdomain_and_alignment_tags_parsed():
    rec = "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50"
    with patch.object(ea, "_txt_records", side_effect=_fake_txt([rec])):
        r = ea.evaluate_dmarc("example.com")
    assert r["subdomain_policy"] == "quarantine"
    assert r["alignment_dkim"] == "s"
    assert r["alignment_spf"] == "s"
    assert r["pct"] == "50"
