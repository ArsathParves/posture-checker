"""Regression tests for SPF RFC 7208 lookup counting (N12, N13).

Fixes pinned:
- §6.1: redirect= is ignored when 'all' is present
- §4.6.4: mx and mx:foo count as one DNS-querying mechanism each

All tests are offline: _count_spf_lookups only fetches nested records via
get_spf() when recursing, so a flat record with only include:/redirect= at
depth 0 is a pure string operation until it tries to resolve the target.
We patch get_spf to keep the whole test hermetic.
"""
from __future__ import annotations

from unittest.mock import patch

from posture.emailauth import _count_spf_lookups


def _no_recursion(_target):
    """Force nested lookups to return 'no record' so we only count depth 0."""
    return {"record": None}


def test_flat_record_counts_only_lookup_mechanisms():
    rec = "v=spf1 ip4:203.0.113.0/24 -all"
    with patch("posture.emailauth.get_spf", side_effect=_no_recursion):
        count, trace = _count_spf_lookups(rec, "example.com")
    assert count == 0
    assert trace == []


def test_a_and_mx_each_cost_one():
    rec = "v=spf1 a mx -all"
    with patch("posture.emailauth.get_spf", side_effect=_no_recursion):
        count, _ = _count_spf_lookups(rec, "example.com")
    assert count == 2


def test_mx_with_domain_argument_counts_once():
    """N13: mx:example.net is one lookup, not zero."""
    rec = "v=spf1 mx:mail.example.net -all"
    with patch("posture.emailauth.get_spf", side_effect=_no_recursion):
        count, trace = _count_spf_lookups(rec, "example.com")
    assert count == 1
    assert "mx:mail.example.net" in trace


def test_redirect_is_ignored_when_all_is_present():
    """N12: RFC 7208 §6.1 — redirect ignored if terminal 'all' present."""
    rec = "v=spf1 include:_spf.google.com -all redirect=other.example"
    with patch("posture.emailauth.get_spf", side_effect=_no_recursion):
        count, trace = _count_spf_lookups(rec, "example.com")
    # include costs 1, redirect must be ignored -> total 1
    assert count == 1
    assert "include:_spf.google.com" in trace
    assert not any("redirect=" in t for t in trace)


def test_redirect_counts_when_no_all():
    rec = "v=spf1 include:_spf.google.com redirect=other.example"
    with patch("posture.emailauth.get_spf", side_effect=_no_recursion):
        count, trace = _count_spf_lookups(rec, "example.com")
    assert count == 2
    assert any("redirect=other.example" in t for t in trace)


def test_ptr_counts_as_one_lookup():
    rec = "v=spf1 ptr -all"
    with patch("posture.emailauth.get_spf", side_effect=_no_recursion):
        count, _ = _count_spf_lookups(rec, "example.com")
    assert count == 1


def test_exists_counts_as_one_lookup():
    rec = "v=spf1 exists:%{i}._spf.example.com -all"
    with patch("posture.emailauth.get_spf", side_effect=_no_recursion):
        count, _ = _count_spf_lookups(rec, "example.com")
    assert count == 1


def test_ip4_and_ip6_do_not_count():
    rec = "v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 -all"
    with patch("posture.emailauth.get_spf", side_effect=_no_recursion):
        count, _ = _count_spf_lookups(rec, "example.com")
    assert count == 0


def test_qualifiers_do_not_confuse_parser():
    """+, -, ~, ? qualifiers precede the mechanism token."""
    rec = "v=spf1 +include:a.example ~include:b.example -all"
    with patch("posture.emailauth.get_spf", side_effect=_no_recursion):
        count, _ = _count_spf_lookups(rec, "example.com")
    assert count == 2


def test_loop_protection_prevents_infinite_recursion():
    """seen-set guards against include cycles."""
    def loopy(target):
        # a includes b, b includes a
        return {"record": f"v=spf1 include:{('b' if target=='a' else 'a')}.example -all"}
    with patch("posture.emailauth.get_spf", side_effect=loopy):
        count, _ = _count_spf_lookups("v=spf1 include:a.example -all", "start")
    # Must return without hanging; count is small and finite
    assert count < 50
