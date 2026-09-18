"""Regression tests for D2 — parent_delegation queried one parent NS only.

Originally the function:
  1. Called query(parent, "NS") to enumerate parent-side NSes.
  2. Iterated those, picked the FIRST with an A/AAAA record.
  3. Queried THAT ONE parent NS directly for the child's NS records.

A single stale/lame parent NS distorts the whole RDAP-vs-parent check;
CLAUDE.md ground truth #7 (indianbank.bank.in via NIXI) is exactly this
class of divergence surfaced from the *registry* side. The child-facing
symmetry — where the parent zone itself has inconsistent secondaries —
was invisible.

Fix: query up to `_PARENT_QUERY_MAX` parent NSes in parallel, record each
view. On unanimous agreement return the consensus (backward-compatible
shape). On disagreement expose `consensus=False, views={host: [ns]}` so
the downstream check can emit a divergence finding while the primary
comparison keeps working from the first successful response.
"""
from __future__ import annotations

from unittest.mock import patch

import dns.flags
import dns.message
import dns.rdatatype

import posture.dnsmod as dnsmod


# ---------------------------- helpers to fake DNS answers ---------------

def _fake_query(returns: dict):
    """Return a fake for dnsmod.query keyed on (name, rdtype)."""
    def _f(name, rdtype, nameservers=None):
        r = returns.get((name, rdtype))
        if r is None:
            return {"ok": False, "error": "NXDOMAIN"}
        return r
    return _f


def _fake_response_with_ns(ns_hosts):
    """Build a minimal dns.message.Message-like object with .answer/.authority
    populated with an NS rrset. Uses real dnspython machinery to build
    the message so parent_delegation's list(resp.answer) walk works
    without additional stubbing."""
    msg = dns.message.make_response(dns.message.make_query("child.example", "NS"))
    # Compose a small zone text and parse it into an rrset via dnspython's
    # from_text — this gives us the exact rdtype the walker expects.
    from dns import rrset as _rrset
    rr = _rrset.from_text_list("child.example.", 300, "IN", "NS",
                               [f"{h}." for h in ns_hosts])
    msg.answer = [rr]
    return msg


# ---------------------------- backward-compat ---------------------------

def test_single_parent_ns_still_works():
    """Only one parent NS reachable → consensus trivially True, shape
    unchanged for the primary consumer."""
    q_returns = {
        ("example", "NS"): {"ok": True, "records": ["ns1.parent."], "ttl": 300},
        ("ns1.parent", "A"): {"ok": True, "records": ["192.0.2.1"], "ttl": 300},
    }

    def udp_fake(msg, ip, timeout=None):
        return _fake_response_with_ns(["ns1.child", "ns2.child"])

    with patch.object(dnsmod, "query", side_effect=_fake_query(q_returns)), \
         patch("dns.query.udp", side_effect=udp_fake):
        result = dnsmod.parent_delegation("child.example")

    assert result["ok"] is True
    assert set(result["nameservers"]) == {"ns1.child", "ns2.child"}
    assert result.get("consensus") is True


# ---------------------------- consensus path ----------------------------

def test_multiple_parent_ns_agree_reports_consensus():
    """Two parent NSes both return the same child-side NS set → consensus."""
    q_returns = {
        ("example", "NS"): {"ok": True, "records": ["ns1.parent.", "ns2.parent."], "ttl": 300},
        ("ns1.parent", "A"): {"ok": True, "records": ["192.0.2.1"], "ttl": 300},
        ("ns2.parent", "A"): {"ok": True, "records": ["192.0.2.2"], "ttl": 300},
    }

    def udp_fake(msg, ip, timeout=None):
        return _fake_response_with_ns(["ns1.child", "ns2.child"])

    with patch.object(dnsmod, "query", side_effect=_fake_query(q_returns)), \
         patch("dns.query.udp", side_effect=udp_fake):
        result = dnsmod.parent_delegation("child.example")

    assert result["ok"] is True
    assert result["consensus"] is True
    assert set(result["nameservers"]) == {"ns1.child", "ns2.child"}


# ---------------------------- divergence path ---------------------------

def test_parent_ns_disagreement_is_flagged():
    """Two parent NSes return different child-side NS sets → consensus=False,
    views populated so downstream can name the disagreeing hosts."""
    q_returns = {
        ("example", "NS"): {"ok": True, "records": ["ns1.parent.", "ns2.parent."], "ttl": 300},
        ("ns1.parent", "A"): {"ok": True, "records": ["192.0.2.1"], "ttl": 300},
        ("ns2.parent", "A"): {"ok": True, "records": ["192.0.2.2"], "ttl": 300},
    }

    def udp_fake(msg, ip, timeout=None):
        # ns1.parent (192.0.2.1) reports {a, b}
        # ns2.parent (192.0.2.2) reports {a, b, stale}
        if ip == "192.0.2.1":
            return _fake_response_with_ns(["a.child", "b.child"])
        return _fake_response_with_ns(["a.child", "b.child", "stale.child"])

    with patch.object(dnsmod, "query", side_effect=_fake_query(q_returns)), \
         patch("dns.query.udp", side_effect=udp_fake):
        result = dnsmod.parent_delegation("child.example")

    assert result["ok"] is True
    assert result["consensus"] is False
    assert "views" in result
    assert len(result["views"]) == 2
    # nameservers must reflect the first successful response (backward compat)
    assert "nameservers" in result and result["nameservers"]


# ---------------------------- no reachable parent -----------------------

def test_no_reachable_parent_ns_is_unchanged():
    """Failure mode is unchanged — ok=False if no parent NS has an IP."""
    q_returns = {
        ("example", "NS"): {"ok": True, "records": ["ns1.parent."], "ttl": 300},
        # ns1.parent has no A/AAAA
    }
    with patch.object(dnsmod, "query", side_effect=_fake_query(q_returns)):
        result = dnsmod.parent_delegation("child.example")
    assert result["ok"] is False
    assert "parent_ip_lookup_failed" in result.get("error", "")


# ---------------------------- consumer WARN surface ---------------------

def test_checks_emits_warn_on_parent_ns_divergence():
    """The dnsmod-level `consensus=False` must surface as a WARN finding in
    the checks orchestrator — otherwise the divergence never reaches users."""
    from posture import checks
    from posture.core import Report

    rep = Report(domain_input="child.example", domain="child.example")
    rep.data["environment"] = {"safe_for_per_ns_checks": False}  # skip per-NS probing

    ns_map = {"a.child": {"ipv4": ["203.0.113.1"], "ipv6": []},
              "b.child": {"ipv4": ["203.0.113.2"], "ipv6": []}}

    def fake_get_ns_and_ips(_d):
        return {"ok": True, "ns": ns_map, "ttl": 300}

    def fake_parent_delegation(_d):
        # zone-served set matches ns1's view; ns2 has a stale extra
        return {
            "ok": True,
            "nameservers": ["a.child", "b.child"],
            "queried_via": ["ns1.parent", "ns2.parent"],
            "consensus": False,
            "views": {
                "ns1.parent": ["a.child", "b.child"],
                "ns2.parent": ["a.child", "b.child", "stale.child"],
            },
        }

    from unittest.mock import patch as _p
    with _p.object(dnsmod, "get_ns_and_ips", side_effect=fake_get_ns_and_ips), \
         _p.object(dnsmod, "parent_delegation", side_effect=fake_parent_delegation):
        checks._nameservers(rep, "child.example", skip_asn=True)

    warn_findings = [f for f in rep.findings
                     if f.status == "WARN" and "Parent-side NS agreement" in f.label]
    assert warn_findings, "Expected a WARN finding when parent NSes disagree"
    detail = warn_findings[0].detail
    assert "ns1.parent" in detail and "ns2.parent" in detail
    assert "stale.child" in detail
