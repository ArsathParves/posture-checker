"""Regression tests for D5 — open-resolver probe used a single query and
trusted the server's RA-flag/answer combination as ground truth.

Two false-PASS classes the old check missed:

  (1) RA=1 but answered_foreign=False. The server SUPPORTS recursion
      (advertises the RA capability bit) but refused our specific query.
      Common cause: source-subnet ACL that whitelists internal ranges
      and refuses everyone else. A random client on the public internet
      may be inside a whitelisted range even though we are not — the
      check would say PASS while the resolver is genuinely open to a
      large fraction of the internet.

  (2) Single-probe blind spots. If the target only answers recursion
      for specific query names it caches internally, one static probe
      (www.google.com) can be gamed or coincidentally denied.

Fix design:
  - Two probes per NS: (a) plain, (b) with an EDNS Client Subnet option
    naming a documentation prefix (203.0.113.0/24) to hint that the
    "client" is on a different subnet. Uses distinct probe names too.
  - Any probe that answers a foreign name with RA=1 → `open=True`.
  - Any probe with RA=1 AND answered=False → `partial_recursion=True`
    (server supports recursion but refused this attempt — likely ACLed).
  - `subnet_variance=True` when the two probes disagreed.
  - Checks orchestrator maps `partial_recursion` or `subnet_variance`
    to WARN, never PASS. Confirmed refusal (RA=0 on both probes) still
    PASSes.

The three CLAUDE.md rule 1 states remain distinct:
  - open (FAIL): confirmed answered_foreign from at least one probe.
  - refused (PASS): both probes RA=0.
  - inconclusive (WARN, not PASS): server supports recursion but refused
    our specific probes — cannot rule out openness from other vantages.
"""
from __future__ import annotations

from unittest.mock import patch

import dns.flags
import dns.rcode
import dns.rrset

import posture.dnsmod as dnsmod


# ---------------------------- fake response helpers ---------------------

def _mock_resp(ra: bool, answered: bool, rcode: int = dns.rcode.NOERROR):
    """Build a mock DNS response object with the flags the check reads."""
    class R:
        pass
    r = R()
    r.flags = dns.flags.RA if ra else 0
    r.answer = []
    if answered:
        r.answer = [dns.rrset.from_text_list("www.google.com.", 60, "IN", "A", ["1.2.3.4"])]
    r.rcode = lambda: rcode
    return r


# ---------------------------- probe count is ≥ 2 ------------------------

def test_open_resolver_sends_at_least_two_probes_per_ns():
    """A single probe cannot detect subnet-dependent ACLs. Baseline
    invariant of the D5 fix: at least two probes per NS."""
    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    calls: list = []

    def udp_fake(msg, ip, timeout=None):
        calls.append((msg, ip))
        return _mock_resp(ra=False, answered=False)

    with patch("dns.query.udp", side_effect=udp_fake):
        dnsmod.open_resolver_check(ns_map)

    assert len(calls) >= 2, f"expected ≥2 probes per NS, got {len(calls)}"


# ---------------------------- ECS on probe 2 ----------------------------

def test_second_probe_carries_edns_client_subnet_option():
    """The second probe must send an EDNS Client Subnet option — that is
    the *only* signal that reaches an authoritative NS to indicate we
    represent a client on a different subnet. Without ECS we're just
    repeating the same probe with a new TXID."""
    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    sent_messages: list = []

    def udp_fake(msg, ip, timeout=None):
        sent_messages.append(msg)
        return _mock_resp(ra=False, answered=False)

    with patch("dns.query.udp", side_effect=udp_fake):
        dnsmod.open_resolver_check(ns_map)

    # At least one message must include an ECS option in its EDNS OPT set.
    ecs_seen = False
    for m in sent_messages:
        for opt in m.options or []:
            if opt.otype == 8:  # OptionType.ECS is 8
                ecs_seen = True
                break
    assert ecs_seen, "expected an EDNS Client Subnet option on ≥1 probe"


# ---------------------------- confirmed open ---------------------------

def test_any_probe_answering_foreign_marks_open():
    """Worst-case wins: if either probe returned recursion for a foreign
    name, the server is open."""
    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}
    call_count = [0]

    def udp_fake(msg, ip, timeout=None):
        call_count[0] += 1
        # First probe refused; second answered. Old code would only see the first.
        if call_count[0] == 1:
            return _mock_resp(ra=True, answered=False)
        return _mock_resp(ra=True, answered=True)

    with patch("dns.query.udp", side_effect=udp_fake):
        out = dnsmod.open_resolver_check(ns_map)

    assert out["any_open"] is True
    assert out["per_ns"]["ns1.example."]["open"] is True


# ---------------------------- partial-recursion WARN --------------------

def test_ra_flag_set_but_no_answer_flags_partial_recursion():
    """The false-PASS case the audit called out: RA=1 says 'I do
    recursion', answered=False says 'not for you today'. Together they
    strongly suggest a subnet-based ACL that may serve recursion to
    other clients."""
    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}

    def udp_fake(msg, ip, timeout=None):
        return _mock_resp(ra=True, answered=False)

    with patch("dns.query.udp", side_effect=udp_fake):
        out = dnsmod.open_resolver_check(ns_map)

    per = out["per_ns"]["ns1.example."]
    assert per["open"] is False
    assert per["partial_recursion"] is True


def test_partial_recursion_surfaces_as_warn_not_pass():
    """The whole point of D5: a server that advertises recursion but
    refused our probes must not silently PASS the open-resolver check."""
    from posture import checks
    from posture.core import Report

    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {"safe_for_per_ns_checks": True}
    rep.data["ns_map"] = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}

    def udp_fake(msg, ip, timeout=None):
        return _mock_resp(ra=True, answered=False)

    # short-circuit AXFR so we exercise only the open-resolver path
    def fake_axfr(_d, _ns):
        return {"any_open": False, "per_ns": {}}

    with patch("dns.query.udp", side_effect=udp_fake), \
         patch.object(dnsmod, "axfr_open_check", side_effect=fake_axfr):
        checks._security(rep, "example.com")

    findings = [f for f in rep.findings if "open resolver" in f.label.lower()
                or "recursive" in f.label.lower()]
    assert findings, "expected an open-resolver-related finding"
    # None of the open-resolver findings may claim PASS when partial recursion detected.
    pass_findings = [f for f in findings if f.status == "PASS"]
    assert not pass_findings, \
        f"partial recursion must not produce PASS; got: {[(f.label, f.detail) for f in pass_findings]}"
    warn_findings = [f for f in findings if f.status == "WARN"]
    assert warn_findings, "expected a WARN when RA=1 but our probes were refused"


# ---------------------------- confirmed refusal is PASS ----------------

def test_ra_zero_on_both_probes_is_a_clean_pass():
    """Regression guard — the tightened check must not turn every server
    into a WARN. RA=0 on both probes = the server does not do recursion
    at all → PASS."""
    ns_map = {"ns1.example.": {"ipv4": ["192.0.2.1"], "ipv6": []}}

    def udp_fake(msg, ip, timeout=None):
        return _mock_resp(ra=False, answered=False)

    with patch("dns.query.udp", side_effect=udp_fake):
        out = dnsmod.open_resolver_check(ns_map)

    per = out["per_ns"]["ns1.example."]
    assert per["tested"] is True
    assert per["open"] is False
    assert per.get("partial_recursion") is False
