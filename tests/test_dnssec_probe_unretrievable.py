"""Regression tests for L4 — dnssec_status collapsed unretrievable
DS/DNSKEY probes into `state="not_configured"`.

When every UDP query for DS and every fallback for DNSKEY fails
(iptables blocks UDP/53, or the network path is degraded but the
selftest has not yet flipped `safe_for_per_ns_checks`), both
`out["ds"]` and `out["dnskey"]` stay False. The state-machine's first
branch (`not ds and not dnskey → not_configured`) is meant for the
case where the *authoritative answer* to both queries is "absent".
It cannot distinguish "we asked and were told no" from "we could not
ask at all", so a signed zone under UDP/53 blackhole silently reported
as **FAIL — "Zone is unsigned — responses can be spoofed or cache-
poisoned"**.

That is a direct CLAUDE.md rule 1 violation: `unretrievable` collapsed
into `broken`, on the tool's highest-stakes finding.

Fix contract:
  - Track whether the DS query and the DNSKEY-loop produced *any*
    successful response.
  - When BOTH failed to produce a response, `state = "unknown"` with
    a note that names the probe outcome ("DS/DNSKEY queries
    unretrievable — UDP/53 may be blocked").
  - The two legitimate absence paths remain untouched:
      * DS answered NoAnswer + DNSKEY answered NoAnswer → not_configured
      * DS present + DNSKEY answered NoAnswer → broken (existing case)
      * DNSKEY present + DS NoAnswer → incomplete (existing case)
  - Downstream (`checks._dnssec`) already maps `state == "unknown"`
    to a UNKNOWN finding, so the fix requires no renderer change.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.exception
import dns.flags
import dns.rcode

from posture.dnsmod import dnssec_status


def test_state_is_unknown_when_all_probes_fail():
    """Every UDP query raises Timeout — simulates UDP/53 blocked in
    iptables. The zone might be signed, unsigned, or broken — we
    cannot tell. State must NOT be `not_configured` (which renders
    as a hard FAIL "zone is unsigned")."""
    def raise_timeout(*a, **kw):
        raise dns.exception.Timeout()

    with patch("posture.dnsmod.dns.query.udp", side_effect=raise_timeout):
        st = dnssec_status("example.com")

    assert st["state"] == "unknown", (
        f"When DS and DNSKEY probes are all unretrievable, state must be "
        f"'unknown' (CLAUDE.md rule 1 — never collapse unretrievable into "
        f"broken/unsigned). Got state={st['state']!r}. "
        f"Rendering this as not_configured causes a false FAIL 'zone is "
        f"unsigned' on any signed zone whose UDP/53 path is blocked."
    )


def test_note_names_the_probe_outcome_when_all_fail():
    """The operator has to know *why* the answer is UNKNOWN. A generic
    'AD-bit inconclusive' note is not enough — the DS and DNSKEY probes
    themselves must be called out."""
    def raise_timeout(*a, **kw):
        raise dns.exception.Timeout()

    with patch("posture.dnsmod.dns.query.udp", side_effect=raise_timeout):
        st = dnssec_status("example.com")

    joined = " | ".join(st["notes"]).lower()
    assert (
        "ds" in joined and "dnskey" in joined
        and ("unretrievable" in joined or "blocked" in joined
             or "no response" in joined or "could not query" in joined)
    ), (
        f"When probes are unretrievable, notes must name DS+DNSKEY and "
        f"identify the probe outcome. Got notes={st['notes']!r}"
    )


def test_not_configured_still_fires_when_probes_succeed_with_noanswer():
    """Regression guard: the fix must NOT weaken the legitimate
    not_configured branch. When both queries succeed and return
    NoAnswer (i.e. the zone genuinely has no DS and no DNSKEY),
    state stays not_configured."""
    def mock_udp(q, ip, timeout=None):
        resp = MagicMock()
        resp.rcode.return_value = dns.rcode.NOERROR
        resp.flags = 0
        resp.answer = []  # NoAnswer — genuine absence
        return resp

    with patch("posture.dnsmod.dns.query.udp", side_effect=mock_udp):
        st = dnssec_status("example.com")

    assert st["state"] == "not_configured", (
        f"Genuinely unsigned zones (both DS and DNSKEY queries returned "
        f"NoAnswer) must still classify as not_configured. Got {st['state']!r}"
    )
    assert st["ds"] is False
    assert st["dnskey"] is False


def test_state_is_unknown_when_only_ds_probe_fails_and_dnskey_missing():
    """Half-blocked: DS query times out, DNSKEY query succeeds but the
    zone genuinely has no DNSKEY (i.e. zone truly unsigned). Because
    we could not verify DS presence, we cannot claim `not_configured`
    — we only know DNSKEY is absent, not that DS is absent."""
    calls = {"n": 0}

    def mock_udp(q, ip, timeout=None):
        calls["n"] += 1
        if q.question[0].rdtype == 43:  # DS
            raise dns.exception.Timeout()
        resp = MagicMock()
        resp.rcode.return_value = dns.rcode.NOERROR
        resp.flags = 0
        resp.answer = []
        return resp

    with patch("posture.dnsmod.dns.query.udp", side_effect=mock_udp):
        st = dnssec_status("example.com")

    assert st["state"] == "unknown", (
        f"When the DS probe was unretrievable, we cannot claim "
        f"not_configured — got state={st['state']!r}"
    )
