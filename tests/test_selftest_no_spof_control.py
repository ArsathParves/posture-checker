"""B33 — self-test control resolver must not be a single point of failure.

Prior state (see git for `ns1.google.com`):
`selftest.check_environment` had two SPOFs in its control leg:
  1. It called `dns.resolver.resolve("ns1.google.com", "A")` — a
     resolver lookup that itself needs the network the self-test is
     trying to characterise.
  2. It then probed EXACTLY ONE authoritative server — the specific
     IP the resolver returned. If Google's NS was overloaded, geo-
     rerouted, or serving a stale response for its own name, the
     self-test would incorrectly declare the whole environment
     untrusted, cascading a downstream UNKNOWN on every check.

Failure mode this closes:
  A pre-sales SE runs the tool against a customer domain over a
  mobile hotspot. Their operator's resolver returns a stale
  `ns1.google.com` A record → control probe hits an unrelated IP →
  `aa_flag_trustworthy=False` → every per-NS check downstream reports
  UNKNOWN. The customer's domain is fine; the tool is broken.

Fix:
  - Replace `ns1.google.com` with a rotating sample from the IANA
    root-server set. Root IPs are stable, well-known, and belong to
    thirteen independently-operated organisations — no single
    outage can defeat the control leg.
  - Any single root probe failing is now benign — the quorum is
    what matters (`_CONTROL_PROBE_COUNT_SUCCESS_MIN` of `N`).
  - `dns.resolver.resolve` MUST NOT be called by the control leg.
    Coupling a network-integrity check to a recursive resolver is
    the exact circular-dependency this bug fixes.

Rule 5 semantics preserved: `safe_for_per_ns_checks` still requires
BOTH `not intercepted` AND `aa_flag_trustworthy`. That contract is
downstream-load-bearing (checks.py rule-5 gate); only the
implementation of how we establish `aa_flag_trustworthy` changed.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import dns.exception
import dns.flags
import dns.rcode
import pytest

from posture import selftest
from posture.selftest import BLACKHOLE_PROBES, check_environment


class _FakeMsg:
    def __init__(self, aa: bool = True, ra: bool = False):
        self.flags = 0
        if aa:
            self.flags |= dns.flags.AA
        if ra:
            self.flags |= dns.flags.RA

    def rcode(self):
        return dns.rcode.NOERROR


# --------------------------------------------------------------------- surface area

def test_root_server_table_exists():
    """The root-server table is the anchor for the whole B33 fix. If
    it disappears or shrinks below a quorum-capable size, the SPOF
    reappears silently."""
    assert hasattr(selftest, "_ROOT_SERVERS_V4"), (
        "selftest._ROOT_SERVERS_V4 must exist — the rotating control "
        "probe depends on it"
    )
    roots = selftest._ROOT_SERVERS_V4
    # 13 is the canonical count (a-m). Anything less than 3 defeats
    # the "no single root can defeat the check" property.
    assert len(roots) >= 3, (
        f"root-server table too small ({len(roots)}) — a quorum-of-N "
        "control probe needs at least 3 independent operators"
    )
    # Each entry is (name, ipv4). Names must be under root-servers.net;
    # IPs must be routable IPv4 literals (bogon check would burn later).
    for entry in roots:
        assert len(entry) == 2, entry
        name, ip = entry
        assert name.endswith(".root-servers.net"), name
        # Very light IP shape check — full parsing lives in ipaddress.
        parts = ip.split(".")
        assert len(parts) == 4 and all(p.isdigit() for p in parts), ip


# --------------------------------------------------------------------- rotation

def test_control_probe_hits_multiple_roots(monkeypatch):
    """The whole point of B33: the control leg must probe more than
    one authoritative server. If it hits only one, the SPOF is back.
    We record every non-blackhole destination and assert cardinality
    ≥ 2 (the quorum bound; any smaller and a single misbehaving
    root defeats the check)."""
    hit_ips: set[str] = set()

    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        hit_ips.add(ip)
        return _FakeMsg(aa=True)

    monkeypatch.setattr("posture.selftest.dns.query.udp", udp)
    monkeypatch.setattr("posture.selftest.dns.query.tcp",
                        lambda *a, **kw: _FakeMsg())
    # If the control leg secretly called the resolver, blow up loudly.
    monkeypatch.setattr(
        "posture.selftest.dns.resolver.resolve",
        MagicMock(side_effect=AssertionError(
            "control probe must not use the recursive resolver — B33")))

    check_environment(timeout=0.01)

    root_ips = {ip for _name, ip in selftest._ROOT_SERVERS_V4}
    hit_roots = hit_ips & root_ips
    assert len(hit_roots) >= 2, (
        f"control probe hit only {len(hit_roots)} root(s): {hit_roots!r} "
        "— the SPOF has regressed"
    )


def test_control_probe_does_not_use_recursive_resolver(monkeypatch):
    """The specific regression trap: if anything in the control leg
    calls `dns.resolver.resolve`, the check inherits the resolver's
    reliability instead of establishing it. That was the bug."""
    resolve_spy = MagicMock(side_effect=AssertionError(
        "dns.resolver.resolve must NOT be called by the control leg"))
    monkeypatch.setattr("posture.selftest.dns.resolver.resolve", resolve_spy)

    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        return _FakeMsg(aa=True)

    monkeypatch.setattr("posture.selftest.dns.query.udp", udp)
    monkeypatch.setattr("posture.selftest.dns.query.tcp",
                        lambda *a, **kw: _FakeMsg())

    check_environment(timeout=0.01)  # must not raise
    assert resolve_spy.call_count == 0, (
        "resolver was called — the SPOF has regressed"
    )


# --------------------------------------------------------------------- resilience

def test_one_root_down_does_not_defeat_control(monkeypatch):
    """The failure this bug closes: a single misbehaving root must
    NOT tank `aa_flag_trustworthy`. Two of three probes succeeding
    with AA=1 is enough to trust the wire path."""
    # Pick a specific root to fail; every other probe succeeds cleanly.
    doomed_ip = selftest._ROOT_SERVERS_V4[0][1]

    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        if ip == doomed_ip:
            raise dns.exception.Timeout()
        return _FakeMsg(aa=True)

    monkeypatch.setattr("posture.selftest.dns.query.udp", udp)
    monkeypatch.setattr("posture.selftest.dns.query.tcp",
                        lambda *a, **kw: _FakeMsg())
    monkeypatch.setattr("posture.selftest.dns.resolver.resolve",
                        MagicMock())

    # Force the doomed root into the sample so this test is deterministic
    # regardless of the random rotation.
    original_sample = selftest._control_probes

    def _biased_sample():
        base = original_sample()
        # Ensure the doomed entry is definitely in the probed set.
        if not any(ip == doomed_ip for _n, ip in base):
            base = [selftest._ROOT_SERVERS_V4[0], *base[:-1]]
        return base

    monkeypatch.setattr("posture.selftest._control_probes", _biased_sample)

    env = check_environment(timeout=0.01)
    assert env["udp53_direct"] is True
    assert env["aa_flag_trustworthy"] is True, (
        f"one root down must not defeat AA trust; env={env!r}"
    )
    assert env["safe_for_per_ns_checks"] is True


def test_all_roots_down_marks_udp_direct_false(monkeypatch):
    """When every root probe fails, udp53_direct is False and a note
    names the timeout — same downstream semantics as before B33."""
    def udp(q, ip, timeout=None):
        raise dns.exception.Timeout()

    monkeypatch.setattr("posture.selftest.dns.query.udp", udp)
    monkeypatch.setattr("posture.selftest.dns.query.tcp",
                        lambda *a, **kw: _FakeMsg())
    monkeypatch.setattr("posture.selftest.dns.resolver.resolve", MagicMock())

    env = check_environment(timeout=0.01)
    assert env["udp53_direct"] is False
    assert env["safe_for_per_ns_checks"] is False
    joined = " | ".join(env["notes"]).lower()
    assert "timed out" in joined or "timeout" in joined, env["notes"]


def test_partial_success_still_safe(monkeypatch):
    """Two of three succeed with AA=True → quorum met, environment
    trusted. Third probe raising OSError is benign, not disqualifying."""
    # Deterministically pick 3 known root IPs.
    monkeypatch.setattr(
        "posture.selftest._control_probes",
        lambda: selftest._ROOT_SERVERS_V4[:3])

    doomed_ip = selftest._ROOT_SERVERS_V4[0][1]

    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        if ip == doomed_ip:
            raise OSError("no route to host")
        return _FakeMsg(aa=True)

    monkeypatch.setattr("posture.selftest.dns.query.udp", udp)
    monkeypatch.setattr("posture.selftest.dns.query.tcp",
                        lambda *a, **kw: _FakeMsg())
    monkeypatch.setattr("posture.selftest.dns.resolver.resolve", MagicMock())

    env = check_environment(timeout=0.01)
    assert env["udp53_direct"] is True
    assert env["aa_flag_trustworthy"] is True
    assert env["safe_for_per_ns_checks"] is True


def test_aa_stripped_on_all_successful_probes_is_untrustworthy(monkeypatch):
    """Every successful probe returns AA=0 → a middlebox is stripping
    the flag. AA-trust must be False even though UDP works."""
    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        return _FakeMsg(aa=False, ra=True)  # resolver-in-the-middle shape

    monkeypatch.setattr("posture.selftest.dns.query.udp", udp)
    monkeypatch.setattr("posture.selftest.dns.query.tcp",
                        lambda *a, **kw: _FakeMsg())
    monkeypatch.setattr("posture.selftest.dns.resolver.resolve", MagicMock())

    env = check_environment(timeout=0.01)
    assert env["udp53_direct"] is True
    assert env["aa_flag_trustworthy"] is False
    assert env["safe_for_per_ns_checks"] is False
    assert any("AA" in n for n in env["notes"]), env["notes"]
