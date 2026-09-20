"""T4 — Fault-injection tests for `selftest.check_environment`.

`check_environment` is a NON-NEGOTIABLE gate (CLAUDE.md rule 5): if
it reports the network path is untrustworthy, every per-NS check
downstream MUST degrade to UNKNOWN. A regression that changed the
gate's return shape or silenced its notes would silently re-enable
false-positive findings on corporate networks with transparent DNS
proxies — exactly the failure mode that motivated the module.

Existing tests (test_cli_selftest_banner.py) pin the CLI's rendering
of self-test output, but the self-test's internal logic is untested.
This file fault-injects each network capability:

  1. Clean env: no interception, AA trustworthy → safe_for_per_ns_checks=True
  2. UDP/53 interception (blackhole IPs answer) → intercepted=True, safe=False
  3. AA flag rewritten (control query returns without AA) → safe=False
  4. UDP/53 blocked entirely (Timeout) → udp53_direct=False
  5. TCP/53 blocked → tcp53_direct=False
  6. Combined faults (interception + TCP block) → notes name both

The three network entry points patched:
  - `posture.selftest.dns.query.udp` — blackhole probes + control query
  - `posture.selftest.dns.query.tcp` — TCP/53 reachability probe
  - `posture.selftest.dns.resolver.resolve` — resolves ns1.google.com IP

Each test builds a fake wire path that only responds to specific
(destination, protocol) tuples so we can control every branch.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import dns.exception
import dns.flags
import dns.rcode

from posture.selftest import BLACKHOLE_PROBES, check_environment


# --------------------------------------------------------------------- fake infra

class _FakeMsg:
    """Minimal DNS response mock — flags-carrying only."""
    def __init__(self, aa: bool = True, ra: bool = False):
        self.flags = 0
        if aa:
            self.flags |= dns.flags.AA
        if ra:
            self.flags |= dns.flags.RA

    def rcode(self):
        return dns.rcode.NOERROR


class _FakeAnswer:
    """dns.resolver.resolve() → iterable of records with .address."""
    def __init__(self, address: str = "8.8.4.4"):
        self._records = [MagicMock(address=address)]

    def __iter__(self):
        return iter(self._records)

    def __getitem__(self, i):
        return self._records[i]


def _install(monkeypatch, *, udp, tcp=None, resolver_addr="8.8.4.4",
             resolver_raises=None):
    """Wire the three entry points. Each of `udp`/`tcp` is a callable
    `(query, ip, timeout) → _FakeMsg` or a callable that raises."""
    monkeypatch.setattr("posture.selftest.dns.query.udp", udp)
    if tcp is None:
        # Default TCP: succeeds silently. Return value is not read by selftest.
        tcp = lambda *a, **kw: _FakeMsg()
    monkeypatch.setattr("posture.selftest.dns.query.tcp", tcp)

    if resolver_raises:
        monkeypatch.setattr("posture.selftest.dns.resolver.resolve",
                             MagicMock(side_effect=resolver_raises))
    else:
        monkeypatch.setattr("posture.selftest.dns.resolver.resolve",
                             MagicMock(return_value=_FakeAnswer(resolver_addr)))


# --------------------------------------------------------------------- clean

def test_clean_env_is_safe_for_per_ns_checks(monkeypatch):
    """The happy path: blackhole probes time out, control query returns
    AA=True, TCP succeeds. Result must be safe_for_per_ns_checks=True
    with no notes."""
    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        # Control query to the resolver-provided IP: return AA-set answer.
        return _FakeMsg(aa=True)

    _install(monkeypatch, udp=udp)
    env = check_environment(timeout=0.01)

    assert env["intercepted"] is False
    assert env["udp53_direct"] is True
    assert env["tcp53_direct"] is True
    assert env["aa_flag_trustworthy"] is True
    assert env["safe_for_per_ns_checks"] is True
    assert env["notes"] == []


# --------------------------------------------------------------------- interception

def test_interception_when_blackhole_ips_answer(monkeypatch):
    """RFC 5737 addresses that "answer" DNS mean UDP/53 is being
    intercepted by a middlebox. This MUST set intercepted=True and
    disable safe_for_per_ns_checks (CLAUDE.md rule 5)."""
    def udp(q, ip, timeout=None):
        # Every IP answers — full interception.
        return _FakeMsg(aa=True)

    _install(monkeypatch, udp=udp)
    env = check_environment(timeout=0.01)

    assert env["intercepted"] is True
    assert env["safe_for_per_ns_checks"] is False, (
        "interception must disable per-NS checks; rule-5 gate broken"
    )
    joined = " | ".join(env["notes"]).lower()
    assert "intercept" in joined, (
        f"notes must name the interception; got {env['notes']!r}"
    )
    # Note must include the fraction of probes that answered.
    assert f"{len(BLACKHOLE_PROBES)}/{len(BLACKHOLE_PROBES)}" in " ".join(env["notes"])


def test_partial_interception_still_flags_intercepted(monkeypatch):
    """Even ONE blackhole IP answering is enough to declare
    interception — a middlebox may only intercept for some subnets.
    Never treat partial interception as safe."""
    def udp(q, ip, timeout=None):
        if ip == BLACKHOLE_PROBES[0]:
            return _FakeMsg(aa=True)  # This one leaks.
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        return _FakeMsg(aa=True)  # Control query still works.

    _install(monkeypatch, udp=udp)
    env = check_environment(timeout=0.01)

    assert env["intercepted"] is True
    assert env["safe_for_per_ns_checks"] is False


# --------------------------------------------------------------------- AA rewrite

def test_aa_flag_missing_disables_safe_flag(monkeypatch):
    """A resolver-in-the-middle typically strips the AA flag on
    responses passing through. Control query to a known authoritative
    server MUST come back with AA=True — if it doesn't, the wire path
    is untrustworthy. Note must name AA."""
    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        return _FakeMsg(aa=False, ra=True)  # RA set → resolver in the middle

    _install(monkeypatch, udp=udp)
    env = check_environment(timeout=0.01)

    assert env["aa_flag_trustworthy"] is False
    assert env["safe_for_per_ns_checks"] is False
    assert any("AA" in n for n in env["notes"]), (
        f"AA-strip note missing; got {env['notes']!r}"
    )


# --------------------------------------------------------------------- UDP/53 blocked

def test_udp53_control_query_timeout(monkeypatch):
    """When the CONTROL query (to ns1.google.com) times out but
    blackhole IPs also don't answer, udp53_direct is False and the
    note names the timeout. The blackhole leg still passes clean."""
    def udp(q, ip, timeout=None):
        raise dns.exception.Timeout()

    _install(monkeypatch, udp=udp)
    env = check_environment(timeout=0.01)

    assert env["intercepted"] is False   # nobody answered → not intercepted
    assert env["udp53_direct"] is False
    assert env["safe_for_per_ns_checks"] is False
    assert any("timed out" in n.lower() or "timeout" in n.lower()
               for n in env["notes"]), env["notes"]


def test_udp53_control_query_non_timeout_exception(monkeypatch):
    """Any non-Timeout exception on the control query (e.g. socket
    error, resolver name failure) must still set udp53_direct=False
    and add a typed note — not crash the whole self-test."""
    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        raise OSError("Network unreachable")

    _install(monkeypatch, udp=udp)
    env = check_environment(timeout=0.01)

    assert env["udp53_direct"] is False
    assert env["safe_for_per_ns_checks"] is False
    assert any("UDP/53 control" in n and "OSError" in n for n in env["notes"]), (
        f"non-Timeout exception must be typed in note; got {env['notes']!r}"
    )


# --------------------------------------------------------------------- TCP/53 blocked

def test_tcp53_blocked_note_present(monkeypatch):
    """TCP/53 failure only sets tcp53_direct=False and adds a note.
    It does NOT flip safe_for_per_ns_checks by itself (per-NS checks
    are UDP-first) but it must produce an actionable note for AXFR /
    truncated-response fallback consumers."""
    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        return _FakeMsg(aa=True)

    def tcp(*a, **kw):
        raise OSError("connection refused")

    _install(monkeypatch, udp=udp, tcp=tcp)
    env = check_environment(timeout=0.01)

    assert env["tcp53_direct"] is False
    assert any("TCP/53" in n for n in env["notes"]), env["notes"]
    # UDP path is clean → safe_for_per_ns_checks remains True.
    assert env["safe_for_per_ns_checks"] is True, (
        f"TCP block alone should not disable per-NS UDP checks; got "
        f"safe_for_per_ns_checks={env['safe_for_per_ns_checks']!r}"
    )


# --------------------------------------------------------------------- combined

def test_all_faults_combined(monkeypatch):
    """Full outage: interception + AA rewrite + TCP block. Every
    fault must be surfaced in `notes` and every capability flag
    must reflect the fault."""
    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            return _FakeMsg(aa=False)  # everyone answers → interception
        return _FakeMsg(aa=False, ra=True)  # AA stripped

    def tcp(*a, **kw):
        raise dns.exception.Timeout()

    _install(monkeypatch, udp=udp, tcp=tcp)
    env = check_environment(timeout=0.01)

    assert env["intercepted"] is True
    assert env["aa_flag_trustworthy"] is False
    assert env["tcp53_direct"] is False
    assert env["safe_for_per_ns_checks"] is False
    joined = " | ".join(env["notes"]).lower()
    assert "intercept" in joined
    assert "aa" in joined
    assert "tcp/53" in joined


# --------------------------------------------------------------------- shape contract

def test_return_shape_contains_all_expected_keys(monkeypatch):
    """The dict shape is a public contract — downstream renderers
    (cli.py, web/server.py) read specific keys. A refactor that
    dropped or renamed one would break those consumers without
    tripping any existing test."""
    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        return _FakeMsg(aa=True)

    _install(monkeypatch, udp=udp)
    env = check_environment(timeout=0.01)

    expected = {"udp53_direct", "tcp53_direct", "intercepted",
                "aa_flag_trustworthy", "notes", "safe_for_per_ns_checks"}
    assert set(env.keys()) == expected, (
        f"return shape changed: expected {expected!r}, got {set(env.keys())!r}"
    )
    # Types are stable — notes is a list, safe_for_per_ns_checks is a bool.
    assert isinstance(env["notes"], list)
    assert isinstance(env["safe_for_per_ns_checks"], bool)


def test_resolver_lookup_failure_does_not_affect_control_leg(monkeypatch):
    """Post-B33: the control leg uses static root-server IPs and does
    NOT call the recursive resolver, so a broken resolver must be
    invisible to the self-test. This locks in the SPOF-removal fix —
    the control leg no longer inherits the resolver's reliability."""
    def udp(q, ip, timeout=None):
        if ip in BLACKHOLE_PROBES:
            raise dns.exception.Timeout()
        # Any non-blackhole probe hits a root IP directly.
        return _FakeMsg(aa=True)

    _install(monkeypatch, udp=udp,
             resolver_raises=dns.exception.DNSException("no resolver"))
    env = check_environment(timeout=0.01)

    # Resolver is broken but control leg still works.
    assert env["udp53_direct"] is True
    assert env["tcp53_direct"] is True
    assert env["aa_flag_trustworthy"] is True
    assert env["safe_for_per_ns_checks"] is True
    # Shape stays intact — no crash, no missing keys.
    assert isinstance(env["notes"], list)
