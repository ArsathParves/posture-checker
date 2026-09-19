"""B13 — SPF recursion depth guards must be consistent.

`_count_spf_lookups` previously had two mismatched thresholds:

  * Entry guard: `depth > 10` — hard cutoff, returns (0, []).
  * Recursion gate: `depth < 5` — controls whether to descend into
    the current include target's own record.

Effect: a chain of 10 includes (d1 → d2 → … → d10, each includes
the next) counted only ~6 lookups. The RFC-correct count is 10.
The tool declared such a record RFC-compliant when it actually
exceeded the 10-lookup limit (RFC 7208 §4.6.4). The displayed trace
under-represented the count and the count under-represented reality.

Fix: use `depth > 10` as the ONLY termination guard. Cycle
protection is provided by the per-path `seen` frozenset (B12);
runaway pathological input is bounded by `depth > 10`. There is no
justification for a second, tighter `depth < 5` cap.
"""
from __future__ import annotations

import posture.emailauth as ea


def _install(monkeypatch, records):
    """Replace `get_spf` with a table so we can construct exact
    include chains without any live DNS."""
    def _fake(domain):
        rec = records.get(domain)
        if rec is None:
            return {"present": False, "record": None}
        return {"present": True, "record": rec}
    monkeypatch.setattr(ea, "get_spf", _fake)


def _linear_chain(length):
    """Return a records dict for d1 → d2 → … → d{length}, where each
    domain includes the next and the last is terminal (`-all` only).
    RFC-correct lookup count for the top-level record `include:d1.com`
    is `length` (top's include + inner includes)."""
    records = {}
    for i in range(1, length + 1):
        if i < length:
            records[f"d{i}.com"] = f"v=spf1 include:d{i+1}.com -all"
        else:
            records[f"d{i}.com"] = "v=spf1 -all"
    return records


def test_chain_of_10_includes_counts_all_10(monkeypatch):
    """The load-bearing case. d1 → d2 → … → d10 → terminal; the RFC
    counts each `include:` mechanism as one lookup, so the top-level
    record `include:d1.com` contributes 10 lookups total. Previously
    the `depth < 5` recursion gate short-circuited the count at 6."""
    _install(monkeypatch, _linear_chain(10))
    top = "v=spf1 include:d1.com -all"
    count, trace = ea._count_spf_lookups(top, "top.example")
    assert count == 10, (
        f"chain of 10 includes must count 10 (was capped at 6 by "
        f"depth<5 gate); got {count}\ntrace:\n" + "\n".join(trace)
    )


def test_chain_of_11_includes_exceeds_limit(monkeypatch):
    """Boundary: a chain of 11 must surface as >10 so the tool can
    permerror the record per RFC 7208 §4.6.4."""
    _install(monkeypatch, _linear_chain(11))
    top = "v=spf1 include:d1.com -all"
    count, _ = ea._count_spf_lookups(top, "top.example")
    assert count > 10, (
        f"chain of 11 must surface over-limit; got {count}"
    )


def test_trace_matches_count_for_deep_chain(monkeypatch):
    """Trace and count must not disagree — if count says 10 lookups
    happened, trace must list 10 entries. Previously trace ran to
    depth 5 while count stopped counting at 6, but with independent
    definitions the two could diverge on more complex trees."""
    _install(monkeypatch, _linear_chain(10))
    top = "v=spf1 include:d1.com -all"
    count, trace = ea._count_spf_lookups(top, "top.example")
    include_lines = [t for t in trace if "include:" in t]
    assert len(include_lines) == count, (
        f"trace entries ({len(include_lines)}) must match count "
        f"({count}); trace:\n" + "\n".join(trace)
    )


def test_depth_10_hard_cutoff_still_terminates(monkeypatch):
    """Runaway safety: a very deep record (depth 20) must still
    terminate. The `depth > 10` entry guard is the bound."""
    _install(monkeypatch, _linear_chain(20))
    top = "v=spf1 include:d1.com -all"
    count, _ = ea._count_spf_lookups(top, "top.example")
    # The exact count at the boundary depends on the fix's precise
    # semantics; the load-bearing assertion is termination + bounded.
    assert 10 <= count <= 20, (
        f"deep record must terminate with bounded count; got {count}"
    )


def test_shallow_record_unchanged(monkeypatch):
    """Regression backstop: a shallow record (2 includes, chain length
    3) must still count 3 lookups. The fix must not perturb the case
    that was already correct."""
    _install(monkeypatch, _linear_chain(3))
    top = "v=spf1 include:d1.com -all"
    count, _ = ea._count_spf_lookups(top, "top.example")
    assert count == 3
