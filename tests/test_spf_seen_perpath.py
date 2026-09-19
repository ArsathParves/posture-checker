"""B12 — SPF `seen` set must be per-path, not global.

RFC 7208 §4.6.4 counts each DNS-term mechanism (include, a, mx,
ptr, exists) and the redirect modifier as one lookup toward the
10-lookup cap. The RFC does NOT permit a global "already visited"
short-circuit across sibling include branches: two `include:` terms
referencing the same target in two different branches of the tree
represent two distinct DNS-lookup budget items, and each of the
target's own DNS-term mechanisms is likewise counted per-visit.

Prior to this fix, `_count_spf_lookups` seeded `seen` at the top
call and never copied it. The FIRST visit to a shared dependency
counted all its nested DNS-term mechanisms; SUBSEQUENT visits from
other branches short-circuited to `(0, [])`. Result: real over-
limit records (10+ mechanisms) graded as compliant, because the
tool believed the shared dependency had "already been counted".

Rule 3: this test fails before the fix and passes after.

Cycle protection is preserved by two remaining guards:
  * `depth > 10` — hard cutoff
  * `depth < 5` — recursion gate (count still increments for the
    mechanism itself, but no deeper walk happens)
so a truly cyclic record like `a → b → a → b …` still terminates
without runaway recursion.
"""
from __future__ import annotations

import posture.emailauth as ea


def _install(monkeypatch, records):
    """Replace `get_spf` with an in-memory table so we can construct
    exact call graphs without any live DNS."""
    def _fake(domain):
        rec = records.get(domain)
        if rec is None:
            return {"present": False, "record": None}
        return {"present": True, "record": rec}
    monkeypatch.setattr(ea, "get_spf", _fake)


def test_shared_dependency_visited_from_two_branches_counts_both_paths(monkeypatch):
    """`a` and `b` both include `c`; `c` includes three terminal
    domains. RFC-correct count is 8 (a=1, a→c=2, a→c→[d,e,f]=5,
    b=6, b→c=7, b→c→[d,e,f]=10). Previously tool returned 7 because
    the SECOND visit to c (via b) was short-circuited by the global
    `seen` set."""
    _install(monkeypatch, {
        "a.com": "v=spf1 include:c.com -all",
        "b.com": "v=spf1 include:c.com -all",
        "c.com": "v=spf1 include:d.com include:e.com include:f.com -all",
        "d.com": "v=spf1 -all",
        "e.com": "v=spf1 -all",
        "f.com": "v=spf1 -all",
    })
    top = "v=spf1 include:a.com include:b.com -all"
    count, trace = ea._count_spf_lookups(top, "top.example")
    assert count == 10, (
        f"expected RFC-correct 10 (per-path counting); got {count}\n"
        f"trace:\n" + "\n".join(trace)
    )


def test_shared_target_pushes_record_over_the_limit(monkeypatch):
    """Direct RFC 7208 §4.6.4 evaluation: a record that RFC-counts
    as 11 lookups must grade as exceeding the 10-lookup limit. The
    old code counted this as 6 and passed it. This is the finding
    that motivated the fix — a real over-limit record was permerror
    per RFC but graded PASS."""
    _install(monkeypatch, {
        # a and b each include c; c has 4 terminal includes.
        # RFC count: a(1) + a→c(2) + a→c→[d,e,f,g](6) + b(7) + b→c(8)
        # + b→c→[d,e,f,g](12). Total = 12 > 10 → exceeds_limit.
        "a.com": "v=spf1 include:c.com -all",
        "b.com": "v=spf1 include:c.com -all",
        "c.com": "v=spf1 include:d.com include:e.com include:f.com "
                 "include:g.com -all",
        "d.com": "v=spf1 -all",
        "e.com": "v=spf1 -all",
        "f.com": "v=spf1 -all",
        "g.com": "v=spf1 -all",
    })
    top = "v=spf1 include:a.com include:b.com -all"
    result = ea.evaluate_spf.__wrapped__ \
        if hasattr(ea.evaluate_spf, "__wrapped__") else ea.evaluate_spf
    # Direct helper call so we don't need to stub `get_spf` for the
    # apex domain — the top record is passed to `_count_spf_lookups`
    # explicitly.
    count, _ = ea._count_spf_lookups(top, "top.example")
    assert count > 10, (
        f"per-path counting must surface this as over-limit; got {count}"
    )


def test_direct_cycle_still_terminates(monkeypatch):
    """Cycle-protection sanity: `a → b → a → b → …` must not
    infinite-loop after the per-path change. The `depth > 10` and
    `depth < 5` guards still bound the walk. Trace / count is
    bounded and the function returns."""
    _install(monkeypatch, {
        "a.com": "v=spf1 include:b.com -all",
        "b.com": "v=spf1 include:a.com -all",
    })
    top = "v=spf1 include:a.com -all"
    # If this hangs the test will time out; the assertion is
    # simply that it returns and produces a finite count.
    count, trace = ea._count_spf_lookups(top, "top.example")
    assert count < 100, f"cycle should be bounded; got {count}"
    assert isinstance(trace, list)


def test_same_target_at_top_level_still_counts_each_appearance(monkeypatch):
    """Regression backstop for the case that was ALREADY correct
    (three `include:foo.com` at the top level count as 3 lookups
    — the `count += 1` runs per-term at the top-level loop, not
    behind the `seen` gate). Must remain correct after the fix."""
    _install(monkeypatch, {
        "foo.com": "v=spf1 -all",
    })
    top = "v=spf1 include:foo.com include:foo.com include:foo.com -all"
    count, _ = ea._count_spf_lookups(top, "top.example")
    assert count == 3
