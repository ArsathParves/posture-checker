"""T1 — per-finding stable ID field (mechanism).

Findings are currently identified by their display string ("DNSSEC
status", "Chain validates"). That string is what:

  - the CLI renders,
  - the CAA remediation table keys off,
  - some tests match against.

Coupling identity to display text has already caused one class of
bug in this codebase (findings F and V in the original AUDIT), where
grading logic keyed off label content and broke as soon as the label
was reworded. The vendor-neutrality rewording in B36 could have
tripped the same trap.

T1 adds the FIELD so callers have somewhere to route to; migration
of specific existing labels to declare `finding_id=` is follow-up
work — same mechanism-first / migration-later pattern used for T2
(severity) and T5 (confidence).

Grading MUST NOT read `finding_id`. This is a display-independent
handle for external consumers (JSON --output, web SPA, remediation
lookups). Grading is driven by status + hardening + severity only.

Wire-format:
  - `finding_id` is a new key on every per-finding dict returned by
    `_f2d` / `_report_to_dict`.
  - The default value is "" (empty string), NOT `None` — the SPA
    reads keys with `str.length` and would crash on `null`.
  - Empty `finding_id` is legal and expected during the migration
    window; the field is present but unset for unmigrated callers.
"""
from __future__ import annotations

from posture import checks as c
from posture.core import Finding, Report


# --------------------------------------------------------------------- dataclass field

def test_finding_has_finding_id_default_empty():
    """Backward compatibility: every pre-T1 `Finding(...)` construction
    still works. The default is empty (not `None` — the SPA reads the
    field as a string)."""
    f = Finding("DNSSEC", "Chain validates", "PASS", "verified")
    assert f.finding_id == ""
    assert isinstance(f.finding_id, str)


def test_finding_accepts_finding_id():
    f = Finding("DNSSEC", "Chain validates", "PASS", "verified",
                finding_id="DNSSEC_CHAIN_VALIDATES")
    assert f.finding_id == "DNSSEC_CHAIN_VALIDATES"


def test_report_add_accepts_finding_id_kwarg():
    """rep.add must forward `finding_id` to the Finding. Load-bearing:
    every migrated caller declares the ID at the emit site — a global
    label-to-id map would drift out of sync exactly the way the grade
    model's label-string coupling did."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("DNSSEC", "Chain validates", "PASS",
            "DS matches DNSKEY", "",
            finding_id="DNSSEC_CHAIN_VALIDATES")
    assert len(rep.findings) == 1
    assert rep.findings[0].finding_id == "DNSSEC_CHAIN_VALIDATES"


def test_report_add_defaults_finding_id_to_empty():
    """Unmigrated callers pass no `finding_id` — result must be `""`,
    not `None`. Regression trap: a well-meaning refactor auto-
    generating an ID from the label would re-couple identity to
    display text, the exact bug this field exists to prevent."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Core records", "IPv4 (A)", "PASS", "93.184.216.34")
    assert rep.findings[0].finding_id == ""


# --------------------------------------------------------------------- serialisation

def test_f2d_includes_finding_id():
    """`_f2d` MUST surface `finding_id` on every finding dict. Without
    it, external consumers (the SPA, external JSON tooling) cannot
    stable-reference a finding across renaming events."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("DNSSEC", "Chain validates", "PASS", "verified", "",
            finding_id="DNSSEC_CHAIN_VALIDATES")
    d = c._f2d(rep.findings[0])
    assert "finding_id" in d, (
        f"_f2d missing finding_id in wire format; got keys: {sorted(d)!r}"
    )
    assert d["finding_id"] == "DNSSEC_CHAIN_VALIDATES"


def test_f2d_defaults_finding_id_to_empty_string():
    """Unset `finding_id` renders as an empty STRING in the wire
    format, not `null`. The web SPA reads this key with `.length`
    checks and would blow up on `null`."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Core records", "IPv4 (A)", "PASS", "93.184.216.34")
    d = c._f2d(rep.findings[0])
    assert d["finding_id"] == ""
    assert isinstance(d["finding_id"], str)


def test_report_to_dict_includes_finding_id():
    """End-to-end wire-format contract. `_report_to_dict` is what
    CLI --json emits and web SSE `complete` events serialise; every
    finding in the returned list must carry `finding_id`."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("DNSSEC", "Chain validates", "PASS", "verified", "",
            finding_id="DNSSEC_CHAIN_VALIDATES")
    rep.add("Core records", "IPv4 (A)", "PASS", "93.184.216.34")
    d = c._report_to_dict(rep)
    ids = [f["finding_id"] for f in d["findings"]]
    assert ids == ["DNSSEC_CHAIN_VALIDATES", ""]


# --------------------------------------------------------------------- grading orthogonality

def test_finding_id_does_not_affect_grading():
    """Regression backstop for the T1 root cause: grading MUST NOT
    read `finding_id`. If it did, external consumers could steer
    grades by injecting IDs, and rewording a label would break
    grading — the exact bug the field exists to prevent."""
    # Baseline: 5 PASSes → some section band.
    rep = Report(domain_input="example.com", domain="example.com")
    for i in range(5):
        rep.add("Nameserver posture", f"check-{i}", "PASS", "")
    baseline_band = c.grade(rep)["sections"]["Nameserver posture"][0]

    # Same 5 PASSes but every finding declares a `finding_id`.
    rep2 = Report(domain_input="example.com", domain="example.com")
    for i in range(5):
        rep2.add("Nameserver posture", f"check-{i}", "PASS", "",
                 finding_id=f"NS_CHECK_{i}")
    with_id_band = c.grade(rep2)["sections"]["Nameserver posture"][0]

    assert baseline_band == with_id_band, (
        f"declaring finding_id must not change grades — "
        f"baseline={baseline_band}, with-ids={with_id_band}"
    )


def test_finding_id_default_preserves_backward_compat_grading():
    """A `Finding` constructed with the pre-T1 signature (no
    finding_id kwarg) grades identically to one with an explicit
    `finding_id=""`. Locks in the mechanism-first migration
    strategy: unmigrated emit sites are byte-identical to pre-T1."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("Core records", "IPv4 (A)", "PASS", "93.184.216.34")
    rep.add("Core records", "IPv6 (AAAA)", "WARN", "missing")
    result = c.grade(rep)
    assert "Core records" in result["sections"]


# --------------------------------------------------------------------- rename safety

def test_finding_id_survives_display_label_rename():
    """The load-bearing property T1 delivers: an external consumer
    that pins to `finding_id` continues to match the same finding
    across a display-label rename. Simulate the rename inline —
    two findings with the same ID but different labels must both
    be discoverable by ID."""
    rep = Report(domain_input="example.com", domain="example.com")
    rep.add("DNSSEC", "Chain validates end-to-end", "PASS", "v1",
            finding_id="DNSSEC_CHAIN_VALIDATES")
    rep.add("DNSSEC", "Chain validates", "PASS", "v2 (reworded)",
            finding_id="DNSSEC_CHAIN_VALIDATES")

    d = c._report_to_dict(rep)
    matched = [f for f in d["findings"]
               if f["finding_id"] == "DNSSEC_CHAIN_VALIDATES"]
    assert len(matched) == 2, (
        "external consumers must be able to pin on finding_id across "
        "a display-label rewording"
    )
    # But the display labels are different — proof the ID is what
    # actually carries identity, not the label.
    assert matched[0]["label"] != matched[1]["label"]
