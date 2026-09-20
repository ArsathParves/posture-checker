"""T4 — Golden-file pin for the wire-format shape.

Every Finding leaves the check engine through two chokepoints:

    posture.checks._f2d(f)          → per-finding dict
    posture.checks._report_to_dict  → whole-report dict

Both are consumed by CLI (`--json`) and the web SSE `complete` event.
The SPA at `web/static/app.js` reads specific keys off each finding
(section, label, status, detail, why, confidence) — a silent key
rename or field drop would break the browser with no red run.

Prior coverage exercised the fields individually (T5 confidence,
selftest six-key contract, run/run_streaming byte-parity), but
nothing pinned the FULL wire shape as one document. This is the
trip-wire: if a future refactor adds/removes/renames a top-level
key or a per-finding key without also updating the golden fixture,
the test fails loudly. That is by design — schema changes must be
explicit, never accidental.

Why hand-built vs. captured from a live run:
  - `checked_at` is a time.time() snapshot — not deterministic
  - RDAP/DNS network state changes — unpinable
  - The point is to pin the SHAPE, not any particular domain

The synthetic report exercises every state (PASS/WARN/FAIL/INFO/
UNKNOWN), both severity tiers ("" and "CRITICAL"), both hardening
booleans, and all four confidence tiers ("" / low / medium / high).
"""
from __future__ import annotations

from posture import checks as c
from posture.core import Report


# --------------------------------------------------------------------- expected shape

# Every top-level key `_report_to_dict` emits. Regressed if renamed,
# dropped, or added-without-updating-this-list.
EXPECTED_REPORT_KEYS = {
    "domain_input", "domain", "punycode", "checked_at",
    "degraded", "findings",
}

# Every per-finding key `_f2d` emits. Same regression contract.
# NB: `hardening` and `severity` are DELIBERATELY absent from the
# wire — they are grading-internal signals, not display fields.
# Adding them here would leak grading model into the SPA and force
# a coupled UI change.
# T1: `finding_id` is a display-independent handle for external
# consumers. Empty string for unmigrated emit sites (backwards-
# compatible during the migration window).
EXPECTED_FINDING_KEYS = {
    "section", "label", "status", "detail", "why", "confidence",
    "finding_id",
}


# --------------------------------------------------------------------- fixture

def _synthetic_report() -> Report:
    """Deterministic report exercising every wire-format branch."""
    rep = Report(domain_input="Example.COM",
                 domain="example.com",
                 punycode="example.com")
    # Also stamp checked_at to a fixed value so the golden is byte-
    # comparable. Callers normalise this to 0 before comparing.
    rep.checked_at = 1_700_000_000.0
    rep.degraded = ["fake_section"]

    # One finding per state × a few severity/hardening/confidence
    # combinations. Covers the axes that drive UI rendering.
    rep.add("Registration & delegation", "RDAP endpoint", "PASS",
            "found via IANA bootstrap")
    rep.add("Nameserver posture", "Delegation", "PASS",
            "4 NS match parent", confidence="high")
    rep.add("Nameserver posture", "Cross-resolver consensus", "PASS",
            "3/3 resolvers agree", confidence="medium")
    rep.add("SOA & health", "SOA readable", "PASS", "serial=2024010101")
    rep.add("Core records", "IPv6 (AAAA)", "WARN",
            "no AAAA present", hardening=True)
    rep.add("DNSSEC", "Chain validates", "PASS",
            "DS→DNSKEY→root chain OK", hardening=True,
            confidence="high")
    # One migrated emit site to exercise the T1 wire-format field.
    rep.add("DNSSEC", "Chain broken", "FAIL",
            "DS present but DNSKEY absent",
            finding_id="DNSSEC_CHAIN_BROKEN")
    rep.add("Email authentication", "MTA-STS policy", "WARN",
            "policy fetch timed out; TXT present",
            confidence="low")
    rep.add("Security posture", "Full-zone AXFR", "FAIL",
            "master leaked entire zone",
            severity="CRITICAL")
    rep.add("Security posture", "Environment gate", "INFO",
            "wire path trusted")
    rep.add("Security posture", "Cert expiry", "UNKNOWN",
            "TLS handshake failed", confidence="")
    return rep


# --------------------------------------------------------------------- top-level shape

def test_report_dict_has_exactly_expected_top_level_keys():
    """Top-level wire-format keys are the schema. A silent addition
    would ship a field the SPA does not read and cannot label; a
    silent removal would break the SPA on the next SSE frame."""
    rep = _synthetic_report()
    d = c._report_to_dict(rep)
    assert set(d.keys()) == EXPECTED_REPORT_KEYS, (
        f"top-level wire keys drifted: added={set(d) - EXPECTED_REPORT_KEYS}, "
        f"dropped={EXPECTED_REPORT_KEYS - set(d)}"
    )


def test_finding_dict_has_exactly_expected_keys_for_every_finding():
    """Per-finding shape must be byte-identical across every finding
    the tool emits. A finding that carries a NEW key (e.g., a debug
    field a check leaked into `_f2d`) is a wire-contract violation
    even if benign — the SPA does not tolerate unknown keys silently."""
    rep = _synthetic_report()
    d = c._report_to_dict(rep)
    for i, f in enumerate(d["findings"]):
        assert set(f.keys()) == EXPECTED_FINDING_KEYS, (
            f"finding[{i}] (section={f.get('section')!r}, "
            f"label={f.get('label')!r}) wire keys drifted: "
            f"added={set(f) - EXPECTED_FINDING_KEYS}, "
            f"dropped={EXPECTED_FINDING_KEYS - set(f)}"
        )


# --------------------------------------------------------------------- full golden

def test_report_dict_matches_golden():
    """The whole-report byte-for-byte golden. Any wire-format change
    — a new field, a rename, a reordering of `findings` — flips this
    test red. Update the GOLDEN literal deliberately (and update any
    consumer of the wire format at the same time) rather than
    hand-waving the diff away.

    `checked_at` is normalised to a fixed sentinel so the golden
    stays stable across runs."""
    rep = _synthetic_report()
    got = c._report_to_dict(rep)

    # Freeze the timestamp for comparison. The field EXISTS in the
    # wire — dropping it would break the CLI header — but its value
    # is not a schema invariant.
    got["checked_at"] = 0

    golden = {
        "domain_input": "Example.COM",
        "domain": "example.com",
        "punycode": "example.com",
        "checked_at": 0,
        "degraded": ["fake_section"],
        "findings": [
            {"section": "Registration & delegation",
             "label": "RDAP endpoint",
             "status": "PASS",
             "detail": "found via IANA bootstrap",
             "why": "",
             "confidence": "",
             "finding_id": ""},
            {"section": "Nameserver posture",
             "label": "Delegation",
             "status": "PASS",
             "detail": "4 NS match parent",
             "why": "",
             "confidence": "high",
             "finding_id": ""},
            {"section": "Nameserver posture",
             "label": "Cross-resolver consensus",
             "status": "PASS",
             "detail": "3/3 resolvers agree",
             "why": "",
             "confidence": "medium",
             "finding_id": ""},
            {"section": "SOA & health",
             "label": "SOA readable",
             "status": "PASS",
             "detail": "serial=2024010101",
             "why": "",
             "confidence": "",
             "finding_id": ""},
            {"section": "Core records",
             "label": "IPv6 (AAAA)",
             "status": "WARN",
             "detail": "no AAAA present",
             "why": "",
             "confidence": "",
             "finding_id": ""},
            {"section": "DNSSEC",
             "label": "Chain validates",
             "status": "PASS",
             "detail": "DS→DNSKEY→root chain OK",
             "why": "",
             "confidence": "high",
             "finding_id": ""},
            {"section": "DNSSEC",
             "label": "Chain broken",
             "status": "FAIL",
             "detail": "DS present but DNSKEY absent",
             "why": "",
             "confidence": "",
             "finding_id": "DNSSEC_CHAIN_BROKEN"},
            {"section": "Email authentication",
             "label": "MTA-STS policy",
             "status": "WARN",
             "detail": "policy fetch timed out; TXT present",
             "why": "",
             "confidence": "low",
             "finding_id": ""},
            {"section": "Security posture",
             "label": "Full-zone AXFR",
             "status": "FAIL",
             "detail": "master leaked entire zone",
             "why": "",
             "confidence": "",
             "finding_id": ""},
            {"section": "Security posture",
             "label": "Environment gate",
             "status": "INFO",
             "detail": "wire path trusted",
             "why": "",
             "confidence": "",
             "finding_id": ""},
            {"section": "Security posture",
             "label": "Cert expiry",
             "status": "UNKNOWN",
             "detail": "TLS handshake failed",
             "why": "",
             "confidence": "",
             "finding_id": ""},
        ],
    }
    assert got == golden, (
        "Wire-format golden drift. Update the golden literal in "
        "tests/test_report_golden_shape.py AND update every consumer "
        "of the wire format (web/static/app.js, CLI --json readers)."
    )


# --------------------------------------------------------------------- section order

def test_findings_preserve_insertion_order():
    """The wire format is a list, not a set — order is load-bearing.
    The SPA renders sections in the order they arrive; a reshuffle
    would change the visible section ordering silently."""
    rep = _synthetic_report()
    d = c._report_to_dict(rep)
    sections_in_order = [f["section"] for f in d["findings"]]
    expected_first = "Registration & delegation"
    expected_last = "Security posture"
    assert sections_in_order[0] == expected_first
    assert sections_in_order[-1] == expected_last


# --------------------------------------------------------------------- values are strings

def test_all_wire_fields_are_strings_except_lists_and_scalars():
    """Every wire-format value the SPA writes into the DOM must be
    a string (interpolated via `escapeHtml` / `safeStatus`). A
    non-string leaking through would either crash `.length` reads
    or render `[object Object]` in the UI."""
    rep = _synthetic_report()
    d = c._report_to_dict(rep)
    for f in d["findings"]:
        for key in ("section", "label", "status", "detail", "why",
                    "confidence", "finding_id"):
            assert isinstance(f[key], str), (
                f"finding[{f.get('label')!r}][{key!r}] = "
                f"{f[key]!r} (type={type(f[key]).__name__}) — "
                "wire-format values must be strings"
            )
