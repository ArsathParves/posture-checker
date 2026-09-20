"""T1 — End-to-end orchestration tests for `posture.checks.run` and
`run_streaming` under a fake-DNS harness.

Prior coverage sliced individual pieces of the check engine (DNSSEC
state machine, SPF lookup counting, per-NS probing, anycast classifier
call site, grading fixtures, section-specific renderers) but the
orchestrator itself was untested:

  - `run()` end-to-end: the 7-section pipeline, its exception isolation,
    the NXDOMAIN short-circuit, the degraded-environment gate.
  - `run_streaming()` event sequence: the contract that `web/server.py`
    consumes to drive the SPA. A refactor that dropped an event type or
    reordered the stream would break the SPA silently — no unit test
    at the section level would notice.

The tests here never hit real DNS. Every function that touches the
network is patched at the `posture.checks` module boundary:

  - `check_environment` — controls the rule-5 self-test gate
  - `dnsmod.domain_exists` — controls the NXDOMAIN short-circuit
  - `dnsmod.get_ns_and_ips` / `parent_delegation` / `probe_each_ns` /
    `get_soa` / `query` / `dnssec_status` / `axfr_open_check` /
    `open_resolver_check` — the DNS section surface
  - `emailauth.evaluate_spf` / `evaluate_dkim` / `evaluate_dmarc` /
    `evaluate_dmarc_reporting` / `evaluate_mta_sts` — email-auth surface
  - `rdap_lookup` / `ip_rdap` — RDAP surface

The fake harness returns "no data / not present" shapes wherever
possible; sections tolerate this cleanly and emit WARN/INFO rows. What
the tests pin is the *orchestrator's* decision tree, not each section's
semantic — those are already pinned by their own test files.

Rule-1 pin: three states remain permanently distinct. Rule-5 pin: an
unsafe environment collapses per-NS reachability to UNKNOWN, never
FAIL. Rule-4: one bug, one test — the file is deliberately narrow.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from posture.checks import run, run_streaming, SECTIONS


# ---------------------------------------------------------------- fake DNS

_CLEAN_ENV = {
    "safe_for_per_ns_checks": True,
    "udp53_direct": True,
    "tcp53_direct": True,
    "intercepted": False,
    "aa_flag_trustworthy": True,
    "notes": [],
}

_DEGRADED_ENV = {
    "safe_for_per_ns_checks": False,
    "udp53_direct": True,
    "tcp53_direct": True,
    "intercepted": True,
    "aa_flag_trustworthy": True,
    "notes": ["UDP/53 interception detected (3/3 blackhole IPs answered)"],
}


def _fake_get_ns_and_ips(d):
    return {"ok": True, "ns": {
        "ns1.example.net": {"ipv4": ["192.0.2.1"], "ipv6": []},
        "ns2.example.net": {"ipv4": ["192.0.2.2"], "ipv6": []},
    }, "ttl": 3600}


def _fake_parent_delegation(d):
    return {"ok": True, "nameservers": ["ns1.example.net", "ns2.example.net"],
            "consensus": True, "queried_via": ["parent.tld"]}


def _fake_probe_each_ns(d, ns_map):
    return {host: {"reachable": True, "authoritative": True, "serial": 2026010101,
                   "rtt_ms": 15.0, "ip": ips.get("ipv4", [None])[0], "error": None}
            for host, ips in ns_map.items()}


def _fake_get_soa(d):
    return {"ok": True, "mname": "ns1.example.net", "rname": "admin.example.net",
            "serial": 2026010101, "refresh": 3600, "retry": 900,
            "expire": 1209600, "minimum": 300, "ttl": 3600}


def _fake_query_absent(d, rt, nameservers=None):
    """Default: NoAnswer semantics (ok=True, empty records)."""
    return {"ok": True, "records": [], "ttl": 3600}


def _fake_dnssec_not_configured(d):
    """The google.com posture: positive evidence of no DNSSEC."""
    return {
        "state": "not_configured",
        "ds": False, "dnskey": False,
        "self_signed": None, "ds_matches_dnskey": None,
        "ad_authenticated": None, "validated": None,
        "notes": [], "signatures": [], "algorithms": [],
    }


def _fake_axfr_closed(d, ns_map):
    return {"open": False, "results": {}}


def _fake_open_resolver_none(ns_map):
    return {"open_resolvers": [], "closed": len(ns_map),
            "checked": len(ns_map)}


def _fake_authoritative_vs_cached(d, ns_map):
    return {"checked": True, "agree": True, "disagreements": []}


def _fake_evaluate_spf(d):
    return {"present": False, "record": None}


def _fake_evaluate_dkim(d, selectors=None):
    return {"selectors": {}}


def _fake_evaluate_dmarc(d):
    return {"present": False}


def _fake_evaluate_dmarc_reporting(*a, **kw):
    return {"checked": []}


def _fake_evaluate_mta_sts(d):
    return {"present": False}


def _fake_rdap_no_tld(d):
    return {"ok": False, "error": "no_rdap_for_tld"}


def _fake_ip_rdap(ip):
    return {"ok": False}


@pytest.fixture()
def fake_dns(monkeypatch):
    """Patch every DNS/RDAP/emailauth entry point to a benign default.
    Individual tests override just what they care about."""
    import posture.checks as chk

    monkeypatch.setattr(chk, "check_environment", lambda: _CLEAN_ENV)
    monkeypatch.setattr(chk, "rdap_lookup", _fake_rdap_no_tld)
    monkeypatch.setattr(chk, "ip_rdap", _fake_ip_rdap)

    monkeypatch.setattr(chk.dnsmod, "domain_exists",
                        lambda d: {"exists": True, "via": "SOA"})
    monkeypatch.setattr(chk.dnsmod, "get_ns_and_ips", _fake_get_ns_and_ips)
    monkeypatch.setattr(chk.dnsmod, "parent_delegation", _fake_parent_delegation)
    monkeypatch.setattr(chk.dnsmod, "probe_each_ns", _fake_probe_each_ns)
    monkeypatch.setattr(chk.dnsmod, "get_soa", _fake_get_soa)
    monkeypatch.setattr(chk.dnsmod, "query", _fake_query_absent)
    monkeypatch.setattr(chk.dnsmod, "dnssec_status", _fake_dnssec_not_configured)
    monkeypatch.setattr(chk.dnsmod, "nsec_type",
                        lambda d: {"ok": True, "type": "none"})
    monkeypatch.setattr(chk.dnsmod, "cds_cdnskey_status",
                        lambda d: {"ok": True, "has_cds": False,
                                   "has_cdnskey": False,
                                   "delete_signal": False})
    monkeypatch.setattr(chk.dnsmod, "axfr_open_check", _fake_axfr_closed)
    monkeypatch.setattr(chk.dnsmod, "open_resolver_check", _fake_open_resolver_none)
    monkeypatch.setattr(chk.dnsmod, "authoritative_vs_cached",
                        _fake_authoritative_vs_cached)

    monkeypatch.setattr(chk.emailauth, "evaluate_spf", _fake_evaluate_spf)
    monkeypatch.setattr(chk.emailauth, "evaluate_dkim", _fake_evaluate_dkim)
    monkeypatch.setattr(chk.emailauth, "evaluate_dmarc", _fake_evaluate_dmarc)
    monkeypatch.setattr(chk.emailauth, "evaluate_dmarc_reporting",
                        _fake_evaluate_dmarc_reporting)
    monkeypatch.setattr(chk.emailauth, "evaluate_mta_sts", _fake_evaluate_mta_sts)
    return chk


# ---------------------------------------------------------------- NXDOMAIN

def test_run_nxdomain_short_circuits_pipeline(fake_dns):
    """The existence gate: if `domain_exists` returns False, the entire
    per-section pipeline must be skipped. Registration & delegation
    gets a single FAIL row. No section beyond Registration runs — the
    rest of the sections are meaningless on a non-existent domain and
    would just add noise (or worse, crash on empty NS data)."""
    with patch.object(fake_dns.dnsmod, "domain_exists",
                      return_value={"exists": False, "via": "SOA",
                                     "error": "NXDOMAIN"}):
        rep = run("nx-domain-that-does-not-exist.example")

    # One FAIL, in the registration section, naming the check.
    assert len(rep.findings) == 1, (
        f"NXDOMAIN must short-circuit — got {len(rep.findings)} findings, "
        f"expected 1: {[(f.section, f.label, f.status) for f in rep.findings]}"
    )
    f = rep.findings[0]
    assert f.section == "Registration & delegation"
    assert f.label == "Domain resolves"
    assert f.status == "FAIL"


def test_run_streaming_nxdomain_yields_terminating_sequence(fake_dns):
    """Event contract: on NXDOMAIN, the stream yields
    `started → environment → nxdomain → section → complete` and stops.
    No further `section` events for the 6 downstream sections.
    The SPA relies on `complete` as the signal to stop listening."""
    with patch.object(fake_dns.dnsmod, "domain_exists",
                      return_value={"exists": False, "via": "SOA",
                                     "error": "NXDOMAIN"}):
        events = list(run_streaming("nx-domain-that-does-not-exist.example"))

    event_types = [e["event"] for e in events]
    assert event_types[0] == "started"
    assert "environment" in event_types
    assert "nxdomain" in event_types
    # Exactly one section event: Registration & delegation. No SOA/DNSSEC/etc.
    section_events = [e for e in events if e["event"] == "section"]
    assert len(section_events) == 1
    assert section_events[0]["name"] == "Registration & delegation"
    # Terminates with complete.
    assert event_types[-1] == "complete"


# ---------------------------------------------------------------- streaming shape

def test_run_streaming_happy_path_emits_every_section(fake_dns):
    """The web SPA renders each section as its event lands. Every one
    of the seven CLAUDE.md-defined sections must produce a `section`
    event, in the order defined by `SECTIONS`."""
    events = list(run_streaming("example.com"))

    # Skeleton: started → environment → 7 sections → complete.
    types = [e["event"] for e in events]
    assert types[0] == "started"
    assert "environment" in types
    assert types[-1] == "complete"

    section_events = [e for e in events if e["event"] == "section"]
    section_names = [e["name"] for e in section_events]
    # Section names are the SECTIONS list minus "Input" (which is
    # rendered as pre-check normalisation, not a section event).
    expected_sections = [s for s in SECTIONS
                         if s not in ("Input",)]
    for s in expected_sections:
        assert s in section_names, (
            f"missing section event {s!r}; got sections={section_names!r}"
        )


def test_run_streaming_complete_event_carries_report_and_grades(fake_dns):
    """The `complete` event is the SPA's payload for rendering the
    final report — it MUST carry both `report` (per-section findings)
    and `grades` (correctness/hardening/overall). A shape regression
    that dropped `grades` would leave the SPA with no letter to show."""
    events = list(run_streaming("example.com"))
    complete = events[-1]
    assert complete["event"] == "complete"
    assert "report" in complete
    assert "grades" in complete
    # Grade payload has the three keys the UI reads.
    grades = complete["grades"]
    assert "overall" in grades
    assert "correctness_grade" in grades
    assert "hardening_grade" in grades
    # Report payload has the shape web+CLI both consume.
    report = complete["report"]
    for k in ("domain", "punycode", "checked_at", "findings"):
        assert k in report, f"report missing key {k!r}: {list(report)}"


def test_run_streaming_event_order_matches_cli_run(fake_dns):
    """`run()` (CLI) and `run_streaming()` (web) must be byte-for-byte
    identical on the underlying report. This is the CLAUDE.md module-
    map contract — the web layer is presentation and access control
    only, no divergent check logic. Compare the final findings sets."""
    rep = run("example.com")
    events = list(run_streaming("example.com"))
    complete = events[-1]

    stream_findings = complete["report"]["findings"]
    run_findings = [{"section": f.section, "label": f.label,
                     "status": f.status, "detail": f.detail, "why": f.why}
                    for f in rep.findings]

    assert stream_findings == run_findings, (
        "run() and run_streaming() must produce identical findings — "
        "the web layer is presentation only. Divergence here is the "
        "start of two-implementations-drift."
    )


# ---------------------------------------------------------------- section isolation

def test_section_exception_becomes_unknown_and_does_not_kill_run(fake_dns):
    """CLAUDE.md rule 1 boundary: a section that raises must not
    collapse into FAIL — the correct routing is UNKNOWN (data
    unretrievable) plus the section name in `rep.degraded`. And the
    subsequent sections MUST still run — one broken section cannot
    take down the whole check."""
    def _raising_soa(*_a, **_kw):
        raise RuntimeError("synthetic — get_soa exploded")

    with patch.object(fake_dns.dnsmod, "get_soa", _raising_soa):
        rep = run("example.com")

    # The broken section produced an UNKNOWN "Section error" row.
    unknown_rows = [f for f in rep.findings
                    if f.section == "SOA & zone hygiene"
                    and f.status == "UNKNOWN"
                    and "Section error" in f.label]
    assert unknown_rows, (
        f"section that raised must emit UNKNOWN Section error; got "
        f"{[(f.section, f.label, f.status) for f in rep.findings if f.section=='SOA & zone hygiene']!r}"
    )
    # And the section is in `degraded`.
    assert "SOA & zone hygiene" in rep.degraded, (
        f"a raising section must be added to rep.degraded; got {rep.degraded!r}"
    )
    # Downstream sections still ran (Core records, DNSSEC, Email auth,
    # Security posture). Pin a distinctive later section:
    downstream = [f for f in rep.findings if f.section == "DNSSEC"]
    assert downstream, (
        "SOA section raising must NOT kill DNSSEC — the orchestrator "
        "catches the exception and continues"
    )


def test_streaming_section_exception_still_emits_section_event(fake_dns):
    """Even when the underlying section function raised, the streaming
    generator MUST yield a `section` event so the SPA doesn't hang
    waiting for that section's frame. The event carries the UNKNOWN
    row; the SPA renders it as a soft-failure section."""
    def _raising_dnssec(*_a, **_kw):
        raise RuntimeError("synthetic dnssec_status failure")

    with patch.object(fake_dns.dnsmod, "dnssec_status", _raising_dnssec):
        events = list(run_streaming("example.com"))

    dnssec_events = [e for e in events
                     if e["event"] == "section" and e["name"] == "DNSSEC"]
    assert len(dnssec_events) == 1, (
        f"raising section must still yield exactly one section event; "
        f"got {len(dnssec_events)}"
    )
    unknown = [f for f in dnssec_events[0]["findings"]
               if f["status"] == "UNKNOWN"]
    assert unknown, "section-exception must surface an UNKNOWN row to the SPA"


# ---------------------------------------------------------------- rule-5 gate

def test_degraded_environment_suppresses_per_ns_probing(fake_dns):
    """CLAUDE.md rule 5: when `check_environment` reports the wire
    path is untrustworthy, per-NS reachability MUST report UNKNOWN,
    NEVER produce a confident finding. This is the load-bearing
    invariant that keeps the tool honest on corporate networks with
    transparent DNS proxies."""
    with patch.object(fake_dns, "check_environment", return_value=_DEGRADED_ENV):
        rep = run("example.com")

    # rep.degraded includes per-NS probing.
    assert any("per-nameserver" in d.lower() for d in rep.degraded), (
        f"unsafe env must add per-NS probing to rep.degraded; "
        f"got {rep.degraded!r}"
    )
    # And the Nameserver reachability finding is UNKNOWN, NOT FAIL —
    # rule-1 boundary: unretrievable never collapses into broken.
    reachability = [f for f in rep.findings
                    if f.section == "Nameserver posture"
                    and "reachability" in f.label.lower()]
    assert reachability, "unsafe env must still emit a reachability row"
    assert reachability[0].status == "UNKNOWN", (
        f"unsafe env must route reachability to UNKNOWN, not FAIL; "
        f"got status={reachability[0].status!r}"
    )


def test_degraded_environment_surfaces_in_streaming_event(fake_dns):
    """The `environment` streaming event carries `safe=False` + notes
    so the SPA can render the env banner (W5). A regression that
    dropped the notes would leave the user with UNKNOWN findings and
    no explanation of why."""
    with patch.object(fake_dns, "check_environment", return_value=_DEGRADED_ENV):
        events = list(run_streaming("example.com"))

    env_events = [e for e in events if e["event"] == "environment"]
    assert len(env_events) == 1
    assert env_events[0]["safe"] is False
    assert env_events[0]["notes"], (
        "degraded env must carry notes so the SPA can render the reason"
    )


# ---------------------------------------------------------------- input handling

def test_run_streaming_input_error_yields_error_event_only(fake_dns):
    """`normalize_domain` raising ValueError (unparseable input) must
    produce a terminal `error` event, NOT crash the generator. The
    web layer catches `error` events and renders them as validation
    failures — a raising generator would 500 the endpoint instead."""
    events = list(run_streaming("!!!not-a-domain!!!"))
    types = [e["event"] for e in events]
    # First (and possibly only) event is the error.
    assert "error" in types
    err = next(e for e in events if e["event"] == "error")
    assert err["type"] == "input"
    # No section events on invalid input — nothing to check.
    assert not any(e["event"] == "section" for e in events)


def test_report_has_expected_shape(fake_dns):
    """The Report dataclass's public contract: `.findings`, `.domain`,
    `.punycode`, `.checked_at`, `.degraded`, `.data`. These are read
    by the CLI renderer and the streaming _report_to_dict serialiser
    — a rename here would break rendering."""
    rep = run("example.com")
    for attr in ("findings", "domain", "punycode", "checked_at", "degraded",
                 "data"):
        assert hasattr(rep, attr), (
            f"Report missing attribute {attr!r} — public contract broken"
        )
    assert isinstance(rep.findings, list)
    assert isinstance(rep.degraded, list)
    assert isinstance(rep.data, dict)
