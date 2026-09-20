"""B23 — parent-side glue-record validation.

When a nameserver is *in-bailiwick* (its name is under or equal to the
delegated zone — e.g. `ns1.example.com` for `example.com`), the parent
zone MUST supply A/AAAA "glue" for it in the delegation. Without glue,
a resolver that reaches the parent NS learns `example.com NS
ns1.example.com` but has no way to reach `ns1.example.com` — resolving
its address requires knowing where `example.com`'s zone lives, which is
precisely what the delegation is supposed to tell you (RFC 1034 §4.2.1
+ RFC 1035 §5.1). Missing glue is a real fragility that manifests as
intermittent SERVFAILs on cold caches.

Before this fix, `_query_parent_ns_view` collected only NS records from
the `authority` section and ignored the `additional` section entirely.
The tool had no signal on glue at all.

Out-of-bailiwick NSes (`ns1.dns-provider.net` serving `example.com`)
require NO glue — the resolver looks up the NS's own address through
the normal delegation graph. Emitting a "missing glue" finding for
them would be a false FAIL. Rule 1: not-applicable must never collapse
into broken.

Fix (dnsmod):
  - `_query_parent_ns_view` also extracts A/AAAA from the additional
    section, returning a `glue: {ns_name: [ip, ...]}` map alongside
    the NS list.
  - `parent_delegation` surfaces the aggregated `glue` on the result
    dict so downstream can reason without another parent query.

Fix (checks): `_delegation` emits a new `Glue records` finding.
  - In-bailiwick NS with glue → PASS
  - In-bailiwick NS missing glue → FAIL naming the specific NS
  - No in-bailiwick NS (all out-of-bailiwick) → skip (not applicable)
  - Parent query failed → skip (delegation branch already emits UNKNOWN)
"""
from __future__ import annotations

from posture import dnsmod


# --------------------------------------------------------------------- unit: in-bailiwick classifier

def test_in_bailiwick_classifier_matches_apex():
    """`example.com` is trivially in-bailiwick with itself as an NS
    name (unusual but legal)."""
    assert dnsmod._is_in_bailiwick("example.com", "example.com") is True


def test_in_bailiwick_classifier_matches_subdomain():
    """`ns1.example.com` is under `example.com` — the canonical
    in-bailiwick case."""
    assert dnsmod._is_in_bailiwick("ns1.example.com", "example.com") is True
    assert dnsmod._is_in_bailiwick(
        "a.b.c.example.com", "example.com") is True


def test_in_bailiwick_classifier_rejects_sibling():
    """`ns1.example.net` is NOT under `example.com` — out-of-bailiwick.
    No glue needed. The classifier must not be fooled by suffix
    similarity."""
    assert dnsmod._is_in_bailiwick(
        "ns1.example.net", "example.com") is False


def test_in_bailiwick_classifier_rejects_prefix_overlap():
    """`fooexample.com` shares a suffix substring with `example.com`
    but is a different zone. Must not be classified as in-bailiwick —
    a naive `.endswith("example.com")` would false-positive here."""
    assert dnsmod._is_in_bailiwick(
        "fooexample.com", "example.com") is False


def test_in_bailiwick_classifier_case_insensitive():
    """DNS is case-insensitive per RFC 1035 §2.3.3 — classifier must
    not depend on case."""
    assert dnsmod._is_in_bailiwick(
        "NS1.EXAMPLE.COM", "example.com") is True
    assert dnsmod._is_in_bailiwick(
        "ns1.example.com", "EXAMPLE.COM") is True


# --------------------------------------------------------------------- unit: parent-view helper extracts glue

def test_parent_view_returns_glue_from_additional(monkeypatch):
    """`_query_parent_ns_view` must return glue A/AAAA from the parent
    response's additional section. Without this, no downstream code
    can validate glue."""
    import dns.message
    import dns.rrset
    import dns.rdatatype

    resp = dns.message.QueryMessage()
    # authority section — parent hands back the NS delegation
    resp.authority.append(dns.rrset.from_text_list(
        "example.com.", 3600, "IN", "NS",
        ["ns1.example.com.", "ns2.example.com.", "ns1.example.net."],
    ))
    # additional section — glue A/AAAA for in-bailiwick NSes
    resp.additional.append(dns.rrset.from_text_list(
        "ns1.example.com.", 3600, "IN", "A", ["203.0.113.1"],
    ))
    resp.additional.append(dns.rrset.from_text_list(
        "ns2.example.com.", 3600, "IN", "AAAA", ["2001:db8::2"],
    ))
    # `ns1.example.net.` is out-of-bailiwick — no glue expected in
    # additional; the parent has no authority over that zone

    monkeypatch.setattr(dnsmod.dns.query, "udp", lambda *a, **kw: resp)

    host, ns, glue = dnsmod._query_parent_ns_view(
        "example.com", "parent-ns.example", "192.0.2.1")

    assert host == "parent-ns.example"
    assert set(ns) == {"ns1.example.com", "ns2.example.com",
                       "ns1.example.net"}
    assert glue == {
        "ns1.example.com": ["203.0.113.1"],
        "ns2.example.com": ["2001:db8::2"],
    }


def test_parent_view_empty_additional_returns_empty_glue(monkeypatch):
    """A parent that lists NS but ships no glue (all out-of-bailiwick,
    or a broken parent) yields an empty glue map. Not an error —
    downstream decides whether missing glue is a problem based on
    in-bailiwick classification."""
    import dns.message
    import dns.rrset

    resp = dns.message.QueryMessage()
    resp.authority.append(dns.rrset.from_text_list(
        "example.com.", 3600, "IN", "NS",
        ["ns1.example.net.", "ns2.example.net."],
    ))
    # no additional section

    monkeypatch.setattr(dnsmod.dns.query, "udp", lambda *a, **kw: resp)

    _, ns, glue = dnsmod._query_parent_ns_view(
        "example.com", "parent", "192.0.2.1")
    assert set(ns) == {"ns1.example.net", "ns2.example.net"}
    assert glue == {}


# --------------------------------------------------------------------- integration: checks emits Glue records finding

def _fake_query_factory(table):
    """Build a `dnsmod.query` stand-in from a `{(name, qtype): result}`
    table. Missing entries return an "ok:False no_answer" shape so the
    caller can distinguish absent from lookup-failed."""
    def _fake(name, qtype, **kw):
        key = (name.lower().rstrip("."), qtype.upper())
        return table.get(key, {"ok": False, "records": [],
                               "error": "no_answer"})
    return _fake


def _run_delegation(monkeypatch, parent_result, ns_records=None):
    """Drive `_nameservers` with a stubbed `parent_delegation` and a
    minimal NS map so the block that emits `Glue records` executes.
    Returns the Report so tests can pick out findings."""
    from posture import checks as c
    from posture.core import Report

    # NS map defaults to the parent's declared NSes so served == deleg
    # and delegation-mismatch findings don't clutter the test surface.
    if ns_records is None:
        ns_records = parent_result.get("nameservers", [])

    ns_map = {n: {"ipv4": ["192.0.2.99"], "ipv6": []} for n in ns_records}

    monkeypatch.setattr(c.dnsmod, "get_ns_and_ips",
                        lambda d: {"ok": True, "ns": ns_map})
    monkeypatch.setattr(c.dnsmod, "parent_delegation",
                        lambda d: parent_result)
    # Neutralise RDAP + AS lookup so the section stays focused on glue.
    monkeypatch.setattr(c.dnsmod, "probe_each_ns", lambda d, ns_map: {})

    rep = Report(domain_input="example.com", domain="example.com")
    # environment gate: force safe=False so per-NS probes are skipped,
    # keeping the finding surface focused on the delegation block.
    rep.data["environment"] = {"safe_for_per_ns_checks": False,
                               "notes": ["test harness"]}
    c._nameservers(rep, "example.com", skip_asn=True)
    return rep


def _findings(rep, label):
    return [f for f in rep.findings if f.label == label]


def test_all_inbailiwick_ns_have_glue_passes(monkeypatch):
    """Load-bearing PASS case: parent lists `ns1.example.com` and
    `ns2.example.com` and ships glue for both. Must emit
    `Glue records` PASS."""
    parent = {
        "ok": True,
        "nameservers": ["ns1.example.com", "ns2.example.com"],
        "queried_via": ["a.gtld-servers.net"],
        "consensus": True,
        "glue": {"ns1.example.com": ["203.0.113.1"],
                 "ns2.example.com": ["203.0.113.2"]},
    }
    rep = _run_delegation(monkeypatch, parent)
    findings = _findings(rep, "Glue records")
    assert findings, (
        f"expected a `Glue records` finding; got labels: "
        f"{[f.label for f in rep.findings]}"
    )
    assert findings[0].status == "PASS", findings[0].detail


def test_missing_glue_for_inbailiwick_ns_fails(monkeypatch):
    """The load-bearing FAIL case: parent lists `ns1.example.com` as an
    NS but ships NO glue for it. A resolver walking to the parent
    learns of an in-bailiwick NS with no way to reach it. Must FAIL
    naming the specific offending NS."""
    parent = {
        "ok": True,
        "nameservers": ["ns1.example.com", "ns2.example.com"],
        "queried_via": ["a.gtld-servers.net"],
        "consensus": True,
        "glue": {"ns2.example.com": ["203.0.113.2"]},
        # ns1.example.com has no glue
    }
    rep = _run_delegation(monkeypatch, parent)
    findings = _findings(rep, "Glue records")
    assert findings
    f = findings[0]
    assert f.status == "FAIL", f.detail
    assert "ns1.example.com" in f.detail, (
        f"FAIL detail must name the offending NS; got: {f.detail}"
    )
    # Non-missing NS should not appear in the detail (avoid false
    # accusations)
    assert "ns2.example.com" not in f.detail


def test_out_of_bailiwick_ns_needs_no_glue(monkeypatch):
    """Rule 1: not-applicable. All NSes are out-of-bailiwick
    (`ns1.dns-provider.net` serving `example.com`). No glue expected;
    NO `Glue records` finding should be emitted (or, if emitted at
    all, it must be INFO/PASS — never FAIL)."""
    parent = {
        "ok": True,
        "nameservers": ["ns1.dns-provider.net", "ns2.dns-provider.net"],
        "queried_via": ["a.gtld-servers.net"],
        "consensus": True,
        "glue": {},  # no glue — correct, none expected
    }
    rep = _run_delegation(monkeypatch, parent)
    findings = _findings(rep, "Glue records")
    # Either no finding at all, or a positive one. FAIL would be a
    # rule-1 violation.
    for f in findings:
        assert f.status in ("PASS", "INFO"), (
            f"out-of-bailiwick NSes must not FAIL on missing glue "
            f"(none is required); got {f.status}: {f.detail}"
        )


def test_mixed_bailiwick_only_flags_inbailiwick_missing_glue(monkeypatch):
    """Realistic case: two in-bailiwick NSes (need glue) plus one
    out-of-bailiwick (does not). Parent ships glue for one of the
    two in-bailiwick. Finding must FAIL naming ONLY the in-bailiwick
    NS missing glue — not the out-of-bailiwick one."""
    parent = {
        "ok": True,
        "nameservers": ["ns1.example.com", "ns2.example.com",
                        "ns.external.net"],
        "queried_via": ["a.gtld-servers.net"],
        "consensus": True,
        "glue": {"ns1.example.com": ["203.0.113.1"]},
    }
    rep = _run_delegation(monkeypatch, parent)
    findings = _findings(rep, "Glue records")
    assert findings
    f = findings[0]
    assert f.status == "FAIL"
    assert "ns2.example.com" in f.detail
    assert "ns.external.net" not in f.detail, (
        "out-of-bailiwick NS must not appear in a missing-glue detail — "
        "glue is not required for it"
    )


def test_parent_query_failed_produces_no_glue_finding(monkeypatch):
    """When the parent query itself failed, the delegation block
    already emits an UNKNOWN. Emitting an additional glue UNKNOWN
    would double-count the same unretrievable condition. Silence is
    correct."""
    parent = {"ok": False, "error": "parent_query_failed"}
    rep = _run_delegation(monkeypatch, parent,
                          ns_records=["ns1.example.com",
                                      "ns2.example.com"])
    findings = _findings(rep, "Glue records")
    assert not findings, (
        "glue finding must not appear when parent query failed — the "
        "delegation block already emits UNKNOWN for that condition. "
        f"got: {[(f.label, f.status, f.detail) for f in findings]}"
    )
