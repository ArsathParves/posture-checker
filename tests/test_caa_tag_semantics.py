"""B16 — parse CAA tags rather than treating records as opaque strings.

RFC 8659 defines three critical tags plus a growing property set:

  * `issue`      — CAs permitted to issue certificates for the domain
                   (non-wildcard). Special value `;` = no CA may issue.
  * `issuewild`  — CAs permitted to issue wildcard certificates.
                   Absent → falls back to `issue` per §4.3. Special
                   value `;` = no wildcard issuance permitted.
  * `iodef`      — mailto/URL where CAs report policy violations.
                   Reporting endpoint = closes the loop when a CA
                   receives a request that CAA forbids.

Prior to this fix `_records` emitted a single `CAA record PASS`
line with the raw record strings joined. That surfaces CAA
adoption but tells nothing about *what the policy actually says* —
a Solutions Engineer reviewing a report cannot distinguish:

  * `0 issue "letsencrypt.org"` (LE only)                vs
  * `0 issue ";"` (no CA at all, hard lockdown)          vs
  * `0 issue "letsencrypt.org"` + `0 iodef "mailto:..."`   (LE with reporting)

All three grade the same today. B16 splits them into distinct
findings with actionable detail.

Rule 1 preserved: parsing runs only on records that WERE retrieved.
Malformed / unparseable CAA lines are surfaced separately as WARN
(the CA-view is what matters — but a malformed line is still worth
naming so ops can fix it).
"""
from __future__ import annotations

import posture.checks as checks
from posture.core import Report


def _fake_query(records_by_qtype):
    def _q(name, qtype, **kwargs):
        got = records_by_qtype.get(qtype, {})
        return {"ok": True, "records": got.get("records", []),
                "ttl": got.get("ttl", 300)}
    return _q


def _run_records(caa_records, monkeypatch):
    rep = Report(domain_input="example.com", domain="example.com",
                 punycode="example.com")
    monkeypatch.setattr(checks.dnsmod, "query",
                        _fake_query({
                            "A": {"records": ["1.1.1.1"]},
                            "AAAA": {"records": []},
                            "MX": {"records": []},
                            "CAA": {"records": caa_records},
                            "CNAME": {"records": []},
                        }))
    checks._records(rep, "example.com")
    return rep


def _labels(rep):
    return {f.label: f for f in rep.findings if f.section == "Core records"}


# --------------------------------------------------------------------- allowed CAs

def test_issue_tag_surfaces_permitted_ca_list(monkeypatch):
    """A domain with `0 issue "letsencrypt.org"` and
    `0 issue "digicert.com"` must produce a finding whose detail
    lists both CAs — a Solutions Engineer needs to see the CAs
    without re-parsing the wire format themselves."""
    rep = _run_records(
        ['0 issue "letsencrypt.org"', '0 issue "digicert.com"'],
        monkeypatch,
    )
    findings = _labels(rep)
    assert "CAA issuers (non-wildcard)" in findings, (
        f"issue tags must surface as their own finding; "
        f"got {list(findings)}"
    )
    detail = findings["CAA issuers (non-wildcard)"].detail
    assert "letsencrypt.org" in detail
    assert "digicert.com" in detail


def test_issuewild_tag_is_a_separate_finding(monkeypatch):
    """RFC 8659 §4.3: `issuewild` overrides `issue` for wildcards.
    A domain that allows LE for non-wildcards but ONLY DigiCert
    for wildcards needs two distinct findings so the split is
    visible."""
    rep = _run_records(
        ['0 issue "letsencrypt.org"', '0 issuewild "digicert.com"'],
        monkeypatch,
    )
    findings = _labels(rep)
    assert "CAA issuers (wildcard)" in findings
    assert "digicert.com" in findings["CAA issuers (wildcard)"].detail
    assert findings["CAA issuers (wildcard)"].status == "PASS"


# --------------------------------------------------------------------- no-CA lockdown

def test_no_ca_lockdown_is_flagged_as_pass_with_specific_detail(monkeypatch):
    """`0 issue ";"` is the RFC 8659 §4.3 "no CA may issue" form.
    This is a deliberate hard lockdown — must be surfaced as its
    own PASS finding with unambiguous detail so ops don't mistake
    it for "empty issue tag = broken"."""
    rep = _run_records(['0 issue ";"'], monkeypatch)
    findings = _labels(rep)
    assert "CAA no-issue lockdown" in findings, (
        f"the RFC 8659 no-CA form must surface distinctly; "
        f"got {list(findings)}"
    )
    assert findings["CAA no-issue lockdown"].status == "PASS"


# --------------------------------------------------------------------- iodef reporting

def test_iodef_endpoint_is_flagged_as_hardening_pass(monkeypatch):
    """An iodef endpoint closes the CAA loop — CAs report
    forbidden-issuance attempts to it. This is a hardening signal
    (not required for correctness) and must surface as its own
    PASS hardening=True finding so it feeds the hardening bucket."""
    rep = _run_records(
        ['0 issue "letsencrypt.org"',
         '0 iodef "mailto:security@example.com"'],
        monkeypatch,
    )
    findings = _labels(rep)
    assert "CAA iodef reporting" in findings
    f = findings["CAA iodef reporting"]
    assert f.status == "PASS"
    assert f.hardening is True
    assert "mailto:security@example.com" in f.detail


def test_iodef_absent_is_hardening_warn(monkeypatch):
    """CAA without iodef is functional but missing the reporting
    signal. WARN + hardening=True — grades into the hardening
    bucket only, does not drag correctness."""
    rep = _run_records(['0 issue "letsencrypt.org"'], monkeypatch)
    findings = _labels(rep)
    f = findings["CAA iodef reporting"]
    assert f.status == "WARN"
    assert f.hardening is True


# --------------------------------------------------------------------- malformed

def test_malformed_caa_line_surfaces_as_warn(monkeypatch):
    """A CAA record that doesn't parse as `<flags> <tag> "<value>"`
    is worth naming so a zone admin can fix it — but MUST NOT drag
    the "CAA present" PASS finding down (rule 1: the presence of a
    malformed record is not proof of no CAA)."""
    rep = _run_records(
        ['0 issue "letsencrypt.org"', 'this-is-not-a-caa-record'],
        monkeypatch,
    )
    findings = _labels(rep)
    assert "CAA malformed record" in findings
    assert findings["CAA malformed record"].status == "WARN"
    # The valid one still surfaces as its own finding.
    assert "CAA issuers (non-wildcard)" in findings


# --------------------------------------------------------------------- rule 1 preservation

def test_no_caa_still_emits_original_warn(monkeypatch):
    """B16 must not regress the existing empty-CAA behaviour. When
    no CAA records exist and no parent CAA is inherited, the
    original `CAA record WARN` must still fire (via the existing
    parent-walk path)."""
    rep = _run_records([], monkeypatch)
    findings = _labels(rep)
    assert findings["CAA record"].status == "WARN"


def test_new_findings_do_not_appear_when_no_caa(monkeypatch):
    """None of the new B16 findings should exist when CAA is
    absent — otherwise a domain without CAA would fail on missing
    iodef, which is nonsensical (you can't have iodef without CAA)."""
    rep = _run_records([], monkeypatch)
    findings = _labels(rep)
    for absent in ("CAA issuers (non-wildcard)", "CAA issuers (wildcard)",
                   "CAA no-issue lockdown", "CAA iodef reporting",
                   "CAA malformed record"):
        assert absent not in findings, (
            f"{absent!r} must not appear when CAA is absent; "
            f"got {list(findings)}"
        )
