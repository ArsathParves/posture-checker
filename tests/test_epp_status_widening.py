"""B3 — widen EPP status parsing beyond `transferProhibited`.

`posture/checks.py::_registration` today only inspects RDAP's status
array for the transfer-lock signal. RFC 5731 §2.3 defines a much
wider status set, and three subsets are directly product-visible
for a BFSI domain audit:

  * **hold states** (`clientHold`, `serverHold`) — the registry has
    pulled the domain out of the DNS delegation. The domain will
    not resolve for anyone. This is not "misconfigured", it's
    "actively down at the registry level" — the highest-severity
    registration signal there is.

  * **redemption / pending-delete** (`redemptionPeriod`,
    `pendingDelete`) — the domain has been deleted and is inside
    the grace window before it becomes available for anyone to
    register. A BFSI customer whose domain is in redemption has
    30-ish days to renew before losing the name entirely.

  * **pendingTransfer** — someone has initiated a transfer of the
    domain to a different registrar. Could be legitimate (planned
    move) or a hijack in progress — either way it warrants a
    signal.

Prior to this fix all four cases surfaced as "PASS Transfer lock"
if the transfer-lock flag happened to be set, and were otherwise
invisible. The ROOT CAUSE PRINCIPLE anchor on line 263 of
`checks.py` (DO2) names EPP as the source of truth and flags the
"transfer-prohibited only" reading as a shortcut.

Rule 1 must still hold: absence of status data → the check is
skipped, not FAILed. The RDAP call already handles the
"unretrievable" state upstream (registration section raises
`Unretrievable` and `run()`'s dispatch layer records that as a
section-level UNKNOWN). This test file drives the check with
pre-canned RDAP payloads and asserts on the emitted findings.
"""
from __future__ import annotations

import posture.checks as checks
from posture.core import Report


def _fake_lookup(status: list[str]):
    """Emulate a successful `core.rdap_lookup` return + the shape
    `core.parse_rdap` produces once decoded."""
    return {
        "ok": True,
        "endpoint": "https://rdap.example/",
        "suffix": "com",
        "data": {"__status__": status},  # consumed by fake parser below
    }


def _fake_parse(payload):
    return {
        "registrar": "Example Registrar Inc.",
        "events": {"registration": "2010-01-01T00:00:00Z",
                   "expiration": "2035-01-01T00:00:00Z"},
        "status": payload["__status__"],
        "redacted": False,
    }


def _run_registration(status: list[str], monkeypatch):
    """Invoke `_registration` with `core.rdap_lookup` + `parse_rdap`
    patched to return a fixed status set; return the Report."""
    rep = Report(domain_input="example.com", domain="example.com",
                 punycode="example.com")
    monkeypatch.setattr(checks, "rdap_lookup", lambda d: _fake_lookup(status))
    monkeypatch.setattr(checks, "parse_rdap", _fake_parse)
    checks._registration(rep, "example.com")
    return rep


def _labels(rep, section="Registration & delegation"):
    return {f.label: f for f in rep.findings if f.section == section}


# --------------------------------------------------------------------- hold states

def test_client_hold_is_flagged_as_registry_hold_fail(monkeypatch):
    """A domain in clientHold has been pulled out of the DNS by the
    registrar — it won't resolve. This is a strictly stronger signal
    than "no transfer lock"; it MUST surface as its own finding at
    FAIL, not be hidden inside the transfer-lock summary."""
    rep = _run_registration(["clientHold"], monkeypatch)
    findings = _labels(rep)
    assert "Registry hold" in findings, (
        f"clientHold must surface as 'Registry hold' finding; "
        f"got labels {list(findings)}"
    )
    f = findings["Registry hold"]
    assert f.status == "FAIL"
    assert "clientHold" in f.detail or "clienthold" in f.detail.lower()


def test_server_hold_is_flagged_as_registry_hold_fail(monkeypatch):
    """serverHold is set by the registry itself (vs. clientHold set
    by the registrar). Same product-visible effect — domain is
    non-resolving — same FAIL treatment."""
    rep = _run_registration(["serverHold"], monkeypatch)
    findings = _labels(rep)
    assert "Registry hold" in findings
    assert findings["Registry hold"].status == "FAIL"


# --------------------------------------------------------------------- redemption / pending delete

def test_redemption_period_surfaces_as_registry_lifecycle_fail(monkeypatch):
    """redemptionPeriod means the domain has been deleted and is
    inside the grace window. Losing the domain is a total-outage
    event; surface it at FAIL with a specific label that says
    'about to be lost', not just 'no transfer lock'."""
    rep = _run_registration(["redemptionPeriod"], monkeypatch)
    findings = _labels(rep)
    assert "Registry lifecycle" in findings, (
        f"redemptionPeriod must surface as 'Registry lifecycle' "
        f"finding; got labels {list(findings)}"
    )
    assert findings["Registry lifecycle"].status == "FAIL"
    assert "redemption" in findings["Registry lifecycle"].detail.lower()


def test_pending_delete_surfaces_as_registry_lifecycle_fail(monkeypatch):
    """pendingDelete = grace window has expired, the registry is
    about to drop the domain. Same treatment as redemptionPeriod."""
    rep = _run_registration(["pendingDelete"], monkeypatch)
    findings = _labels(rep)
    assert "Registry lifecycle" in findings
    assert findings["Registry lifecycle"].status == "FAIL"
    assert "pendingdelete" in findings["Registry lifecycle"].detail.lower()


# --------------------------------------------------------------------- pending transfer

def test_pending_transfer_surfaces_as_warn(monkeypatch):
    """pendingTransfer may be legitimate (planned registrar move) or
    a hijack in progress — the tool cannot know which. Surface it as
    WARN with a clear detail so a Solutions Engineer / customer can
    verify it was authorised."""
    rep = _run_registration(["pendingTransfer"], monkeypatch)
    findings = _labels(rep)
    assert "Registry transfer state" in findings, (
        f"pendingTransfer must surface its own WARN finding; "
        f"got labels {list(findings)}"
    )
    assert findings["Registry transfer state"].status == "WARN"


# --------------------------------------------------------------------- non-regression

def test_transfer_lock_finding_is_unchanged_when_only_ok_status_present(monkeypatch):
    """Sanity: a domain with a plain `ok` status shouldn't sprout
    new FAIL findings from B3. Only the pre-existing 'Transfer lock'
    (WARN — no lock set) should appear from this widening."""
    rep = _run_registration(["ok"], monkeypatch)
    findings = _labels(rep)
    for absent in ("Registry hold", "Registry lifecycle",
                   "Registry transfer state"):
        assert absent not in findings, (
            f"{absent!r} must not appear when status={['ok']!r}; "
            f"got {list(findings)}"
        )
    assert findings["Transfer lock"].status == "WARN"


def test_transfer_lock_finding_pass_when_client_transfer_prohibited_present(monkeypatch):
    """The pre-existing transfer-lock detection must continue to
    work when B3 widens the parser. `clientTransferProhibited` in
    the status list still yields Transfer lock = PASS."""
    rep = _run_registration(["clientTransferProhibited"], monkeypatch)
    findings = _labels(rep)
    assert findings["Transfer lock"].status == "PASS"


def test_multiple_statuses_each_surface_their_own_finding(monkeypatch):
    """A real registry response may carry several statuses at once
    (e.g. `clientTransferProhibited` + `clientHold`). Each must
    surface its own finding — hold state MUST NOT be masked by the
    presence of a transfer lock."""
    rep = _run_registration(
        ["clientTransferProhibited", "clientHold"], monkeypatch
    )
    findings = _labels(rep)
    assert findings["Transfer lock"].status == "PASS"
    assert findings["Registry hold"].status == "FAIL", (
        "clientHold must not be masked by transfer-lock PASS"
    )
