"""B30 (final part) — CAA-vs-served-issuer alignment.

RFC 8659 §3: A CA MUST NOT issue a certificate unless a CAA `issue`
(or `issuewild`) tag names the CA. That's a rule imposed on the CA,
not a client-side check — but a scan-time alignment check can catch
three real classes of problem:

  1. A CA violated policy at issuance time (rare, but has happened).
  2. The CAA policy was tightened AFTER a still-valid cert was
     issued (common; the cert is fine but the audit trail matters).
  3. The served cert is from a stale infrastructure element (an old
     load balancer, a cached edge cert) that predates the current
     CAA policy.

The check emits a hardening finding with confidence=low. Confidence
is low because the mapping between CAA identifier (`letsencrypt.org`)
and cert issuer text ("Let's Encrypt", "R3", "E1", ...) is fuzzy —
CAs rebrand (Comodo → Sectigo) and issue under sub-CAs whose names
don't literally contain the CAA identifier. A false positive is
worse than a missed detection here, so the check is deliberately
lenient and the confidence tier admits it.

Rule 1 boundaries:
  - No CAA policy → not applicable, no finding
  - TLS probe failed → UNKNOWN, not FAIL
  - CAA present but no `issue` tags (only `iodef`) → not applicable
  - `issue ";"` lockdown but cert served → CRITICAL (policy says
    NO CA may issue, but one did — this is either a policy typo or
    a real policy violation, either way worth escalating)
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from posture import checks as c
from posture import tlsprobe
from posture.core import Report


# --------------------------------------------------------------------- fixtures

def _rep_with_caa(caa_records=None, tls_result=None, safe=True):
    """Build a Report with CAA records + a stubbed TLS probe result.
    `caa_records` list — wire-form CAA lines (`'0 issue "letsencrypt.org"'`).
    `tls_result` dict — the shape `tlsprobe.probe_tls` returns.
    """
    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["environment"] = {"safe_for_direct_dns": safe}
    rep.data["records"] = {
        "CAA": {"ok": True, "records": caa_records or []},
    }
    if tls_result is not None:
        rep.data["tls_probe"] = tls_result
    return rep


def _run_alignment_only(rep, monkeypatch, tls_ok=True, hsts_ok=True):
    """Patch tls/hsts probes to return canned data + run _tls_posture."""
    tls_result = rep.data.get("tls_probe") or {"ok": False, "error": "no probe"}
    monkeypatch.setattr(tlsprobe, "probe_tls", lambda d: tls_result)
    monkeypatch.setattr(tlsprobe, "probe_hsts",
                        lambda d: {"ok": True, "present": True,
                                   "max_age": 31536000,
                                   "include_subdomains": False,
                                   "preload": False})
    c._tls_posture(rep, "example.com")


def _alignment_finding(rep):
    return next((f for f in rep.findings
                 if f.label == "CAA / cert issuer alignment"), None)


# --------------------------------------------------------------------- happy path

def test_alignment_pass_when_caa_names_the_cert_issuer(monkeypatch):
    """CAA says `letsencrypt.org`; cert issuer says 'Let's Encrypt'.
    Clean alignment — PASS, confidence=high."""
    rep = _rep_with_caa(
        caa_records=['0 issue "letsencrypt.org"'],
        tls_result={"ok": True, "protocol": "TLSv1.3",
                    "cert": {"issuer_cn": "R3",
                             "issuer_org": "Let's Encrypt",
                             "not_after": "2030-01-01T00:00:00Z"}},
    )
    _run_alignment_only(rep, monkeypatch)
    f = _alignment_finding(rep)
    assert f is not None
    assert f.status == "PASS"
    assert f.confidence == "high"


def test_alignment_pass_via_sub_ca_cn(monkeypatch):
    """Let's Encrypt intermediate CN is often just 'R10' / 'E1' — a
    strict substring match on the CN alone would miss. Alignment
    must look at both `issuer_cn` and `issuer_org`."""
    rep = _rep_with_caa(
        caa_records=['0 issue "letsencrypt.org"'],
        tls_result={"ok": True, "protocol": "TLSv1.3",
                    "cert": {"issuer_cn": "E1",
                             "issuer_org": "Let's Encrypt",
                             "not_after": "2030-01-01T00:00:00Z"}},
    )
    _run_alignment_only(rep, monkeypatch)
    f = _alignment_finding(rep)
    assert f.status == "PASS"


def test_alignment_pass_via_alias_comodo_to_sectigo(monkeypatch):
    """Comodo rebranded to Sectigo in 2018. Certs issued after the
    rebrand carry 'Sectigo' in their issuer text even when CAA still
    names 'comodoca.com'. The alias table must translate."""
    rep = _rep_with_caa(
        caa_records=['0 issue "comodoca.com"'],
        tls_result={"ok": True, "protocol": "TLSv1.3",
                    "cert": {"issuer_cn": "Sectigo RSA Domain "
                                          "Validation Secure Server CA",
                             "issuer_org": "Sectigo Limited",
                             "not_after": "2030-01-01T00:00:00Z"}},
    )
    _run_alignment_only(rep, monkeypatch)
    f = _alignment_finding(rep)
    assert f.status == "PASS", (
        "comodoca.com → Sectigo alias must be recognised"
    )


# --------------------------------------------------------------------- misalignment

def test_alignment_warn_when_cert_issuer_not_in_caa_policy(monkeypatch):
    """CAA restricts to letsencrypt.org; cert issued by DigiCert.
    Policy violation OR stale cert OR CAA typo — WARN with
    confidence=low (mapping is fuzzy)."""
    rep = _rep_with_caa(
        caa_records=['0 issue "letsencrypt.org"'],
        tls_result={"ok": True, "protocol": "TLSv1.3",
                    "cert": {"issuer_cn": "DigiCert Global G2",
                             "issuer_org": "DigiCert Inc",
                             "not_after": "2030-01-01T00:00:00Z"}},
    )
    _run_alignment_only(rep, monkeypatch)
    f = _alignment_finding(rep)
    assert f.status == "WARN"
    assert f.confidence == "low", (
        "CAA/issuer mapping is fuzzy; confidence tier must admit it"
    )


def test_alignment_critical_when_no_issue_lockdown_but_cert_served(monkeypatch):
    """CAA `issue ";"` says NO CA may issue. If a cert is being
    served, either the policy was violated at issuance or the cert
    predates the lockdown. Escalation-worthy — CRITICAL."""
    rep = _rep_with_caa(
        caa_records=['0 issue ";"'],
        tls_result={"ok": True, "protocol": "TLSv1.3",
                    "cert": {"issuer_cn": "R3",
                             "issuer_org": "Let's Encrypt",
                             "not_after": "2030-01-01T00:00:00Z"}},
    )
    _run_alignment_only(rep, monkeypatch)
    f = _alignment_finding(rep)
    assert f is not None
    assert f.status == "FAIL"
    assert f.severity == "CRITICAL"


# --------------------------------------------------------------------- rule 1 boundaries

def test_no_alignment_finding_when_caa_absent(monkeypatch):
    """No CAA policy → the whole check is not-applicable. Rule 1:
    emitting anything would collapse 'no policy' into a finding."""
    rep = _rep_with_caa(
        caa_records=[],
        tls_result={"ok": True, "protocol": "TLSv1.3",
                    "cert": {"issuer_cn": "R3", "issuer_org": "Let's Encrypt",
                             "not_after": "2030-01-01T00:00:00Z"}},
    )
    _run_alignment_only(rep, monkeypatch)
    assert _alignment_finding(rep) is None


def test_no_alignment_finding_when_caa_only_has_iodef(monkeypatch):
    """iodef alone is a reporting tag, not an issuance restriction.
    Nothing to align against — skip."""
    rep = _rep_with_caa(
        caa_records=['0 iodef "mailto:security@example.com"'],
        tls_result={"ok": True, "protocol": "TLSv1.3",
                    "cert": {"issuer_cn": "R3", "issuer_org": "Let's Encrypt",
                             "not_after": "2030-01-01T00:00:00Z"}},
    )
    _run_alignment_only(rep, monkeypatch)
    assert _alignment_finding(rep) is None


def test_alignment_unknown_when_tls_probe_failed(monkeypatch):
    """No cert to compare against → UNKNOWN, not WARN. Rule 1:
    unretrievable stays unretrievable."""
    rep = _rep_with_caa(
        caa_records=['0 issue "letsencrypt.org"'],
        tls_result={"ok": False, "error": "timeout"},
    )
    _run_alignment_only(rep, monkeypatch)
    f = _alignment_finding(rep)
    assert f is not None
    assert f.status == "UNKNOWN"


def test_no_alignment_finding_when_env_unsafe():
    """Rule 5: the whole `_tls_posture` section is gated on
    `safe_for_direct_dns`. An untrusted path emits one UNKNOWN row
    and returns — no CAA alignment attempt."""
    rep = _rep_with_caa(
        caa_records=['0 issue "letsencrypt.org"'],
        tls_result={"ok": True, "cert": {}},
        safe=False,
    )
    c._tls_posture(rep, "example.com")
    assert _alignment_finding(rep) is None
