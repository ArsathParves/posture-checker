"""B14 — DMARC `sp` (subdomain policy) and `adkim` / `aspf`
(alignment modes) parsed but never evaluated.

Prior to this fix, `evaluate_dmarc` captured `sp`, `adkim`, and
`aspf` into the return dict then the emit block used only `p=` to
grade. A domain with `p=reject; sp=none` (strict apex policy, wide-
open subdomain policy — a real and common misconfiguration where an
attacker registers `sub.victim.com` and spoofs mail from that origin
because the subdomain policy is `none`) graded IDENTICALLY to
`p=reject; sp=reject`.

RFC 7489 §6.3: when `sp` is unset, subdomains inherit the apex `p`.
When `sp` is set, it applies to subdomains INSTEAD of `p`. A weaker
`sp` than `p` is thus a real, exploitable gap.

Alignment modes (`adkim` / `aspf`, RFC 7489 §3.1): `r` (relaxed,
default) allows subdomain matches on the DKIM/SPF identifier;
`s` (strict) requires exact match. Strict is a hardening choice, not
a correctness requirement — surface it as INFO/hardening so a SE
can see what's configured without pushing every relaxed-default
domain toward a WARN.
"""
from __future__ import annotations

from posture import checks as c
from posture.core import Report


def _run_email_with_dmarc(monkeypatch, dmarc_out: dict) -> Report:
    """Drive `_email` through the DMARC branch with a synthetic
    result. Neutralises SPF/DKIM/MTA-STS so their findings do not
    clutter the assertions."""
    monkeypatch.setattr(c.emailauth, "evaluate_dmarc",
                        lambda d: dmarc_out)
    monkeypatch.setattr(c.emailauth, "evaluate_spf",
                        lambda d: {"present": False})
    monkeypatch.setattr(c.emailauth, "evaluate_dkim",
                        lambda d, selectors: {"found": False, "probed": 0,
                                              "selectors": []})
    monkeypatch.setattr(c.emailauth, "evaluate_mta_sts",
                        lambda d: {"mta_sts": False, "tls_rpt": False})
    monkeypatch.setattr(c.emailauth, "evaluate_dmarc_reporting",
                        lambda d, rua=None, ruf=None: {"destinations": []})

    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["records"] = {
        "MX": {"records": [(10, "mail.example.com")]},
        "A": {"records": ["203.0.113.1"]},
        "AAAA": {"records": []},
    }
    c._email(rep, "example.com", None)
    return rep


def _dmarc(policy="reject", sp=None, adkim="r", aspf="r"):
    """Convenience DMARC dict builder — the evaluate_dmarc contract."""
    return {
        "present": True,
        "record": f"v=DMARC1; p={policy}",
        "policy": policy,
        "strength": {"reject": "strong", "quarantine": "moderate",
                     "none": "weak"}.get(policy, "unknown"),
        "subdomain_policy": sp,
        "pct": "100",
        "rua": None, "ruf": None,
        "alignment_dkim": adkim,
        "alignment_spf": aspf,
        "multiple": False,
        "all_records": None,
    }


def _dmarc_findings(rep, label_contains):
    return [f for f in rep.findings
            if f.section == "Email authentication"
            and label_contains in f.label]


# --------------------------------------------------------------------- sp

def test_sp_none_with_p_reject_is_fail(monkeypatch):
    """The load-bearing case: `p=reject; sp=none` leaves subdomains
    wide-open even though the apex is strict. Attackers can spoof
    from `anything.victim.com` and receivers apply no DMARC decision
    on the subdomain. Must FAIL — a real and common misconfiguration."""
    rep = _run_email_with_dmarc(monkeypatch,
                                _dmarc(policy="reject", sp="none"))
    sp_findings = _dmarc_findings(rep, "DMARC subdomain policy")
    assert sp_findings, (
        "sp=none with p=reject must emit a DMARC subdomain policy "
        f"finding; got findings: "
        f"{[(f.label, f.status) for f in rep.findings]}"
    )
    f = sp_findings[0]
    assert f.status == "FAIL", (
        f"sp=none / p=reject must FAIL (subdomains wide-open); got "
        f"{f.status}"
    )
    assert "sp=none" in f.detail or "none" in f.detail.lower()


def test_sp_quarantine_with_p_reject_is_warn(monkeypatch):
    """One step weaker than the apex (`p=reject; sp=quarantine`) —
    subdomains only quarantine when the apex rejects. This is a real
    gap but less severe than sp=none. WARN, not FAIL."""
    rep = _run_email_with_dmarc(monkeypatch,
                                _dmarc(policy="reject", sp="quarantine"))
    sp_findings = _dmarc_findings(rep, "DMARC subdomain policy")
    assert sp_findings
    assert sp_findings[0].status == "WARN"


def test_sp_matches_p_produces_pass(monkeypatch):
    """`p=reject; sp=reject` — subdomain policy at least as strong
    as apex. PASS."""
    rep = _run_email_with_dmarc(monkeypatch,
                                _dmarc(policy="reject", sp="reject"))
    sp_findings = _dmarc_findings(rep, "DMARC subdomain policy")
    assert sp_findings
    assert sp_findings[0].status == "PASS"


def test_sp_absent_inherits_p_no_separate_finding(monkeypatch):
    """RFC 7489 §6.3: when sp is unset, subdomains inherit p. There
    is no real subdomain-policy gap — do NOT emit a WARN for the
    common case of "no sp tag" (that would pester every properly-
    configured domain)."""
    rep = _run_email_with_dmarc(monkeypatch,
                                _dmarc(policy="reject", sp=None))
    sp_findings = _dmarc_findings(rep, "DMARC subdomain policy")
    # Either no finding at all, or an INFO/PASS explicitly noting
    # inheritance — never WARN or FAIL.
    for f in sp_findings:
        assert f.status in ("PASS", "INFO"), (
            f"sp absent must not WARN/FAIL (RFC 7489 §6.3 inheritance); "
            f"got {f.status}: {f.detail}"
        )


def test_sp_stronger_than_p_is_pass(monkeypatch):
    """Unusual but valid: `p=none; sp=reject` (monitor the apex,
    protect subdomains). Not a bug — must not FAIL."""
    rep = _run_email_with_dmarc(monkeypatch,
                                _dmarc(policy="none", sp="reject"))
    sp_findings = _dmarc_findings(rep, "DMARC subdomain policy")
    if sp_findings:
        assert sp_findings[0].status in ("PASS", "INFO")


# --------------------------------------------------------------------- alignment

def test_strict_alignment_dkim_surfaces_as_hardening(monkeypatch):
    """`adkim=s` is a genuine hardening choice — surface it so a SE
    can see it, with `hardening=True` so it feeds the hardening bucket
    without pretending relaxed is broken."""
    rep = _run_email_with_dmarc(monkeypatch,
                                _dmarc(adkim="s"))
    findings = _dmarc_findings(rep, "DMARC alignment (DKIM)")
    assert findings, (
        f"adkim=s must surface a DMARC alignment (DKIM) finding; got "
        f"{[(f.label, f.status) for f in rep.findings]}"
    )
    f = findings[0]
    assert f.status == "PASS"
    assert f.hardening is True
    assert "strict" in f.detail.lower() or "s" == f.detail.strip()


def test_strict_alignment_spf_surfaces_as_hardening(monkeypatch):
    """Same treatment for aspf=s."""
    rep = _run_email_with_dmarc(monkeypatch,
                                _dmarc(aspf="s"))
    findings = _dmarc_findings(rep, "DMARC alignment (SPF)")
    assert findings
    f = findings[0]
    assert f.status == "PASS"
    assert f.hardening is True


def test_relaxed_default_does_not_emit_negative_finding(monkeypatch):
    """`adkim=r` and `aspf=r` are the RFC defaults (§6.3) — must not
    generate WARN/FAIL. Relaxed alignment is a valid, common choice."""
    rep = _run_email_with_dmarc(monkeypatch,
                                _dmarc(adkim="r", aspf="r"))
    for label in ("DMARC alignment (DKIM)", "DMARC alignment (SPF)"):
        matched = _dmarc_findings(rep, label)
        for f in matched:
            assert f.status not in ("WARN", "FAIL"), (
                f"relaxed default must not negative-grade; got {f.status} "
                f"for {label}: {f.detail}"
            )


# --------------------------------------------------------------------- rule 1

def test_dmarc_absent_produces_no_sp_or_alignment_findings(monkeypatch):
    """Rule 1: if DMARC is absent, none of the sub-DMARC findings
    (sp, alignment) can apply — reporting FAIL for sp=none when
    there's no DMARC at all would be nonsensical."""
    monkeypatch.setattr(c.emailauth, "evaluate_dmarc",
                        lambda d: {"present": False})
    monkeypatch.setattr(c.emailauth, "evaluate_spf",
                        lambda d: {"present": False})
    monkeypatch.setattr(c.emailauth, "evaluate_dkim",
                        lambda d, selectors: {"found": False, "probed": 0,
                                              "selectors": []})
    monkeypatch.setattr(c.emailauth, "evaluate_mta_sts",
                        lambda d: {"mta_sts": False, "tls_rpt": False})
    monkeypatch.setattr(c.emailauth, "evaluate_dmarc_reporting",
                        lambda d, rua=None, ruf=None: {"destinations": []})

    rep = Report(domain_input="example.com", domain="example.com")
    rep.data["records"] = {
        "MX": {"records": [(10, "mail.example.com")]},
        "A": {"records": ["203.0.113.1"]},
        "AAAA": {"records": []},
    }
    c._email(rep, "example.com", None)

    for label in ("DMARC subdomain policy",
                  "DMARC alignment (DKIM)",
                  "DMARC alignment (SPF)"):
        matched = _dmarc_findings(rep, label)
        assert not matched, (
            f"{label!r} must not appear when DMARC is absent; got "
            f"{[(f.label, f.status) for f in matched]}"
        )
