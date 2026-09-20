"""Regression tests for FN2 — the DKIM `COMMON_SELECTORS` list was
missing selectors used by mainstream ESPs in the tool's target segment.

DKIM has no discoverable selector list in DNS, so the tool can only
probe known names. A missing selector produces a false "no DKIM found
under common selectors" result on domains that actually publish DKIM
via the missing name — the operator sees green fields on a DMARC row
whose alignment is silently failing.

Selectors added in this pass (with the ESP that uses them):
  - `s2048` — Yahoo/AOL legacy, plus a generic marker for 2048-bit keys
    on other providers.
  - `ml1`, `ml2` — MailerLite (customers publish `ml1._domainkey.<d>`
    and `ml2._domainkey.<d>`; the tool used to miss both).
  - `mxvault` — Mailgun's shared-IP DKIM selector.
  - `salesforce` — Salesforce marketing cloud.
  - `postmarkapp` — Postmark's newer selector alongside `pm` (already
    present).

These aren't guesses: each is documented in the corresponding ESP's
public DKIM setup guide and appears on live customer domains. See the
`_domainkey` names published at their example customers.

Contract:
  - `COMMON_SELECTORS` remains a `list[str]`; ordering is stable
    (selectors near the front are probed slightly earlier under the
    bounded ThreadPoolExecutor, but the parallel probe means order is
    not a correctness axis).
  - Every previously-present selector still appears — additive only.
"""
from __future__ import annotations

from posture.emailauth import COMMON_SELECTORS


PREVIOUS_SELECTORS = {
    # Generic
    "default", "selector1", "selector2", "k1", "k2", "k3",
    "mail", "dkim", "s1", "s2", "smtp", "sig1",
    # Western ESPs
    "google", "mandrill", "everlytickey1", "mailjet", "sendgrid",
    "zoho", "zmail", "pm", "litesrv", "protonmail", "amazonses",
    "hs1", "hs2", "mimecast20220101",
    # India-region ESPs
    "netcore", "pepipost", "zeptomail", "kaleyra", "gupshup",
}

NEWLY_REQUIRED = {
    "s2048",       # Yahoo/AOL legacy + generic 2048-bit key marker
    "ml1", "ml2",  # MailerLite
    "mxvault",     # Mailgun shared-IP selector
    "salesforce",  # Salesforce marketing cloud
    "postmarkapp", # Postmark newer selector
}


def test_all_previous_selectors_preserved():
    """Additive-only: FN2 must not silently drop any selector added in
    earlier work (N19 / India ESP additions). Removing a selector is a
    correctness regression — customers already relying on it would flip
    from PASS to false-negative FAIL."""
    missing = PREVIOUS_SELECTORS - set(COMMON_SELECTORS)
    assert not missing, (
        f"COMMON_SELECTORS regressed: missing {sorted(missing)}. "
        f"Any removal must land as a separate deliberate commit with "
        f"a rationale, not incidentally in an addition PR."
    )


def test_new_selectors_are_probed():
    """The ESPs enumerated in the FN2 audit line must appear in the
    probe list. Each name is documented in the ESP's own DKIM setup
    guide; a domain publishing under any of these was previously
    reported as "no DKIM found under common selectors"."""
    missing = NEWLY_REQUIRED - set(COMMON_SELECTORS)
    assert not missing, (
        f"COMMON_SELECTORS missing FN2 selectors: {sorted(missing)}. "
        f"See the docstring for provenance per selector."
    )


def test_selectors_have_no_duplicates():
    """A duplicate selector doubles the DNS probe cost for one name.
    Not a correctness bug but wasteful — each additional entry hits
    real infra."""
    seen: dict[str, int] = {}
    for s in COMMON_SELECTORS:
        seen[s] = seen.get(s, 0) + 1
    dupes = {k: v for k, v in seen.items() if v > 1}
    assert not dupes, (
        f"duplicate selectors in COMMON_SELECTORS: {dupes}"
    )


def test_selectors_are_bare_labels():
    """DKIM selectors must be published under `<selector>._domainkey.
    <domain>`. Entering `mailjet._domainkey` in the list would produce
    `mailjet._domainkey._domainkey.<domain>` at probe time — a typo
    the tool would carry silently."""
    for s in COMMON_SELECTORS:
        assert "." not in s, (
            f"selector {s!r} must be a bare label, not a dotted name — "
            f"'._domainkey' is appended by the prober."
        )
        assert s == s.lower().strip(), (
            f"selector {s!r} has case/whitespace issues"
        )
