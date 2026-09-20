"""T6 — Right-to-left label walk in `core.rdap_endpoint_for`.

CLAUDE.md ground-truth call-out:

    `.in` and `.co.in` resolve RDAP via NIXI using right-to-left label
    walking — there is no separate `co.in` bootstrap entry. Do not
    regress this.

The audit item asks for tests of the label walk. The bootstrap cache
tests (`test_rdap_bootstrap_cache.py`) pin the caching contract but
NOT the walk — a refactor that broke the walk order (left-to-right,
or first-match-anywhere) would leave every India-region domain
`example.co.in` → `example.bank.in` → `example.gov.in` failing RDAP
without any existing test catching it. The audit is very clear that
this is a high-stakes case for the tool's Indian-BFSI target segment.

Contract pinned:
  - Walks right-to-left starting from the TLD (SHORTEST suffix first).
    IANA's DNS-RDAP bootstrap (RFC 7484 §3) is TLD-keyed — every valid
    entry is a single label. Shortest-first stops on the first single
    match, which is always the delegated TLD.
  - `example.co.in` → matches `in` immediately (co.in is not in
    IANA's bootstrap). This is the CLAUDE.md guardrail.
  - Multi-label domains like `a.b.c.in` still match `in` at the TLD.
  - Case is normalised to lowercase in the mapping (per bootstrap
    loader); the walk must be lowercase.
  - A domain whose eTLD is not in bootstrap returns `(None, None)` —
    used by the CLI/web renderer to emit UNKNOWN, not FAIL.

Note on longest-match: RDAP-IP bootstrap (RFC 7484 §5) IS longest-
match on CIDR — but that's a different code path (`_ip_bootstrap`)
handled by `ip_rdap`. This test file is DNS-RDAP only.

Fixture: patch `_load_bootstrap` to return a fixed mapping so the
tests don't hit IANA. That keeps them pure and marker-free (offline).
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from posture.core import rdap_endpoint_for


# --------------------------------------------------------------------- fixture

# Bootstrap mapping matching what IANA actually publishes today for the
# suffixes we care about. All keys are single labels — that mirrors RFC
# 7484 §3, which specifies DNS-RDAP bootstrap on TLDs only.
_STUB_MAPPING = {
    "com": "https://rdap.verisign.com/com/v1/",
    "in": "https://rdap.registry.in/",   # NIXI serves .in AND .co.in via this
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.net/rdap/",
}


@pytest.fixture(autouse=True)
def stub_bootstrap():
    with patch("posture.core._load_bootstrap", return_value=_STUB_MAPPING):
        yield


# --------------------------------------------------------------------- walk correctness

def test_single_label_tld_com_resolves_at_tld_only():
    """example.com must NOT match `example.com` in bootstrap (there is
    no per-domain entry). The walk falls through to `com`."""
    ep, suffix = rdap_endpoint_for("example.com")
    assert suffix == "com"
    assert ep == _STUB_MAPPING["com"]


def test_co_in_domain_resolves_via_in_entry():
    """The CLAUDE.md call-out: `co.in` is NOT in IANA's bootstrap
    (checked live — DNS-RDAP is TLD-keyed only). `example.co.in`
    must resolve via the `.in` entry. Guards against a walk-order
    bug that would fail to match anything and return (None, None)
    for every co.in domain."""
    ep, suffix = rdap_endpoint_for("example.co.in")
    assert suffix == "in", (
        f"example.co.in must resolve via the .in entry (NIXI serves both); "
        f"got suffix={suffix!r}. Right-to-left walk broken."
    )
    assert ep == "https://rdap.registry.in/"


def test_walk_never_matches_multi_label_prefix_of_a_domain():
    """DNS-RDAP bootstrap keys are single labels (RFC 7484 §3). Even
    if the mapping accidentally had `co.in` as a key, the walk starts
    from the TLD (shortest first) — so it should still match `.in`
    on the first probe. This is a defensive test for the walk order,
    NOT a check on what bootstrap should contain (that's IANA's).

    We add `co.in` to a shadowed mapping and confirm the walk still
    returns `in`, not `co.in`. If a future refactor flipped to
    longest-match, this test would break; the flip should be a
    deliberate commit with the RFC 7484 change explained, not
    incidental."""
    shadowed = dict(_STUB_MAPPING)
    shadowed["co.in"] = "https://should-never-be-used/"
    with patch("posture.core._load_bootstrap", return_value=shadowed):
        ep, suffix = rdap_endpoint_for("example.co.in")
    assert suffix == "in", (
        f"walk must be shortest-first (TLD-first) per RFC 7484 §3; "
        f"got suffix={suffix!r}. If this reversed to longest-match, the "
        f"CLAUDE.md `.co.in` guarantee needs re-verification against IANA."
    )


def test_multi_label_domain_matches_at_tld():
    """A four-label domain `a.b.c.in`: the walk starts at the TLD
    (shortest suffix) and matches `in` immediately. This tests that
    label count does NOT confuse the walk — a bug where the walker
    hardcoded a 2-label or 3-label stop would either miss the match
    or return the wrong suffix."""
    ep, suffix = rdap_endpoint_for("a.b.c.in")
    assert suffix == "in"
    assert ep == _STUB_MAPPING["in"]


def test_unknown_tld_returns_none_none():
    """A domain whose eTLD is NOT in bootstrap returns `(None, None)`.
    The rdap_lookup caller uses this to emit UNKNOWN, not FAIL — a
    tuple shape change here would break the rule-1 UNKNOWN routing."""
    ep, suffix = rdap_endpoint_for("example.example")
    assert ep is None
    assert suffix is None


def test_walk_handles_uppercase_input_labels():
    """Bootstrap keys are lowercased in the loader. The walk itself
    receives already-normalised punycode from `normalize_domain`, but
    if someone hands `rdap_endpoint_for` an uppercase label directly,
    the walk should either succeed (case-insensitive match) or return
    (None, None) — it must NOT crash. Current behaviour is exact-
    match, so uppercase misses; pin the safe-return contract so a
    future case-insensitivity change is a deliberate one."""
    ep, suffix = rdap_endpoint_for("EXAMPLE.COM")
    # Not asserting the specific answer — asserting the shape.
    assert (ep is None and suffix is None) or (
        ep == _STUB_MAPPING["com"] and suffix in {"com", "COM"}
    ), f"unexpected walk result on uppercase input: ep={ep!r}, suffix={suffix!r}"


def test_walk_does_not_match_prefix_of_a_bootstrap_key():
    """A domain `com.example` (dotted-reversed anomaly) must NOT match
    `com` at the front — the walk is over SUFFIXES, right-to-left.
    Guards against a bug where labels were joined in the wrong direction."""
    ep, suffix = rdap_endpoint_for("com.example")
    # `example` is not in bootstrap. Walk fails → (None, None).
    assert ep is None
    assert suffix is None


# --------------------------------------------------------------------- CLAUDE.md ground truth

def test_indian_bank_bank_in_resolves_via_nixi():
    """CLAUDE.md ground-truth row (`indianbank.bank.in`): the domain
    resolves RDAP under NIXI. Today's IANA bootstrap only has `.in`
    as a single-label key; the walk from `indianbank.bank.in` starts
    at the TLD (`in`), matches, and returns NIXI's endpoint. Missing
    this would fail the tool on every Indian-BFSI domain in the
    target segment."""
    ep, suffix = rdap_endpoint_for("indianbank.bank.in")
    assert ep == "https://rdap.registry.in/"
    assert suffix == "in", (
        f"indianbank.bank.in must land on the NIXI `.in` endpoint; "
        f"got suffix={suffix!r}"
    )


def test_verge_cloud_resolves_via_com():
    """Sanity: the tool's own home domain must resolve via the standard
    Verisign `.com` RDAP path."""
    ep, suffix = rdap_endpoint_for("vergecloud.com")
    assert suffix == "com"
    assert ep == _STUB_MAPPING["com"]
