"""Regression tests for S9 — outbound HTTP must name the tool.

Every `requests.get(...)` call from the posture engine must send a
`User-Agent` header identifying the tool + version + contact URL.
Third parties (IANA, ARIN, NIXI, DNS operators) receive traffic from
this tool; without a distinctive User-Agent they cannot:

  - rate-limit our traffic specifically (so a bug that hammers RDAP
    gets an entire IP block banned instead of just our tool)
  - contact us if the tool's traffic pattern is problematic

The v0.5 baseline had TWO problems:

  (1) The IANA RDAP bootstrap fetches at posture/core.py:152 and
      posture/core.py:312/320 did NOT pass `headers=HEADERS` at all —
      they went out with the default `python-requests/X.Y.Z` UA.

  (2) The `UA` constant said `vergecloud-posture-checker/0.1 (prototype)`,
      which is stale (project is v0.5) and does not include a contact
      channel.

Fix contract:
  - `posture.core.UA` names the tool, the current version, and includes
    a contact URL (repo URL is fine — third parties can open an issue).
  - Every `requests.get(...)` in the codebase passes `headers=HEADERS`,
    including the bootstrap calls that used to omit them.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def test_ua_string_names_the_tool():
    from posture.core import UA
    assert "posture-checker" in UA.lower(), (
        f"User-Agent must name the tool; got {UA!r}"
    )


def test_ua_string_carries_a_version():
    """The UA must include a version number. The exact value can change
    with releases, but a bare tool-name is not enough — third parties
    need to identify which build hit them."""
    import re
    from posture.core import UA
    assert re.search(r"\d+\.\d+", UA), (
        f"User-Agent must include a version; got {UA!r}"
    )


def test_ua_string_has_contact_url():
    """A UA without a contact channel is only marginally better than
    the default `python-requests/*`. Include a URL third parties can
    reach — repo URL is enough."""
    from posture.core import UA
    assert "http" in UA.lower() or "@" in UA, (
        f"User-Agent must include a contact URL or email; got {UA!r}"
    )


def test_ua_string_is_not_prototype_stub():
    """Guard against reverting to the placeholder `0.1 (prototype)` UA
    from the v0.5 baseline. This is the specific value the S9 audit
    called out."""
    from posture.core import UA
    assert "prototype" not in UA.lower(), (
        f"User-Agent must not label the tool 'prototype' — v0.5 shipped "
        f"this and S9 is the audit item to remove it; got {UA!r}"
    )


# ---------------------------------------------------------- bootstrap coverage

def _mock_response(json_data):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


def test_dns_bootstrap_passes_headers():
    """`_load_bootstrap` (called on every RDAP lookup with an empty cache)
    used to `requests.get(RDAP_BOOTSTRAP_URL, timeout=20)` — no headers.
    Must now pass `headers=HEADERS`."""
    from posture import core

    core._bootstrap_cache.clear()
    fake_bootstrap = {"services": [[["com"], ["https://rdap.example/"]]]}
    with patch.object(core.requests, "get",
                      return_value=_mock_response(fake_bootstrap)) as g:
        core._load_bootstrap()

    assert g.called, "expected _load_bootstrap to call requests.get"
    call_kwargs = g.call_args.kwargs
    headers = call_kwargs.get("headers") or {}
    assert "User-Agent" in headers, (
        f"IANA RDAP bootstrap fetch must send a User-Agent; "
        f"call kwargs were {call_kwargs!r}"
    )
    assert "posture-checker" in headers["User-Agent"].lower()


def test_ip_bootstrap_passes_headers():
    """The IPv4-RDAP bootstrap (posture/core.py:312 and :320) had the
    same omission. Same fix expected."""
    from posture import core

    core._ip_bootstrap.clear()
    fake_bootstrap = {"services": []}
    with patch.object(core.requests, "get",
                      return_value=_mock_response(fake_bootstrap)) as g:
        core.ip_rdap("192.0.2.1")

    if not g.called:
        pytest.skip("ip_rdap short-circuited before requests — bootstrap "
                    "not fetched in this path")
    for call in g.call_args_list:
        headers = (call.kwargs.get("headers") or {})
        assert "User-Agent" in headers, (
            f"IPv4 bootstrap fetch must send a User-Agent; "
            f"call was {call!r}"
        )
        assert "posture-checker" in headers["User-Agent"].lower()
