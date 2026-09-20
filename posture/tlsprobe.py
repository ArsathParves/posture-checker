"""B30 — TLS / HTTPS posture.

Two primitives, each independently mockable at the test seam:

- `probe_tls(domain)` — open a TLS socket to `<domain>:443`, negotiate
  the highest available protocol version, and extract the peer
  certificate. Returns a status dict; never raises.

- `probe_hsts(domain)` — HTTP GET to `https://<domain>/`, inspect the
  `Strict-Transport-Security` header. Never raises.

Both primitives normalise their outputs to a stable shape so
`checks._tls_posture` can key off it without caring about `ssl`
module internals.

Rule 1: any probe failure returns `{"ok": False, "error": ...}` — the
caller emits UNKNOWN. Never conflate "we could not connect" with
"the service is broken".

Rule 5: the caller is expected to gate TLS probing on
`env.safe_for_direct_dns`. An intercepted TLS path (corporate MITM CA
in the trust store) would produce false PASS on chain validity —
probing that path is worse than not probing at all.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

import requests

from .core import UA_HEADERS


TLS_PORT = 443
TLS_TIMEOUT = 10.0

# RFC 6797 §5.1: max-age is the header's teeth. Anything below six
# months is below the industry baseline for a bank/BFSI site.
HSTS_BASELINE_MAX_AGE = 15_552_000  # 180 * 86400

# Cert-expiry thresholds. Same shape as the RDAP expiry finding in
# `_registration`: <7d → FAIL, <30d → WARN, otherwise PASS. `notAfter`
# in the past is FAIL regardless.
CERT_FAIL_DAYS = 7
CERT_WARN_DAYS = 30


def _parse_openssl_time(raw: str) -> datetime:
    """OpenSSL time format: 'Jan  1 12:00:00 2027 GMT'.
    Anchored to UTC; the trailing 'GMT' is documented in the openssl
    x509 manpage.
    """
    dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
    return dt.replace(tzinfo=timezone.utc)


def _tuple_fields_to_dict(seq) -> dict:
    """ssl.getpeercert() returns tuples-of-tuples-of-tuples. Flatten
    one level: `((("CN","x"),),(("O","y"),))` → `{"CN":"x","O":"y"}`."""
    out: dict = {}
    for rdn in seq or ():
        for pair in rdn:
            if len(pair) == 2:
                out[pair[0]] = pair[1]
    return out


def _extract_cert(cert: dict) -> dict:
    subj = _tuple_fields_to_dict(cert.get("subject"))
    iss = _tuple_fields_to_dict(cert.get("issuer"))
    san = [v for k, v in (cert.get("subjectAltName") or ()) if k == "DNS"]
    not_before = _parse_openssl_time(cert["notBefore"]) if cert.get("notBefore") else None
    not_after = _parse_openssl_time(cert["notAfter"]) if cert.get("notAfter") else None
    return {
        "subject_cn": subj.get("commonName"),
        "issuer_cn": iss.get("commonName"),
        "issuer_org": iss.get("organizationName"),
        "not_before": not_before.strftime("%Y-%m-%dT%H:%M:%SZ") if not_before else None,
        "not_after": not_after.strftime("%Y-%m-%dT%H:%M:%SZ") if not_after else None,
        "san": san,
    }


def _open_tls_socket(host: str, port: int, timeout: float):
    """Split out as the network entry point — every test replaces this."""
    ctx = ssl.create_default_context()
    sock = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(sock, server_hostname=host)


def probe_tls(domain: str, port: int = TLS_PORT,
              timeout: float = TLS_TIMEOUT) -> dict:
    """Open TLS, capture cert + negotiated protocol. Never raises."""
    try:
        s = _open_tls_socket(domain, port, timeout)
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": "cert_verify_failed",
                "detail": str(e)}
    except ssl.SSLError as e:
        return {"ok": False, "error": "ssl_error", "detail": str(e)}
    except socket.gaierror:
        return {"ok": False, "error": "dns_lookup_failed"}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "error": "timeout"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "connection_refused"}
    except OSError as e:
        return {"ok": False, "error": "os_error", "detail": str(e)}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__,
                "detail": str(e)}
    try:
        cert = s.getpeercert()
        proto = s.version()
    finally:
        try:
            s.close()
        except Exception:
            pass
    if not cert:
        return {"ok": False, "error": "no_cert"}
    return {"ok": True, "protocol": proto,
            "cert": _extract_cert(cert), "chain_valid": True}


def probe_hsts(domain: str, timeout: float = TLS_TIMEOUT) -> dict:
    """HTTP GET https://<domain>/, inspect Strict-Transport-Security.
    We do not follow redirects — HSTS is scoped to the host that
    served the response; a redirect to a different origin's HSTS is
    not our target's HSTS.
    """
    try:
        r = requests.get(f"https://{domain}/", headers=UA_HEADERS,
                         timeout=timeout, allow_redirects=False)
    except requests.exceptions.SSLError:
        return {"ok": False, "error": "SSLError"}
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Timeout"}
    except requests.exceptions.ConnectionError:
        return {"ok": False, "error": "ConnectionError"}
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": type(e).__name__}
    hsts = r.headers.get("Strict-Transport-Security")
    if not hsts:
        return {"ok": True, "present": False}
    parts = [p.strip().lower() for p in hsts.split(";")]
    max_age = None
    for p in parts:
        if p.startswith("max-age="):
            try:
                max_age = int(p[len("max-age="):])
            except ValueError:
                pass
            break
    return {"ok": True, "present": True, "value": hsts,
            "max_age": max_age,
            "include_subdomains": "includesubdomains" in parts,
            "preload": "preload" in parts}
