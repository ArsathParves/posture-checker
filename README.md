# VergeCloud Domain Posture Checker

Single self-contained bundle with both the CLI and the FastAPI web tool.
Same check engine underneath both. No overlap between folders, nothing to
copy or shuffle.

---

## Layout

```
posture-checker/
├── README.md              ← this file
├── pyproject.toml         ← PEP 621 install metadata (preferred install path)
├── requirements.txt       ← legacy flat requirements (still works)
├── Dockerfile             ← multi-stage container image (runs the web tool)
├── run_cli.sh             ← legacy CLI launcher (use `posture-cli` instead)
├── run_web.sh             ← legacy web launcher (use `posture-web` instead)
│
├── posture/               ← the check engine (used by both CLI and web)
│   ├── __init__.py
│   ├── checks.py          orchestrator + grading
│   ├── cli.py             CLI renderer + argparse entry point
│   ├── core.py            RDAP, IP-RDAP, ASN via Team Cymru, normalisation
│   ├── dnsmod.py          DNS queries, parent-delegation, DNSSEC state machine
│   ├── emailauth.py       SPF (RFC 7208 lookup counting), DKIM, DMARC, MTA-STS
│   └── selftest.py        network-path integrity check
│
├── web/                   ← FastAPI web tool
│   ├── __init__.py
│   ├── server.py          endpoints, SSE streaming, cache, rate limit
│   └── static/
│       ├── index.html
│       ├── style.css
│       └── app.js         SSE consumer + progressive rendering
│
└── tests/                 ← pytest suite (162+ tests, offline)
```

The `posture/` package is imported by both entry points. Nothing outside
`posture/` is imported by any check module — clean one-way dependency.

---

## Install (one time)

**Preferred (PEP 621):**

```bash
cd posture-checker
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[web]        # CLI + web tool + tests
```

`pip install .` on its own gives you the CLI only. The `[web]` extra pulls
in FastAPI + uvicorn + slowapi. On Linux/macOS you can additionally
opt in to `uvloop`-backed uvicorn with `pip install .[web,performance]`
(skipped on Windows where uvloop does not build).

After install, `posture-cli` and `posture-web` are on your PATH.

**Legacy flat requirements (still works):**

```bash
pip install -r requirements.txt
```

---

## Run the CLI

```bash
posture-cli example.com
posture-cli indianbank.bank.in --no-info
posture-cli example.com --json
posture-cli example.com --strict
```

Flags:

| Flag | Effect |
|---|---|
| `--json` | Machine-readable output. `grades` block contains overall + correctness + hardening letters. |
| `--no-info` | Hide `INFO` rows (normalisation notes, "skipped — null MX", etc). |
| `--dkim-selector NAME` | Add a DKIM selector to probe. Repeatable. |
| `--skip-asn` | Skip IP-RDAP / Team Cymru ASN lookups (faster; loses operator classification). |
| `--strict` | Pre-production audit mode: WARN findings score as FAIL for the grade only. Section renderer still shows the underlying status. |

The legacy `./run_cli.sh example.com` wrapper still works but is a thin
shim around the installed `posture-cli` script.

---

## Run the web tool

```bash
posture-web
```

Open http://127.0.0.1:8000/ in a browser. Stop with Ctrl+C.

The legacy `./run_web.sh` wrapper still works. On a fresh clone without a
`.venv`, `run_web.sh` refuses to run and prints the install command.

**Docker:**

```bash
docker build -t posture-checker .
docker run --rm -p 8000:8000 posture-checker
```

The image binds `0.0.0.0:8000` inside the container and runs as a
dedicated non-root user.

---

## Environment health check

Before trusting any result, the tool verifies the network path it's
running on. If the environment intercepts DNS (corporate proxy, VPN
transparent resolver) or blocks TCP/53, per-nameserver checks would
produce false findings, so the tool refuses to present them — either as
a `⚠ Self-test warnings` block above the CLI grade, or as HTTP 503 on
the web tool's `/healthz` endpoint.

Check the web tool's environment health explicitly:

```bash
curl http://127.0.0.1:8000/healthz
```

---

## Tests

```bash
pytest -m "not network"     # offline gate — must pass in CI
pytest -m network           # nightly / manual — hits live DNS/RDAP
pytest                      # everything
```

`pytest -m "not network"` is the CI contract — every fix in this repo
ships with a regression test in that set, so a green offline run means
no known bug has regressed. The `network` marker is for the small set of
tests that exercise live DNS/RDAP against the four CLAUDE.md ground-truth
domains (`cloudflare.com`, `google.com`, `dnssec-failed.org`,
`vergecloud.com`); those are intentionally excluded from the offline
gate because a flaky network would produce a false CI failure.

---

## What each entry point does

**CLI (`posture-cli`)** — one run, printed report, rich colours. Best
for exploring a single domain or spot-checking a customer domain during
a call.

**Web (`posture-web`)** — HTTP + JSON API, SSE progressive rendering
(sections stream in as they complete), in-memory cache (5 minutes per
domain), per-IP rate limit (10 checks/minute), single-page UI. Best
when you want a shareable checker running on a machine other developers
or a landing page can reach.

Both produce byte-for-byte identical findings — the web tool wraps the
same `run()` function the CLI calls.

---

## Known limitations (POC)

- DNSSEC validation checks DNSKEY self-signature; the audit-tracked
  full DS→DNSKEY chain-to-root walk lives in `dnsmod.dnssec_status`.
- No WHOIS fallback for TLDs without RDAP (`.io`, `.de`, `.jp`, `.cn`).
- Single-vantage-point latency only; multi-region benchmarking (RIPE
  Atlas) not built.
- Web tool has no OTP gate, no persistence, no authentication.
- Result cache is in-process only; restarts wipe state.
