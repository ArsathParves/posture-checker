# VergeCloud Domain Posture Checker

Single self-contained bundle with both the CLI and the FastAPI web tool.
Same check engine underneath both. No overlap between folders, nothing to
copy or shuffle.

---

## Layout

```
posture-checker/
├── README.md              ← this file
├── requirements.txt       ← all Python dependencies in one place
├── run_cli.sh             ← starts the CLI
├── run_web.sh             ← starts the web tool
│
├── posture/               ← the check engine (used by both CLI and web)
│   ├── __init__.py
│   ├── checks.py          orchestrator + grading
│   ├── cli.py             CLI renderer (used by run_cli.sh)
│   ├── core.py            RDAP, IP-RDAP, ASN via Team Cymru, normalisation
│   ├── dnsmod.py          DNS queries, parent-delegation, DNSSEC state machine
│   ├── emailauth.py       SPF (RFC 7208 lookup counting), DKIM, DMARC, MTA-STS
│   └── selftest.py        network-path integrity check
│
└── web/                   ← FastAPI web tool
    ├── __init__.py
    ├── server.py          endpoints, SSE streaming, cache, rate limit
    └── static/
        ├── index.html
        ├── style.css
        └── app.js         SSE consumer + progressive rendering
```

The `posture/` package is imported by both entry points. Nothing outside
`posture/` is imported by any check module — clean one-way dependency.

---

## Install (one time)

```bash
cd posture-checker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

That's the whole install. Both entry points use the same venv.

---

## Run the CLI

```bash
./run_cli.sh example.com
./run_cli.sh indianbank.bank.in --no-info
./run_cli.sh example.com --json
```

The CLI runs one check and prints the result to your terminal.

## Run the web tool

```bash
./run_web.sh
```

Open http://127.0.0.1:8000/ in a browser.

To stop the web tool, press Ctrl+C in the terminal.

---

## Environment health check

Before trusting any result, the tool verifies the network path it's running
on. If the environment intercepts DNS (corporate proxy) or blocks TCP/53,
per-nameserver checks would produce false findings, so the tool refuses to
present them — either as a `⚠ Degraded modules` line in the CLI, or as
HTTP 503 on the web tool's `/healthz` endpoint.

Check the web tool's environment health explicitly:

```bash
curl http://127.0.0.1:8000/healthz
```

---

## What each entry point does

**CLI** — one run, printed report, rich colours. Best for exploring a single
domain or spot-checking a customer domain during a call.

**Web** — HTTP + JSON API, SSE progressive rendering (sections stream in as
they complete), in-memory cache (5 minutes per domain), per-IP rate limit
(10 checks/minute), single-page UI. Best when you want a shareable checker
running on a machine other developers or a landing page can reach.

Both produce byte-for-byte identical findings — the web tool wraps the same
`run()` function the CLI calls.

---

## Known limitations (POC)

- DNSSEC validation checks the DNSKEY self-signature, not the full chain to root
- No WHOIS fallback for TLDs without RDAP (`.io`, `.de`, `.jp`, `.cn`)
- Single-vantage-point latency only; multi-region benchmarking (Phase 3, RIPE Atlas) not built
- Web tool has no OTP gate, no persistence, no authentication
- Result cache is in-process only; restarts wipe state
