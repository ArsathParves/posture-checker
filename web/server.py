"""FastAPI web wrapper for the domain posture checker.

Presentation and access control only. No check logic lives here — every
result is produced by posture.checks and is byte-for-byte identical to the
CLI output. The web layer adds:

  - HTTP + JSON API
  - Server-Sent Events for progressive rendering
  - In-memory result cache with TTL
  - Rate limiting per source IP
  - Environment health check that refuses to serve if the network path
    would produce false findings (same guard as the CLI)
  - Static single-page UI

POC scope: no OTP gate, no persistence beyond process lifetime, no auth.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from posture.checks import grade, run_streaming
from posture.core import normalize_domain
from posture.selftest import check_environment

# ---------------------------------------------------------------- config

CACHE_TTL_SECONDS = 300       # 5 minutes
CHECK_JOB_TTL_SECONDS = 900   # jobs held for polling for 15 min
MAX_CONCURRENT_CHECKS = 8     # per process


# ---------------------------------------------------------------- state

@dataclass
class Job:
    """One check run. Populated by the background worker; consumed by SSE."""
    check_id: str
    domain: str
    dkim_selectors: list[str]
    created_at: float = field(default_factory=time.time)
    events: list[dict] = field(default_factory=list)
    done: bool = False
    error: str | None = None
    # Version counter incremented on each new event (prevents race on Event.clear())
    _event_version: int = 0
    # asyncio Event used by SSE consumers to wait for new frames
    _wake: asyncio.Event = field(default_factory=asyncio.Event)


# Job store: check_id -> Job. In-memory only, per POC scope.
JOBS: dict[str, Job] = {}
# domain -> (finished_job, expires_at). Used to skip re-runs.
RESULT_CACHE: dict[str, tuple[Job, float]] = {}
# Bound concurrency so a bulk-scan attempt can't exhaust threads
CHECK_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)


# ---------------------------------------------------------------- app

def _rate_limit_key(request) -> str:
    """Rate-limit key: the raw socket peer, always.

    slowapi's default `get_remote_address` reads `request.client.host`,
    which starlette derives from the ASGI `scope["client"]`. uvicorn's
    default (`proxy_headers=True` + `forwarded_allow_ips="127.0.0.1"`)
    overwrites `scope["client"]` with the leftmost `X-Forwarded-For`
    entry whenever the immediate TCP peer is 127.0.0.1 — turning XFF
    into a fully-controllable rate-limit key on same-host deployments
    (and during dev/test loopback runs). A crawler could rotate the
    header and bypass the per-IP quota.

    This helper unconditionally reads the socket-peer host, so the
    limiter is safe regardless of proxy_headers state or ASGI server
    choice. Falls back to `127.0.0.1` on absent client to match
    slowapi's own behaviour (never lets a request escape the bucket).
    """
    client = getattr(request, "client", None)
    if not client or not getattr(client, "host", None):
        return "127.0.0.1"
    return client.host


limiter = Limiter(key_func=_rate_limit_key)


def _parse_allowed_origins(raw: str | None) -> list[str] | None:
    """Parse the `POSTURE_ALLOWED_ORIGINS` env var into an explicit
    allow-list, or return None if CORS should not be enabled.

    Empty / unset → None (no CORSMiddleware attached → same-origin only).
    A `*` anywhere in the list → ValueError. The whole point of S2 is
    banishing `*`; silently degrading to it would recreate the bug the
    env-var was introduced to fix.
    """
    if not raw or not raw.strip():
        return None
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if any(p == "*" for p in parts):
        raise ValueError(
            "POSTURE_ALLOWED_ORIGINS must not contain a wildcard `*`. "
            "List the exact origins you want to allow, e.g. "
            "'https://vergecloud.com,https://www.vergecloud.com'."
        )
    return parts


def _build_app() -> FastAPI:
    """FastAPI factory. Attached to a module-level `app` at import
    time (that's what `uvicorn web.server:app` binds), and re-invoked
    by tests that need a fresh app under a controlled env state.

    Middleware attached here MUST NOT depend on module-level route
    decorators (`@app.get` etc.) since those are declared later at
    module scope; Starlette composes the middleware stack lazily so
    the ordering works out."""
    import os

    application = FastAPI(
        title="VergeCloud domain posture checker",
        description="POC web wrapper. Same check engine as the CLI.",
        version="0.4-poc",
    )
    application.state.limiter = limiter

    allowed = _parse_allowed_origins(os.environ.get("POSTURE_ALLOWED_ORIGINS"))
    if allowed is not None:
        # Explicit allow-list. `allow_credentials=False` to match the
        # POC's no-cookie / no-auth surface — flipping this on would
        # require re-auditing every endpoint for credential-theft
        # paths, and there's no reason to today.
        application.add_middleware(
            CORSMiddleware,
            allow_origins=allowed,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
            allow_credentials=False,
        )
    # Default (allowed is None): no CORSMiddleware — same-origin only.
    # This is deliberate: the tool is served alongside its own static
    # SPA, so same-origin XHR covers 100% of the intended traffic.
    return application


app = _build_app()


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429,
                        content={"error": "rate_limited",
                                 "detail": "Too many checks from this IP. "
                                           "Try again in a few minutes."})


# ---------------------------------------------------------------- validation

# Anything more permissive than this must be justified — the domain string is
# passed to DNS/RDAP queries and must not accept URLs, IPs, or crafted input.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9\u00a0-\uffff](?:[a-zA-Z0-9\u00a0-\uffff-]{0,61}"
    r"[a-zA-Z0-9\u00a0-\uffff])?\.)+[a-zA-Z\u00a0-\uffff]{2,63}\.?$"
)


class CheckRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    dkim_selectors: list[str] | None = Field(default=None, max_length=20)


def _validate_domain(raw: str) -> str:
    """Validate + normalise. Rejects URLs, IPs, and control characters.

    Reject URL-shaped input at the boundary rather than silently stripping
    the scheme -- a landing-page tool that transforms input silently is a
    source of user confusion and support tickets. normalize_domain() in
    posture.core is the ultimate authority; we mirror its rejection contract
    at the API edge so bad input never reaches DNS.
    """
    if "://" in raw or "/" in raw or "@" in raw:
        raise HTTPException(status_code=400,
            detail="Enter just the domain name, without http:// or paths")
    try:
        _, puny, _ = normalize_domain(raw)
    except ValueError as e:
        raise HTTPException(status_code=400,
                            detail=f"Not a valid domain: {e}")
    if not DOMAIN_RE.match(puny):
        raise HTTPException(status_code=400,
                            detail="Domain failed strict validation")
    return puny


# ---------------------------------------------------------------- worker

def _run_streaming_sync(domain: str, dkim_selectors: list[str] | None):
    """Wrap the checks generator so it can be driven from a thread."""
    yield from run_streaming(domain, dkim_selectors=dkim_selectors)


async def _run_job(job: Job):
    """Consume run_streaming() in a worker thread; push events into the job."""
    loop = asyncio.get_running_loop()
    async with CHECK_SEMAPHORE:
        gen = _run_streaming_sync(job.domain, job.dkim_selectors)
        try:
            while True:
                event = await loop.run_in_executor(None, next, gen, None)
                if event is None:
                    break
                job.events.append(event)
                job._event_version += 1  # Increment version on new event
                job._wake.set()
                if event.get("event") in ("complete", "error", "nxdomain"):
                    # nxdomain already emits complete after itself; keep loop
                    if event["event"] == "complete":
                        break
        except asyncio.CancelledError:
            # Task was cancelled (e.g., server shutdown). Mark as cancelled, not failed.
            job.error = "Check cancelled (server shutdown or timeout)"
            job.events.append({"event": "error", "type": "server",
                               "message": job.error})
            job._event_version += 1
            raise  # Re-raise so asyncio can handle cleanup
        except Exception as e:
            job.error = f"{type(e).__name__}: {e}"
            job.events.append({"event": "error", "type": "server",
                               "message": job.error})
            job._event_version += 1
        finally:
            job.done = True
            job._wake.set()  # Final notification

            # Cache successful runs by punycode domain for repeat visitors.
            if not job.error:
                RESULT_CACHE[job.domain] = (job, time.time() + CACHE_TTL_SECONDS)

            # Schedule GC of the job itself (only if loop is still running)
            try:
                loop.call_later(CHECK_JOB_TTL_SECONDS, JOBS.pop, job.check_id, None)
            except RuntimeError:
                # Loop already closed, just remove immediately
                JOBS.pop(job.check_id, None)


# ---------------------------------------------------------------- routes

@app.get("/healthz")
async def healthz():
    """Deploy-time gate.

    If the deploy environment rewrites DNS or blocks TCP/53, per-nameserver
    and TXT-heavy checks will produce false findings. Refusing to serve
    /healthz -> 503 is preferable to publishing wrong data.
    """
    env = check_environment()
    ok = env["safe_for_per_ns_checks"]
    payload = {
        "status": "ok" if ok else "degraded",
        "environment": env,
        "cache_entries": len(RESULT_CACHE),
        "in_flight_jobs": sum(1 for j in JOBS.values() if not j.done),
    }
    return JSONResponse(status_code=200 if ok else 503, content=payload)


@app.post("/api/check")
@limiter.limit("10/minute")
async def create_check(request: Request, body: CheckRequest):
    """Submit a check. Returns immediately with a check_id.

    Consumers stream results via GET /api/check/{id}/stream (SSE) or poll
    GET /api/check/{id}/result (blocks until done).
    """
    domain = _validate_domain(body.domain)

    # Cache hit? Return the existing check_id — SSE will replay events.
    cached = RESULT_CACHE.get(domain)
    if cached and cached[1] > time.time():
        prior = cached[0]
        complete = next((e for e in prior.events
                         if e.get("event") == "complete"), None)
        return {"check_id": prior.check_id, "cached": True,
                "domain": prior.domain,
                "result": complete}

    check_id = uuid.uuid4().hex[:16]
    job = Job(check_id=check_id, domain=domain,
              dkim_selectors=body.dkim_selectors or [])
    JOBS[check_id] = job
    asyncio.create_task(_run_job(job))
    return {"check_id": check_id, "cached": False, "domain": domain}


@app.get("/api/check/{check_id}/stream")
async def stream_check(check_id: str):
    """Server-Sent Events. Emits each event as the check produces it.

    Progressive rendering: the browser draws Registration & delegation while
    DNSSEC and email auth are still running.
    """
    job = JOBS.get(check_id)
    if not job:
        raise HTTPException(status_code=404, detail="check_id not found")

    async def generator():
        seen = 0
        last_version = job._event_version
        # SSE heartbeat: keep proxies from closing an idle stream
        last_heartbeat = time.time()
        while True:
            # Emit any new events since last check
            while seen < len(job.events):
                event = job.events[seen]
                seen += 1
                yield f"event: {event.get('event', 'message')}\n"
                yield f"data: {json.dumps(event)}\n\n"
            if job.done and seen >= len(job.events):
                yield "event: end\ndata: {}\n\n"
                return
            # Wait for new events (version change) or job completion
            # Check version before waiting to avoid race: if version changed between
            # the event emission loop and here, don't wait.
            if job._event_version > last_version or job.done:
                last_version = job._event_version
                continue
            job._wake.clear()
            try:
                await asyncio.wait_for(job._wake.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                pass
            finally:
                last_version = job._event_version  # Update version after waiting
            if time.time() - last_heartbeat > 20:
                yield ": ping\n\n"
                last_heartbeat = time.time()

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/check/{check_id}/result")
async def get_result(check_id: str):
    """Blocking JSON result. Returns the same Report structure as the CLI."""
    job = JOBS.get(check_id)
    if not job:
        raise HTTPException(status_code=404, detail="check_id not found")
    # Wait up to 30s for completion
    for _ in range(60):
        if job.done:
            break
        await asyncio.sleep(0.5)
    if not job.done:
        raise HTTPException(status_code=504, detail="Check still running; "
                            "use /stream for progressive results.")
    complete = next((e for e in job.events if e.get("event") == "complete"), None)
    if not complete:
        return {"error": job.error or "unknown", "events": job.events}
    return complete


# ---------------------------------------------------------------- static UI

_STATIC = Path(__file__).parent / "static"
if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

    @app.get("/")
    async def index():
        return FileResponse(str(_STATIC / "index.html"))


def main():
    """Console-script entry point (`posture-web`). Cross-platform: uses
    plain uvicorn.run so it works on Windows too — no reliance on the
    shell wrapper or on uvloop from `uvicorn[standard]`.

    S3: `proxy_headers=False` by default so `X-Forwarded-For` cannot
    influence `scope["client"]`, and by extension cannot influence
    the rate-limit key. Operators fronting the tool with a real
    reverse proxy can opt in via `POSTURE_TRUST_PROXY=1` — but even
    then the rate-limit key is the socket peer (see `_rate_limit_key`).
    The env var controls trust for downstream logging / audit uses of
    `request.client.host`, not the rate limiter.
    """
    import os
    import uvicorn

    trust_proxy = os.environ.get("POSTURE_TRUST_PROXY", "").lower() in {
        "1", "true", "yes"
    }
    uvicorn.run("web.server:app", host="127.0.0.1", port=8000,
                proxy_headers=trust_proxy)
