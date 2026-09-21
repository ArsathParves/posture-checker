"""Regression tests for S7 — SSE endpoint has no per-connection ceiling.

The `/api/check/{id}/stream` generator loops forever as long as either
new events arrive OR heartbeats are being emitted (every ~20s). A
slowloris-style client can open the connection and hold it open
indefinitely, consuming one asyncio task per hung connection. The
fix caps total wall-clock lifetime of the stream.

Contract:
  - The generator obeys `web.server.SSE_MAX_STREAM_SECONDS` (a module
    constant so operators can tune it and tests can drive it low).
  - When the ceiling is hit, the generator emits a `timeout` SSE event
    with a `data: {"reason": "..."}` payload, then returns. It does
    NOT delete the underlying Job — the client can reconnect and pick
    up from cached events, or fetch the final report via /result.
  - Normal checks (which complete in < ceiling) MUST NOT see the
    timeout path — no `timeout` event on a happy-path stream.

Tests here drive the generator directly via `async for` rather than
going through `TestClient(...).get(..., stream=True)` because Starlette's
TestClient streams block on synchronous iteration and don't play nicely
with the wall-clock we need to control here.
"""
from __future__ import annotations

import asyncio
import json

import pytest


@pytest.mark.asyncio
async def test_sse_max_stream_seconds_constant_exists():
    """The ceiling must be a module-level constant so operators can
    override it via monkeypatching / config and so tests can drive it
    low without waiting real minutes."""
    from web import server
    assert hasattr(server, "SSE_MAX_STREAM_SECONDS"), (
        "web.server must expose SSE_MAX_STREAM_SECONDS as a tunable "
        "module constant"
    )
    assert server.SSE_MAX_STREAM_SECONDS > 0
    # Sanity: default is generous enough for real checks but short
    # enough to bound a slowloris attacker.
    assert server.SSE_MAX_STREAM_SECONDS <= 600, (
        f"default ceiling {server.SSE_MAX_STREAM_SECONDS}s is too permissive "
        "— a slowloris client should not be able to camp for 10+ minutes"
    )


@pytest.mark.asyncio
async def test_slow_stream_gets_timeout_event_and_closes(monkeypatch):
    """The core S7 assertion: a job that never completes (no events,
    never sets `.done`) must NOT keep the stream open forever. After
    `SSE_MAX_STREAM_SECONDS` the generator emits a `timeout` event
    and exits cleanly."""
    from web import server

    monkeypatch.setattr(server, "SSE_MAX_STREAM_SECONDS", 0.3)

    job = server.Job(check_id="slow", domain="example.com", dkim_selectors=[])
    server.JOBS[job.check_id] = job
    try:
        gen = _drive_stream(job.check_id)
        chunks = []

        async def _consume():
            async for chunk in gen:
                chunks.append(chunk)

        # Give the generator up to 3x the ceiling — if it hasn't
        # terminated by then, the fix is not implemented.
        # `asyncio.wait_for` (3.10-compatible) — `asyncio.timeout`
        # context manager only exists on 3.11+.
        try:
            await asyncio.wait_for(
                _consume(),
                timeout=server.SSE_MAX_STREAM_SECONDS * 3 + 1,
            )
        except asyncio.TimeoutError:
            pytest.fail(
                f"SSE stream did not terminate within "
                f"{server.SSE_MAX_STREAM_SECONDS * 3 + 1}s — S7 ceiling "
                f"not honoured"
            )
        joined = "".join(chunks)
        assert "event: timeout" in joined, (
            f"expected a 'timeout' SSE event when the ceiling fires; "
            f"stream output was: {joined!r}"
        )
    finally:
        server.JOBS.pop(job.check_id, None)


@pytest.mark.asyncio
async def test_timed_out_stream_leaves_job_intact(monkeypatch):
    """The timeout is per-connection, not per-job. The underlying Job
    must remain in JOBS so a reconnecting client can resume, and so
    /api/check/{id}/result can still return the final report once the
    background worker eventually finishes."""
    from web import server

    monkeypatch.setattr(server, "SSE_MAX_STREAM_SECONDS", 0.2)

    job = server.Job(check_id="stays", domain="example.com", dkim_selectors=[])
    server.JOBS[job.check_id] = job
    try:
        gen = _drive_stream(job.check_id)

        async def _drain():
            async for _ in gen:
                pass

        await asyncio.wait_for(_drain(), timeout=2.0)
        # Job must still be there after the stream closed.
        assert job.check_id in server.JOBS, (
            "timing out a stream must NOT delete the underlying job — "
            "the client should be able to reconnect / fetch /result"
        )
    finally:
        server.JOBS.pop(job.check_id, None)


@pytest.mark.asyncio
async def test_happy_path_stream_does_not_emit_timeout_event(monkeypatch):
    """Regression guard: a job that completes normally must NOT trigger
    the timeout path even if `SSE_MAX_STREAM_SECONDS` is low. The final
    event is `end`, not `timeout`."""
    from web import server

    monkeypatch.setattr(server, "SSE_MAX_STREAM_SECONDS", 5.0)

    job = server.Job(check_id="fast", domain="example.com", dkim_selectors=[])
    # Pre-populate a normal complete flow: one section event + complete.
    job.events.append({"event": "started", "domain": "example.com"})
    job.events.append({"event": "complete", "grade": {"overall": "A"}})
    job._event_version = 2
    job.done = True
    job._wake.set()
    server.JOBS[job.check_id] = job
    try:
        gen = _drive_stream(job.check_id)
        chunks = []

        async def _consume():
            async for chunk in gen:
                chunks.append(chunk)

        await asyncio.wait_for(_consume(), timeout=2.0)
        joined = "".join(chunks)
        assert "event: timeout" not in joined, (
            f"happy-path stream must NOT emit 'timeout'; got {joined!r}"
        )
        assert "event: end" in joined, (
            f"happy-path stream must emit 'end'; got {joined!r}"
        )
    finally:
        server.JOBS.pop(job.check_id, None)


# --------------------------------------------------------------- helpers

async def _drive_stream(check_id: str):
    """Invoke `stream_check` and iterate its StreamingResponse body.

    FastAPI wraps our async generator in a StreamingResponse; the
    underlying iterator is `.body_iterator` and yields already-encoded
    bytes / str chunks. We decode to str for the assertion helpers."""
    from web import server
    resp = await server.stream_check(check_id)
    async for chunk in resp.body_iterator:
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", errors="replace")
        yield chunk
