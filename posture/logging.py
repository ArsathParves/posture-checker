"""Structured JSON logging.

TD5 fix — the codebase previously had no structured logging at all;
uvicorn's default access logs were the only signal available on a
public deployment. A public tool on vergecloud.com needs to answer
"what did this specific customer's check do?" from log lines alone,
which requires:

  1. A consistent JSON-lines format so lines are queryable by a
     log-aggregation layer (Loki, Cloudwatch, Datadog).
  2. Per-check correlation IDs so every log line for one check run
     shares a token (the same `check_id` the API returns to the
     caller — see BUGS.md T6).
  3. Sensible defaults on `stderr` so container platforms and
     systemd pick them up without a config.

Scope: JSON formatter + factory. Callers use the returned `logging.Logger`
normally, passing structured context via `extra={"check_id": ..., ...}`.

The formatter is deliberately minimal — timestamp, level, logger name,
message, and any `extra` fields. No stack-trace flattening; no colour
codes; no filtering. The stdlib `logging` module handles the rest.

CLI note: the CLI's Rich-rendered output is the product surface, not
logging. This module is used only where a program-visible log record
adds value the user-facing rendering does not (per-check audit trail,
rate-limit rejections, section exceptions).
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

# Standard LogRecord attributes we DON'T re-emit as `extra` — they
# either go into their own top-level field or are noise for a
# structured consumer.
_LOGRECORD_STANDARD = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname",
    "filename", "module", "exc_info", "exc_text", "stack_info",
    "lineno", "funcName", "created", "msecs", "relativeCreated",
    "thread", "threadName", "processName", "process", "message",
    "asctime", "taskName",
})


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line.

    Any keys in `record.__dict__` that are not standard LogRecord
    attributes are attached as top-level keys — so callers write
    `logger.info("job queued", extra={"check_id": id, "domain": d})`
    and the resulting line has `check_id` and `domain` as first-class
    fields, not buried in the message string.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
                          .isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k in _LOGRECORD_STANDARD or k.startswith("_"):
                continue
            payload[k] = v
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_CONFIGURED: set[str] = set()


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Return a JSON-formatted logger attached to stderr.

    Idempotent — repeated calls with the same name return the same
    logger without stacking handlers. Callers can raise the level
    per-logger via the `level` kwarg but the default of INFO is right
    for the tool's needs (DEBUG is reserved for local development).
    """
    logger = logging.getLogger(name)
    if name in _CONFIGURED:
        return logger
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False  # don't double-emit via root logger
    _CONFIGURED.add(name)
    return logger
