# =========================================================
# STRUCTURED LOGGING
# Stdlib-only (no new dependency). Emits one JSON object per
# line to stdout — parseable by Cloud Logging / Loki / jq —
# with a per-request correlation id carried through a
# ContextVar so every line from one request is tied together.
#
#   LOG_LEVEL   DEBUG|INFO|WARNING|ERROR   (default INFO)
#   LOG_FORMAT  json|text                  (default json)
#
# Text format is the human-friendly local-dev view; json is
# the production default.
# =========================================================

import json
import logging
import os
import sys
import time
from contextvars import ContextVar

_request_id: ContextVar = ContextVar("request_id", default="-")


def set_request_id(rid: str):
    _request_id.set(rid or "-")


def get_request_id() -> str:
    return _request_id.get()


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id.get()
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_configured = False


def configure_logging():
    """Idempotent root-logger setup. Safe to call at import time."""
    global _configured
    if _configured:
        return

    # `or` (not a .get default) so an env var present-but-empty — e.g.
    # a Helm --reuse-values upgrade whose stored values predate these
    # keys and render value: "" — falls back instead of crashing on
    # setLevel("").
    level = (os.environ.get("LOG_LEVEL") or "INFO").upper()
    fmt = (os.environ.get("LOG_FORMAT") or "json").lower()

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(_RequestIdFilter())
    if fmt == "text":
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s [%(request_id)s] %(name)s — %(message)s"
        ))
    else:
        handler.setFormatter(_JsonFormatter())

    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)

    # Route uvicorn's own loggers through the same handler/format
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True

    _configured = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
