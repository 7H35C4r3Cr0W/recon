"""Structured JSON logging + run/agent tracing. Every platform action is a structured event keyed by
(run_id, agent_id, project) so a run reads as one story across the api + N workers.

THREE trails, kept distinct on purpose:
  1. ENGINE audit  — per-project ``audit.jsonl`` (via ``oscprecon.audit``): what actually ran.
  2. PLATFORM audit — Postgres ``audit_log`` (see ``nabu_agent.audit``): who did what in the app.
  3. Structured logs (this module) — the NON-authoritative diagnostic stream (stdout JSON → collector).
"""

from __future__ import annotations

import logging

import structlog


def configure(level: str = "INFO", fmt: str = "json") -> None:
    renderer = (structlog.processors.JSONRenderer() if fmt == "json"
                else structlog.dev.ConsoleRenderer())
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,   # run_id/agent_id bound per task
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
    )


def bind_run(run_id: str, agent_id: str | None = None, **kw: str) -> None:
    structlog.contextvars.bind_contextvars(run_id=run_id, agent_id=agent_id or "-", **kw)
