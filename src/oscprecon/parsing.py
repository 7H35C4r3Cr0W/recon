from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TypeVar

logger = logging.getLogger("oscprecon.parsing")

T = TypeVar("T")


def _substantial(text: str) -> bool:
    # enough non-blank lines that a parser returning NOTHING is suspicious rather than "empty host"
    return sum(1 for line in text.splitlines() if line.strip()) >= 5


def run_parser(
    parse: Callable[[], list[T]],
    *,
    label: str,
    on_line: Callable[[str], None] | None = None,
    raw: str = "",
) -> list[T]:
    """Run a parser at the worker/GUI boundary; on ANY exception log + return [].

    why: a wrapped tool changing its output format — a new version, a truncated or interleaved
    capture — must NEVER crash the app (§24: robustness at the boundary). If a parser raises despite
    the per-parser skip-on-mismatch handling, this degrades to "couldn't parse" + zero findings and
    the recon step still completes. This is the containment net; parsers should still skip bad input
    line-by-line so a single drifted line doesn't lose the rest.

    Fail-loud: pass ``raw`` (the tool's output) and, when a parse returns EMPTY despite substantial
    output, a visible heads-up is streamed — a silent zero-findings on a drifted format is the
    mode that otherwise goes unnoticed. Callers pass ``raw`` only where 0 findings is a real signal.
    """
    try:
        result = parse()
    except Exception as exc:  # boundary: intentional broad catch — tool output drift is unbounded
        message = f"⚠ [parse-error] couldn't parse {label} output — the tool may have changed"
        logger.warning("%s (%s: %s)", message, type(exc).__name__, exc)
        if on_line is not None:
            on_line(message)
        return []
    if not result and on_line is not None and _substantial(raw):
        on_line(
            f"⚠ [parse] {label}: output present but 0 findings parsed — "
            "check the raw output (possible tool-version drift)"
        )
    return result
