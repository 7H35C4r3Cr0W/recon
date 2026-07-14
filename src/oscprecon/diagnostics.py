"""Local diagnostic logging — capture crashes, errors, and Qt warnings to a rotating log file.

So when the GUI or CLI breaks, there is a record to look at. Everything here is best-effort: a
failure to set up logging must never take the app down. Offline only — no telemetry, no network.

    from oscprecon import diagnostics
    diagnostics.install("gui")        # or "cli" — at startup, once
    diagnostics.log_path()            # where the log lives (for a "View log" action)
    diagnostics.get_logger().info(…)  # app code can log through this
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from types import TracebackType

from oscprecon import branding, config

_LOG_FILE = "nabu.log"
_MAX_BYTES = 1_000_000  # ~1 MB per file
_BACKUPS = 3
_installed = False


def log_dir() -> Path:
    directory = config.state_dir() / "logs"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def log_path() -> Path:
    return log_dir() / _LOG_FILE


def get_logger() -> logging.Logger:
    return logging.getLogger("nabu")


def install(context: str) -> Path | None:
    """Set up rotating file logging + a global excepthook. Idempotent and best-effort.

    context: a short label for this process ("gui" | "cli"). Returns the log path, or None if
    logging could not be set up (in which case the app keeps running with no log).
    """
    global _installed
    if _installed:
        try:
            return log_path()
        except OSError:
            return None
    try:
        path = log_path()
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        already = any(
            isinstance(h, logging.handlers.RotatingFileHandler)
            and getattr(h, "baseFilename", None) == str(path)
            for h in root.handlers
        )
        if not already:
            handler = logging.handlers.RotatingFileHandler(
                path, maxBytes=_MAX_BYTES, backupCount=_BACKUPS, encoding="utf-8"
            )
            handler.setFormatter(
                logging.Formatter("%(asctime)s  %(levelname)-7s %(name)s: %(message)s")
            )
            root.addHandler(handler)
        get_logger().info(
            "=== %s %s session start (context=%s) ===",
            branding.APP_NAME,
            branding.app_version(),
            context,
        )
        _install_excepthook(context)
        _installed = True
        return path
    except Exception:  # noqa: BLE001 — logging setup must never crash the app
        return None


def _install_excepthook(context: str) -> None:
    previous = sys.excepthook

    def hook(
        exc_type: type[BaseException],
        exc: BaseException,
        tb: TracebackType | None,
    ) -> None:
        try:
            get_logger().error(
                "uncaught exception (context=%s)", context, exc_info=(exc_type, exc, tb)
            )
            sys.stderr.write(f"\n[nabu] a full traceback was written to {log_path()}\n")
        except Exception:  # noqa: BLE001 — never let the logging path swallow the real error
            pass
        previous(exc_type, exc, tb)  # keep default behaviour (print traceback, exit)

    sys.excepthook = hook


def install_qt_message_handler() -> None:
    """Route Qt's own runtime messages (qWarning/qCritical) into the log. GUI-only; best-effort.

    The default handler (stderr) is preserved so nothing is hidden — messages are logged *and*
    still printed.
    """
    try:
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler

        levels = {
            QtMsgType.QtDebugMsg: logging.DEBUG,
            QtMsgType.QtInfoMsg: logging.INFO,
            QtMsgType.QtWarningMsg: logging.WARNING,
            QtMsgType.QtCriticalMsg: logging.ERROR,
            QtMsgType.QtFatalMsg: logging.CRITICAL,
        }

        def handler(mode: QtMsgType, _ctx: object, message: str) -> None:
            try:
                get_logger().log(levels.get(mode, logging.INFO), "Qt: %s", message)
                stderr = sys.__stderr__
                if stderr is not None:
                    stderr.write(message + "\n")
            except Exception:  # noqa: BLE001
                pass

        qInstallMessageHandler(handler)
    except Exception:  # noqa: BLE001 — the Qt hook is a nicety, never required
        pass


def read_tail(max_bytes: int = 60_000) -> str:
    """Return the last `max_bytes` of the log file (for an in-app viewer). Empty if none yet."""
    try:
        path = log_path()
        if not path.exists():
            return ""
        size = path.stat().st_size
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            if size > max_bytes:
                handle.seek(size - max_bytes)
                handle.readline()  # drop the partial first line
            return handle.read()
    except OSError:
        return ""


def clear() -> bool:
    """Truncate the live log file. Returns True on success. Rotated backups are left in place."""
    try:
        log_path().write_text("", encoding="utf-8")
        get_logger().info("log cleared by user")
        return True
    except OSError:
        return False
