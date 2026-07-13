from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from oscprecon import references, shell
from oscprecon.gui.workers.base import CancellableThread
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile
from oscprecon.references import live_hacktricks


class NmapWorker(CancellableThread):
    line = Signal(str)
    done = Signal(int)
    failed = Signal(str)

    def __init__(
        self, profile: Profile, udp_full: bool = False, scan_profile: str = "default"
    ) -> None:
        super().__init__()
        self._profile = profile
        self._udp_full = udp_full
        self._scan_profile = scan_profile

    def run(self) -> None:
        try:
            orch = Orchestrator(
                self._profile,
                on_line=self.line.emit,
                udp_full=self._udp_full,
                scan_profile=self._scan_profile,
                cancel=self._cancel,
            )
            orch.run_nmap()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(len(self._profile.discovered_services))


class CommandWorker(CancellableThread):
    line = Signal(str)
    done = Signal(int)
    failed = Signal(str)

    def __init__(
        self, shell_line: str, output_file: Path, cwd: Path | None = None, spray: bool = False
    ) -> None:
        super().__init__()
        self._shell_line = shell_line
        self._output_file = output_file
        self._cwd = cwd
        # spray=True only from the gated spray flow (§2a); it relaxes the exec policy for exactly
        # the credential-attempt category. Every other caller leaves it False (recon-only).
        self._spray = spray

    def run(self) -> None:
        try:
            result = shell.run(
                self._shell_line,
                self._output_file,
                cwd=self._cwd,
                cancel=self._cancel,
                on_line=self.line.emit,
                spray=self._spray,
            )
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result.exit_code)


class SearchsploitWorker(QThread):
    done = Signal(object, int)  # (list[ExploitHit], request_id)

    def __init__(self, product: str, version: str, output_file: Path, request_id: int) -> None:
        super().__init__()
        self._product = product
        self._version = version
        self._output_file = output_file
        self._request_id = request_id

    def run(self) -> None:
        try:
            hits = references.search_exploits(self._product, self._version, self._output_file)
        except Exception:  # boundary: never let an EDB lookup crash the worker
            hits = []
        self.done.emit(hits, self._request_id)


class LiveHacktricksWorker(QThread):
    done = Signal(object, int)  # (live_hacktricks.LiveResult, request_id)

    def __init__(
        self, url: str, *, enabled: bool, force: bool, max_age_days: int, request_id: int
    ) -> None:
        super().__init__()
        self._url = url
        self._enabled = enabled
        self._force = force
        self._max_age_days = max_age_days
        self._request_id = request_id

    def run(self) -> None:
        try:
            result = live_hacktricks.get_page(
                self._url,
                enabled=self._enabled,
                force=self._force,
                max_age_days=self._max_age_days,
            )
        except Exception:  # boundary: a fetch must never crash the worker
            result = live_hacktricks.LiveResult("error", "", [], 0.0, self._url, "fetch failed")
        self.done.emit(result, self._request_id)
