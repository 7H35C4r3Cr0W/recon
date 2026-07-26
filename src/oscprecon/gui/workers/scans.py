from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from oscprecon import alive, pivot, references, shell
from oscprecon.gui.workers.base import CancellableThread
from oscprecon.orchestrator import Orchestrator
from oscprecon.profile import Profile
from oscprecon.references import live_hacktricks


class PingWorker(CancellableThread):
    """Pre-flight 'is it alive?' — a quick nmap host-discovery sweep (exam-legal, no port scan) run
    BEFORE a full recon so the user knows the target answered. Emits the parsed AliveResult."""

    line = Signal(str)
    done = Signal(object)  # alive.AliveResult
    failed = Signal(str)

    def __init__(self, target: str, output_file: Path, cwd: Path | None = None) -> None:
        super().__init__()
        self._target = target
        self._output_file = output_file
        self._cwd = cwd

    def run(self) -> None:
        try:
            command = alive.build_alive_command(self._target)
            # §24 / "no hidden magic": the pre-flight check is a real nmap command like any other —
            # show it. It used to stream its output with nothing saying what had been run.
            self.line.emit(f"$ {command}")
            shell.run(
                command,
                self._output_file,
                cwd=self._cwd,
                cancel=self._cancel,
                on_line=self.line.emit,
            )
            if self._cancel.is_set():
                return  # Stop pressed mid-ping: suppress done so the confirm dialog never pops
            try:
                text = self._output_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            result = alive.parse_alive(text)
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result)


class NmapWorker(CancellableThread):
    line = Signal(str)
    done = Signal(int)
    failed = Signal(str)

    def __init__(
        self,
        profile: Profile,
        udp_full: bool = False,
        scan_profile: str = "default",
        resume: bool = False,
    ) -> None:
        super().__init__()
        self._profile = profile
        self._udp_full = udp_full
        self._scan_profile = scan_profile
        self._resume = resume

    def run(self) -> None:
        try:
            orch = Orchestrator(
                self._profile,
                on_line=self.line.emit,
                udp_full=self._udp_full,
                scan_profile=self._scan_profile,
                cancel=self._cancel,
                resume=self._resume,
            )
            orch.run_nmap()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(len(self._profile.discovered_services))


class CustomScanWorker(CancellableThread):
    """Run a user-configured nmap command (custom flags / range) and, in host mode, STREAM each
    discovered host as its block completes so a /24 fills the tree + graph progressively. Entry-host
    mode just runs + returns; the caller parses services from the output file on done."""

    line = Signal(str)
    host_found = Signal(object)  # DiscoveredHost, emitted live as the scan runs
    done = Signal(int)
    failed = Signal(str)

    def __init__(
        self,
        shell_line: str,
        output_file: Path,
        cwd: Path,
        *,
        stream_hosts: bool,
        pivot_source: str = "",
    ) -> None:
        super().__init__()
        self._shell_line = shell_line
        self._output_file = output_file
        self._cwd = cwd
        self._stream = pivot.NmapHostStream(pivot_source) if stream_hosts else None

    def _on_line(self, line: str) -> None:
        self.line.emit(line)
        if self._stream is not None:
            host = self._stream.feed_line(line)
            if host is not None:
                self.host_found.emit(host)

    def run(self) -> None:
        try:
            result = shell.run(
                self._shell_line,
                self._output_file,
                cwd=self._cwd,
                cancel=self._cancel,
                on_line=self._on_line,
            )
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        if self._stream is not None:
            last = self._stream.finish()  # the final host, completed at EOF
            if last is not None:
                self.host_found.emit(last)
        self.done.emit(result.exit_code)


class CommandWorker(CancellableThread):
    line = Signal(str)
    done = Signal(int)
    failed = Signal(str)

    def __init__(
        self,
        shell_line: str,
        output_file: Path,
        cwd: Path | None = None,
        spray: bool = False,
        exploit: bool = False,
    ) -> None:
        super().__init__()
        self._shell_line = shell_line
        self._output_file = output_file
        self._cwd = cwd
        # spray=True only from the gated spray flow (§2a); exploit=True only from the gated
        # Exploitation-tab Run (§2b). Each relaxes the policy for exactly its own tool category;
        # every other caller leaves both False (recon-only). sqlmap/Metasploit stay blocked in all.
        self._spray = spray
        self._exploit = exploit

    def run(self) -> None:
        try:
            result = shell.run(
                self._shell_line,
                self._output_file,
                cwd=self._cwd,
                cancel=self._cancel,
                on_line=self.line.emit,
                spray=self._spray,
                exploit=self._exploit,
            )
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result.exit_code)


class SearchsploitWorker(QThread):
    done = Signal(object, int)  # (references.EdbSearch, request_id)

    def __init__(self, product: str, version: str, output_file: Path, request_id: int) -> None:
        super().__init__()
        self._product = product
        self._version = version
        self._output_file = output_file
        self._request_id = request_id

    def run(self) -> None:
        try:
            search = references.search_exploits(self._product, self._version, self._output_file)
        except Exception:  # boundary: never let an EDB lookup crash the worker
            search = references.EdbSearch([], "", "none")
        self.done.emit(search, self._request_id)


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
        self._cancelled = False

    def cancel(self) -> None:
        # can't abort the in-flight (timeout-bounded) fetch, but suppress its result so a close/
        # delete needn't wait for it and no stale done fires against a torn-down profile. [#48]
        self._cancelled = True

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
        if self._cancelled:
            return  # dropped: the requester (profile/pane) is gone
        self.done.emit(result, self._request_id)
