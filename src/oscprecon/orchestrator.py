from __future__ import annotations

import threading
from collections.abc import Callable

from oscprecon import shell
from oscprecon.models import Command, Port, Proto
from oscprecon.modules.nmap import NmapModule
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter


class Orchestrator:
    def __init__(
        self,
        profile: Profile,
        *,
        on_line: Callable[[str], None] | None = None,
        udp_full: bool = False,
        resume: bool = False,
        force: bool = False,
        cancel: threading.Event | None = None,
    ) -> None:
        self.profile = profile
        self.on_line = on_line
        self.nmap = NmapModule(udp_full=udp_full)
        self.resume = resume
        self.force = force
        self.cancel = cancel
        # why: --resume may reuse only commands that finished cleanly in a PRIOR run (exit 0).
        # Snapshot that history at construction — commands this run appends must not count as
        # reusable, and blocked/missing/timeout (non-zero) entries stay out so they re-run.
        self._completed = {
            str(entry.get("output_file"))
            for entry in profile.command_history
            if entry.get("exit_code") == 0 and entry.get("output_file")
        }
        # why: command ids must stay unique across re-scans of the same profile, whose
        # command_history persists — so continue numbering, don't reset to 0.
        self._counter = len(profile.command_history)

    def _emit(self, text: str) -> None:
        if self.on_line is not None:
            self.on_line(text)

    def _cancelled(self) -> bool:
        return self.cancel is not None and self.cancel.is_set()

    def _reusable(self, cmd: Command) -> bool:
        # why: reuse a command's output only when its prior run finished with exit 0 AND the file is
        # still on disk and non-empty — an aborted run (killed before its history entry was written)
        # leaves no exit-0 record and re-runs. --force forces a re-run regardless.
        if not self.resume or self.force or cmd.output_file not in self._completed:
            return False
        out_path = self.profile.directory / cmd.output_file
        try:
            return out_path.is_file() and out_path.stat().st_size > 0
        except OSError:
            return False

    def _run(self, cmd: Command) -> str:
        out_path = self.profile.directory / cmd.output_file
        if self._reusable(cmd):
            self._emit(f"[resume] reusing {cmd.output_file} — skipping: {cmd.shell_line}")
            try:
                return out_path.read_text(encoding="utf-8")
            except OSError:
                return ""
        self._emit(f"$ {cmd.shell_line}")
        result = shell.run(
            cmd.shell_line,
            out_path,
            cwd=self.profile.directory,
            cancel=self.cancel,
            on_line=self._emit,
        )
        self._counter += 1
        self.profile.add_command(
            {
                "id": f"cmd-{self._counter:03d}",
                "module": cmd.module,
                "shell_line": cmd.shell_line,
                "why": cmd.why,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "exit_code": result.exit_code,
                "output_file": cmd.output_file,
                "phase": cmd.phase,
            }
        )
        if result.blocked is not None:
            self._emit(f"[blocked] {result.blocked} — refusing to run.")
            return ""
        if result.missing_tool is not None:
            self._emit(f"[missing] {result.missing_tool} — skipping.")
            return ""
        try:
            return out_path.read_text(encoding="utf-8")
        except OSError:
            return ""

    def run_nmap(self) -> None:
        target = self.profile.target
        raw: dict[str, str] = {}

        for cmd in self.nmap.commands(target, []):
            if self._cancelled():
                break
            raw[cmd.output_file] = self._run(cmd)
        self.profile.set_services(self.nmap.discovered_services(raw))
        self.profile.save()

        open_tcp = [
            Port(number=s.port, proto=Proto.TCP)
            for s in self.profile.discovered_services
            if s.proto == Proto.TCP
        ]
        # why: an empty port list would collapse NmapModule.commands back to the discovery
        # battery — only run the versioned scan when there is actually a TCP port to version.
        if open_tcp and not self._cancelled():
            for cmd in self.nmap.commands(target, open_tcp):
                raw[cmd.output_file] = self._run(cmd)
            self.profile.set_services(self.nmap.discovered_services(raw))
            self.profile.save()

        Reporter(self.profile).write()
        self._emit(
            f"[done] {len(self.profile.discovered_services)} services — "
            f"report: {self.profile.directory / 'report.md'}"
        )
