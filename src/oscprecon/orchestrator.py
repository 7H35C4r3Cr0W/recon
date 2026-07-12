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
        # why: --resume reuse must key on the LATEST history entry per output_file, not any-ever.
        # command_history only appends, so a later force-run that truncated a file (exit != 0) must
        # override the earlier exit-0 record, and a command whose args changed (e.g. the versioned
        # scan's -p port set grew) must re-run even though the output_file name is unchanged.
        self._last_by_output: dict[str, dict[str, object]] = {}
        for entry in profile.command_history:
            output_file = entry.get("output_file")
            if output_file:
                self._last_by_output[str(output_file)] = entry
        # why: command ids must stay unique across re-scans of the same profile, whose
        # command_history persists — so continue numbering, don't reset to 0.
        self._counter = len(profile.command_history)

    def _emit(self, text: str) -> None:
        if self.on_line is not None:
            self.on_line(text)

    def _cancelled(self) -> bool:
        return self.cancel is not None and self.cancel.is_set()

    def _reusable(self, cmd: Command) -> bool:
        # why: reuse only when the MOST RECENT run for this output_file finished exit 0, was made by
        # the SAME shell_line (args unchanged), and the file is on disk + non-empty. A later
        # truncating force-run (exit != 0) or a changed command re-runs; --force always re-runs.
        if not self.resume or self.force:
            return False
        last = self._last_by_output.get(cmd.output_file)
        if last is None or last.get("exit_code") != 0 or last.get("shell_line") != cmd.shell_line:
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
