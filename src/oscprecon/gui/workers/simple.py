from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from PySide6.QtCore import Signal

from oscprecon import findings, shell
from oscprecon.gui.simple_recon import SIMPLE_SPECS
from oscprecon.gui.workers.base import CancellableThread
from oscprecon.models import Finding
from oscprecon.modules.base import Module
from oscprecon.profile import Profile


@dataclass
class SimpleReconResult:
    module: str
    summary: list[str]


class SimpleReconWorker(CancellableThread):
    line = Signal(str)
    done = Signal(object)  # SimpleReconResult
    failed = Signal(str)

    def __init__(self, profile: Profile, module_name: str, port: int = 0) -> None:
        super().__init__()
        self._profile = profile
        self._spec = SIMPLE_SPECS[module_name]
        self._port = port

    def run(self) -> None:
        try:
            result = self._drive()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        self.done.emit(result)

    def _run_step(self, shell_line: str, output_rel: str) -> str:
        base = self._profile.directory
        out = base / output_rel
        shell.run(shell_line, out, cwd=base, cancel=self._cancel, on_line=self.line.emit)
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _drive(self) -> SimpleReconResult:
        target = self._profile.target
        raw: dict[str, str] = {}
        for command, tool in self._spec.steps_fn(target, self._port):
            if self._cancel.is_set():
                break
            text = self._run_step(command.shell_line, command.output_file)
            if tool:  # unparsed steps (e.g. tftp GETs) still run, but carry no parser key
                raw[tool] = text
        module = self._spec.factory()
        found = module.parse(raw)
        self._write_findings(found)
        return SimpleReconResult(self._spec.module, self._summarize(module, found))

    def _write_findings(self, found: list[Finding]) -> None:
        if not found:
            return
        now = datetime.now(UTC).isoformat()
        findings.add_findings(
            self._profile.directory,
            [
                {
                    "module": f.service,
                    "kind": f.fields.get("kind", ""),
                    "value": f.fields.get("value", ""),
                    "detail": f.detail,
                    "discovered_at": now,
                }
                for f in found
            ],
        )

    def _summarize(self, module: Module, found: list[Finding]) -> list[str]:
        summary: list[str] = []
        by_kind: dict[str, list[str]] = {}
        for f in found:
            by_kind.setdefault(f.fields.get("kind", "?"), []).append(f.fields.get("value", ""))
        for kind, values in by_kind.items():
            shown = ", ".join(v for v in values[:4] if v)
            more = " …" if len(values) > 4 else ""
            summary.append(f"{kind} ({len(values)}): {shown}{more}")
        summary.extend(f"→ {tip}" for tip in module.suggest(found))
        return summary or [f"No {self._spec.module.upper()} findings."]
