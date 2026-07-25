from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from PySide6.QtCore import Signal

from oscprecon import findings, nse_vuln, run_paths, shell
from oscprecon.gui.workers.base import CancellableThread
from oscprecon.models import Proto
from oscprecon.parsing import run_parser
from oscprecon.profile import Profile

# vuln NSE is slower than a service enum (a dozen scripts, each doing its own protocol dance) but it
# still must not hang forever on a tarpit — same watchdog shape as the other workers, longer bound.
_TIMEOUT_S = 900.0


@dataclass
class VulnScanResult:
    service: str
    port: int
    summary: list[str] = field(default_factory=list)
    hits: int = 0
    checked: int = 0  # how many checks actually reported — 0 means the scan did not really run


class VulnScanWorker(CancellableThread):
    """Run the NSE vuln checks for ONE discovered service, and turn the verdicts into findings.

    Findings, not just output: a VULNERABLE line that only ever exists in a scrollback pane is a
    line that gets missed. Recording it means it also reaches the Findings view, the graph, the
    report and `nabu-cli findings`.
    """

    line = Signal(str)
    done = Signal(object)  # VulnScanResult
    failed = Signal(str)

    def __init__(
        self,
        profile: Profile,
        service_name: str,
        port: int,
        mode: str = nse_vuln.MODE_ALL,
        proto: Proto = Proto.TCP,
        host: str = "",
        ports: tuple[int, ...] = (),
    ) -> None:
        super().__init__()
        self._profile = profile
        self._service_name = service_name
        self._port = port
        self._mode = mode
        self._proto = proto
        # a service selected under a PIVOTED host must be scanned on THAT host, not the entry box —
        # otherwise the verdict is about the wrong machine and is filed against the pivot anyway.
        self._host = host
        # an explicit port set from the planner. A service family with no DECLARED ports (msrpc and
        # its dynamic range) cannot be rebuilt from the service key alone.
        self._explicit_ports = tuple(ports)

    def run(self) -> None:
        try:
            result = self._drive()
        except Exception as exc:  # boundary: surface worker failures to the UI thread
            self.failed.emit(str(exc))
            return
        if self._cancel.is_set():
            result.summary.insert(0, "⚠ vuln scan cancelled — checks are incomplete")
        self.done.emit(result)

    def output_rel(self) -> str:
        # the host is part of the path: a pivoted host's scan must not overwrite the entry box's
        # the SAME port list _drive() scans — deriving the name from a different set meant the
        # claim guarded one path while the scan wrote another.
        spec = nse_vuln.profile_for(self._service_name, self._port)
        name = nse_vuln.output_name(spec, self._scan_ports(), self._mode)
        if self._host and self._host != self._profile.target.ip:
            return f"nmap/{self._host.replace(':', '-')}-{name}"
        return f"nmap/{name}"

    def _services(self) -> list[tuple[int, str]]:
        # the ports of the host being scanned: a pivoted host carries its own service list
        if self._host and self._host != self._profile.target.ip:
            for host in self._profile.discovered_hosts:
                if host.ip == self._host:
                    return [
                        (s.port, s.service)
                        for s in host.services
                        if s.state == "open" and s.proto is self._proto
                    ]
            return [(self._port, self._service_name)]
        return [
            (s.port, s.service)
            for s in self._profile.discovered_services
            if s.state == "open" and s.proto is self._proto
        ]

    def _scan_ports(self) -> list[int]:
        # every open port of this service family on the box, so 139 AND 445 get checked in one pass
        if self._explicit_ports:
            return sorted(set(self._explicit_ports))
        spec = nse_vuln.profile_for(self._service_name, self._port)
        open_ports = [port for port, _ in self._services()]
        return sorted({p for p in open_ports if p in spec.ports} | {self._port})

    def _drive(self) -> VulnScanResult:
        prof = self._profile
        spec = nse_vuln.profile_for(self._service_name, self._port)
        ports = self._scan_ports()
        host = self._host or prof.target.ip
        command = nse_vuln.build_command(
            host, ports, mode=self._mode, profile=spec, proto=self._proto
        )
        out = prof.directory / self.output_rel()
        out.parent.mkdir(parents=True, exist_ok=True)
        where = f" on {host}" if self._host else ""
        self.line.emit(
            f"[scan] vuln checks — {spec.label} on {','.join(str(p) for p in ports)}{where}: "
            f"{spec.why}"
        )
        if self._proto is not Proto.TCP:
            self.line.emit("[warning] a UDP scan (-sU) needs root — without it nmap finds nothing.")
        if spec.dos_note and self._mode != nse_vuln.MODE_SAFE:
            self.line.emit(f"[warning] {spec.dos_note}")
        self.line.emit(f"$ {command}")
        result = shell.run(
            command,
            out,
            cwd=prof.directory,
            cancel=self._cancel,
            on_line=self.line.emit,
            timeout=_TIMEOUT_S,
        )
        scan = VulnScanResult(service=spec.label, port=self._port)
        if result.missing_tool is not None:
            scan.summary.append(f"{result.missing_tool} is not installed — nothing was checked")
            return scan
        if result.blocked is not None:
            scan.summary.append(f"blocked by the recon-only policy: {result.blocked}")
            return scan
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        # attribute HOST scripts (smb-vuln-* carry no port line) to the LOWEST port of the set
        # actually scanned, not to whichever node the operator happened to click — otherwise
        # clicking 139 and then 445 files the same verdict twice under two different ports.
        anchor = ports[0] if ports else self._port
        parsed = run_parser(
            lambda: nse_vuln.parse_vuln_output(text, default_port=anchor, proto=self._proto),
            label=f"nse-vuln {spec.key}",
            on_line=self.line.emit,  # fail-loud: say so when substantial output parses to nothing
            raw=text,
        )
        results = parsed or []
        scan.summary = nse_vuln.summary_lines(results)
        scan.hits = sum(1 for r in results if r.vulnerable)
        scan.checked = len(results)
        if result.exit_code != 0 and not results:
            # a killed / watchdog-timed-out nmap produces no verdicts. Saying "clean" here is the
            # single worst thing this feature could do.
            scan.summary.insert(
                0, f"⚠ nmap exited {result.exit_code} — this scan did NOT complete. Re-run it."
            )
        found = nse_vuln.to_findings(results, spec.key)
        if found:
            now = datetime.now(UTC).isoformat()
            findings.add_findings(
                prof.directory,
                [
                    findings.from_parsed(f.service, f.fields, f.detail, now, port=f.port or 0)
                    for f in found
                ],
            )
        for hit in (r for r in results if r.vulnerable):
            # [vuln] is wired to the error banner — a confirmed verdict has to be impossible to miss
            self.line.emit(f"[vuln] {hit.state}: {hit.script} — {hit.title}")
        run_paths.release(out)
        return scan
