from __future__ import annotations

import threading
from collections.abc import Callable

from oscprecon import shell
from oscprecon.models import Command, Port, Proto
from oscprecon.modules.http import HTTP_SERVICE_NAMES
from oscprecon.modules.http.parsers import detect_api_server
from oscprecon.modules.nmap import (
    NmapModule,
    cert_hostnames,
    redirect_vhosts,
    robots_disclosures,
)
from oscprecon.profile import Profile
from oscprecon.reporter import Reporter


def _nmap_saw_open_ports(raw: dict[str, str]) -> bool:
    # nmap prints "22/tcp open ssh"; if any output has an open-port line, 0 parsed services is drift
    return any("open" in text and ("/tcp" in text or "/udp" in text) for text in raw.values())


class Orchestrator:
    def __init__(
        self,
        profile: Profile,
        *,
        on_line: Callable[[str], None] | None = None,
        udp_full: bool = False,
        scan_profile: str = "default",
        resume: bool = False,
        force: bool = False,
        cancel: threading.Event | None = None,
    ) -> None:
        self.profile = profile
        self.on_line = on_line
        self.nmap = NmapModule(udp_full=udp_full, scan_profile=scan_profile)
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
        # command ids are minted by Profile.next_command_id() under the profile lock: they must stay
        # unique across re-scans (command_history persists) AND across workers running in parallel.

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
        self.profile.add_command(
            {
                "id": self.profile.next_command_id(),
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

    def _handle_hostname_leads(self, raw: dict[str, str]) -> None:
        # a box's real hostname/vhost — the host-based-recon prerequisite the bare IP won't serve —
        # is declared by the server two strong ways: an http→name redirect (nmap http-title) and the
        # TLS cert's Subject CN / SAN (nmap ssl-cert). If none is set yet and there's a single clear
        # candidate, wire it in (announced, never silent); surface every other name as a vhost lead.
        # A user-set hostname is never overridden. The redirect keeps its exact old behavior
        # (auto-set on a lone redirect); the cert only auto-sets when there is no redirect.
        redirect = redirect_vhosts(raw)
        cert = cert_hostnames(raw)
        if not redirect and not cert:
            return
        if self.profile.target.hostname is None:
            primary, source = None, ""
            if len(redirect) == 1:
                primary, source = redirect[0], "the nmap redirect"
            elif not redirect and cert:
                primary, source = cert[0], "the SSL certificate"  # cert[0] is the Subject CN
            if primary is not None:
                try:
                    self.profile.set_hostname(primary)
                except ValueError:
                    pass  # malformed (both sources are filtered, so unreachable) — leads still fire
                else:
                    self._emit(
                        f"[vhost] set target hostname = {primary} (from {source}) — host-based "
                        "recon now targets it. Add to /etc/hosts; change via Edit -> Set Hostname."
                    )
        current = self.profile.target.hostname
        seen: set[str] = set()
        for host in redirect:
            if host != current and host not in seen:
                seen.add(host)
                self._emit(
                    f"[vhost] nmap redirects to '{host}' — add to /etc/hosts and Set Target "
                    "Hostname to recon it as a vhost."
                )
        for host in cert:
            if host != current and host not in seen:
                seen.add(host)
                self._emit(
                    f"[vhost] SSL certificate names '{host}' — add to /etc/hosts and Set Target "
                    "Hostname to recon it as a vhost."
                )

    def _handle_nse_leads(self, raw: dict[str, str]) -> None:
        # surface high-value leads nmap's -sC NSE scripts revealed for free, the moment the scan
        # lands (mirrors _handle_hostname_leads): robots.txt disallowed entries = paths an admin
        # hid; a uvicorn / FastAPI / application-json banner = a JSON API to enumerate by schema.
        for path in robots_disclosures(raw):
            self._emit(
                f"[robots] nmap's robots.txt discloses '{path}' — admins hide admin panels, "
                "backups and sensitive endpoints there; investigate it (curl it, feed it to "
                "content discovery)."
            )
        # only nudge about an API when an HTTP service was actually found — else a marker appearing
        # elsewhere in the cross-service scan (an SMB "Computer name: DAPHNE", a cert CN) would emit
        # a JSON-API tip on a box with no web server at all.
        has_http = any(
            s.service.lower() in HTTP_SERVICE_NAMES for s in self.profile.discovered_services
        )
        if has_http and detect_api_server("\n".join(raw.values())):
            self._emit(
                "[api] the web server looks like a JSON API (uvicorn / FastAPI / application-json) "
                "— enumerate the API schema, not files: curl /openapi.json /docs /redoc "
                "/swagger.json /api/v1 (they list every route + parameter)."
            )

    def run_nmap(self) -> None:
        target = self.profile.target
        raw: dict[str, str] = {}

        for cmd in self.nmap.commands(target, []):
            if self._cancelled():
                break
            raw[cmd.output_file] = self._run(cmd)
        self.profile.merge_services(self.nmap.discovered_services(raw))
        # fail-loud: nmap reported open ports but the parser extracted none -> format drift, not an
        # empty host. Silently ending up with 0 services would break everything downstream, quietly.
        if not self.profile.discovered_services and _nmap_saw_open_ports(raw):
            self._emit("⚠ [parse] nmap ran but 0 services parsed — check the scan output (drift?)")
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
                if self._cancelled():
                    break
                raw[cmd.output_file] = self._run(cmd)
            self.profile.merge_services(self.nmap.discovered_services(raw))
            self.profile.save()

        # why: the slow full UDP sweep (`full` profile / --udp-full opt-in) runs LAST — after the
        # versioned TCP scan — so it never blocks the high-value service versions and can be
        # cancelled once those have landed.
        if not self._cancelled():
            deferred = self.nmap.deferred_commands(target)
            if deferred:
                for cmd in deferred:
                    if self._cancelled():
                        break
                    raw[cmd.output_file] = self._run(cmd)
                self.profile.merge_services(self.nmap.discovered_services(raw))
                self.profile.save()

        self._handle_hostname_leads(raw)
        self._handle_nse_leads(raw)

        Reporter(self.profile).write()
        count = len(self.profile.discovered_services)
        self._emit(f"[done] {count} services — report: {self.profile.directory / 'report.md'}")
        if count == 0 and not _nmap_saw_open_ports(raw):
            self._emit(
                "[hint] no open ports found — the host may be down or filtered. Confirm the VPN "
                "is up and the target IP is current, or retry with --scan-profile full."
            )
