from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from oscprecon import findings as findings_mod
from oscprecon import references
from oscprecon.patterns.engine import suggest_for
from oscprecon.profile import Profile

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _now_stamp() -> str:
    # why: microseconds keep two writes in the same second from overwriting each other's archive.
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")


def _finding_line(finding: dict[str, Any]) -> str:
    # why: findings.json carries two shapes — most modules use kind/value/detail (+snmp note);
    # http/vhost use port/path/status/note. Render each into one readable Obsidian bullet.
    kind = str(finding.get("kind", "")).strip()
    if kind:
        value = str(finding.get("value", "")).strip()
        extra = " · ".join(
            part
            for part in (
                str(finding.get("detail", "")).strip(),
                str(finding.get("note", "")).strip(),
            )
            if part
        )
        head = f"**{kind}** — {value}" if value else f"**{kind}**"
        return f"{head} ({extra})" if extra else head
    parts: list[str] = []
    path = str(finding.get("path", "")).strip()
    if path:
        parts.append(f"`{path}`")
    status = finding.get("status")
    if status:
        parts.append(f"→ {status}")
    redirect = str(finding.get("redirect_to", "")).strip()
    if redirect:
        parts.append(f"⇒ {redirect}")
    note = str(finding.get("note", "")).strip()
    if note:
        parts.append(note)
    port = finding.get("port")
    prefix = f"[{port}] " if port else ""
    return (prefix + " ".join(parts)).strip() or "(finding)"


def _group_findings(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    for finding in raw:
        module = str(finding.get("module", "")).strip() or "other"
        groups.setdefault(module, []).append(_finding_line(finding))
    return [{"module": module, "lines": groups[module]} for module in sorted(groups)]


class Reporter:
    def __init__(self, profile: Profile) -> None:
        self.profile = profile
        self.env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def _context(self) -> dict[str, Any]:
        profile = self.profile
        rules = references.load_rules()
        services = []
        for service in profile.discovered_services:
            ref = references.match(service, rules)
            services.append(
                {
                    "port": service.port,
                    "proto": service.proto.value,
                    "service": service.service,
                    "product": service.product,
                    "version": service.version,
                    "hacktricks": ref.hacktricks if ref else "",
                    "label": ref.label if ref else "",
                }
            )
        notes = ""
        if profile.notes_path.exists():
            notes = profile.notes_path.read_text(encoding="utf-8").strip()
        raw_findings = findings_mod.load_findings(profile.directory)
        suggestions = suggest_for(
            raw_findings,
            target=profile.target.ip,
            domain=profile.target.hostname or "",
            has_credential=bool(profile.credentials()),
        )
        return {
            "profile_name": profile.profile_name,
            "target": {
                "ip": profile.target.ip,
                "hostname": profile.target.hostname,
                "platform": profile.target.platform,
                "box_name": profile.target.box_name,
            },
            "status": profile.status,
            "services": services,
            "finding_groups": _group_findings(raw_findings),
            "command_history": profile.command_history,
            "tags": profile.tags,
            "notes": notes,
            "suggestions": [
                {
                    "text": s.text,
                    "command": s.command_template,
                    "source_pattern": s.source_pattern,
                    "source_box": s.source_box,
                }
                for s in suggestions
            ],
        }

    def render(self) -> str:
        return self.env.get_template("report.md.j2").render(**self._context())

    def write(self) -> Path:
        report_path = self.profile.directory / "report.md"
        if report_path.exists():
            archive_dir = self.profile.directory / "report-archive"
            archive_dir.mkdir(exist_ok=True)
            (archive_dir / f"report-{_now_stamp()}.md").write_text(
                report_path.read_text(encoding="utf-8"), encoding="utf-8"
            )
        report_path.write_text(self.render(), encoding="utf-8")
        return report_path
