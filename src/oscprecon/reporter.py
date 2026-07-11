from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from oscprecon import findings as findings_mod
from oscprecon.patterns.engine import suggest_for
from oscprecon.profile import Profile

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _now_stamp() -> str:
    # why: microseconds keep two writes in the same second from overwriting each other's archive.
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")


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
        services = [
            {
                "port": service.port,
                "proto": service.proto.value,
                "service": service.service,
                "product": service.product,
                "version": service.version,
            }
            for service in profile.discovered_services
        ]
        notes = ""
        if profile.notes_path.exists():
            notes = profile.notes_path.read_text(encoding="utf-8").strip()
        suggestions = suggest_for(
            findings_mod.load_findings(profile.directory),
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
