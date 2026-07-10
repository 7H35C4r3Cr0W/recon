from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oscprecon import creds
from oscprecon.models import Credential, DiscoveredService, Proto, Target

SCHEMA_VERSION = 1

SERVICE_DIRS = [
    "nmap",
    "http",
    "vhost",
    "ftp",
    "ssh",
    "dns",
    "ldap",
    "smtp",
    "nfs",
    "snmp",
    "tftp",
    "netbios",
    "ike",
    "ntp",
    "smb",
    "references",
    "manual",
    "report-archive",
]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _target_to_dict(target: Target) -> dict[str, str | None]:
    return {
        "ip": target.ip,
        "hostname": target.hostname,
        "platform": target.platform,
        "box_name": target.box_name,
        "os_guess": target.os_guess,
    }


def _target_from_dict(data: dict[str, Any]) -> Target:
    return Target(
        ip=str(data["ip"]),
        hostname=data.get("hostname"),
        platform=data.get("platform"),
        box_name=data.get("box_name"),
        os_guess=data.get("os_guess"),
    )


def _service_to_dict(service: DiscoveredService) -> dict[str, Any]:
    return {
        "port": service.port,
        "proto": service.proto.value,
        "service": service.service,
        "product": service.product,
        "version": service.version,
        "nmap_scripts_output": service.nmap_scripts_output,
        "discovered_at": service.discovered_at,
    }


def _service_from_dict(data: dict[str, Any]) -> DiscoveredService:
    return DiscoveredService(
        port=int(data["port"]),
        proto=Proto(str(data["proto"])),
        service=str(data.get("service", "")),
        product=str(data.get("product", "")),
        version=str(data.get("version", "")),
        nmap_scripts_output=str(data.get("nmap_scripts_output", "")),
        discovered_at=str(data.get("discovered_at", "")),
    )


@dataclass
class Profile:
    directory: Path
    profile_name: str
    target: Target
    status: dict[str, Any] = field(default_factory=dict)
    discovered_services: list[DiscoveredService] = field(default_factory=list)
    command_history: list[dict[str, Any]] = field(default_factory=list)
    references_visited: list[dict[str, Any]] = field(default_factory=list)
    module_settings: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    @property
    def profile_json_path(self) -> Path:
        return self.directory / "profile.json"

    @property
    def notes_path(self) -> Path:
        return self.directory / "notes.md"

    @classmethod
    def create(cls, workspace_root: Path, name: str, target: Target) -> Profile:
        directory = Path(workspace_root) / name
        directory.mkdir(parents=True, exist_ok=True)
        for sub in SERVICE_DIRS:
            (directory / sub).mkdir(exist_ok=True)
        now = _now_iso()
        profile = cls(
            directory=directory,
            profile_name=name,
            target=target,
            status={"state": "wip", "started_at": now, "rooted_at": None, "last_active": now},
        )
        if not profile.notes_path.exists():
            profile.notes_path.write_text(f"# {name} — notes\n\n", encoding="utf-8")
        profile.save()
        return profile

    @classmethod
    def load(cls, directory: Path) -> Profile:
        directory = Path(directory)
        raw: dict[str, Any] = json.loads((directory / "profile.json").read_text(encoding="utf-8"))
        return cls(
            directory=directory,
            profile_name=str(raw.get("profile_name", directory.name)),
            target=_target_from_dict(raw.get("target", {})),
            status=dict(raw.get("status", {})),
            discovered_services=[_service_from_dict(s) for s in raw.get("discovered_services", [])],
            command_history=[dict(c) for c in raw.get("command_history", [])],
            references_visited=[dict(r) for r in raw.get("references_visited", [])],
            module_settings=dict(raw.get("module_settings", {})),
            tags=[str(t) for t in raw.get("tags", [])],
            schema_version=int(raw.get("schema_version", SCHEMA_VERSION)),
        )

    def save(self) -> None:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "profile_name": self.profile_name,
            "target": _target_to_dict(self.target),
            "status": self.status,
            "discovered_services": [_service_to_dict(s) for s in self.discovered_services],
            "command_history": self.command_history,
            "references_visited": self.references_visited,
            "user_notes_path": "notes.md",
            "module_settings": self.module_settings,
            "tags": self.tags,
        }
        # why: a concurrent read (or a crash mid-write) must never see a half-written
        # profile.json — write a sibling temp then atomically replace.
        tmp = self.directory / "profile.json.tmp"
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.profile_json_path)

    def set_services(self, services: list[DiscoveredService]) -> None:
        self.discovered_services = services
        self.touch()

    def add_command(self, record: dict[str, Any]) -> None:
        self.command_history.append(record)
        self.touch()

    def touch(self) -> None:
        self.status["last_active"] = _now_iso()

    @property
    def creds_path(self) -> Path:
        return self.directory / "creds.json"

    def credentials(self) -> list[Credential]:
        return creds.load_creds(self.creds_path)

    def add_credential(self, cred: Credential) -> None:
        creds.add_credential(self.creds_path, cred)

    def add_reference_visited(self, service: str, url: str) -> None:
        if any(entry.get("url") == url for entry in self.references_visited):
            return
        self.references_visited.append({"service": service, "url": url, "visited_at": _now_iso()})
        self.touch()
