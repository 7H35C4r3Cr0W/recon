from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oscprecon import creds
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.workspace.models import (
    Organization,
    normalize_status,
    normalize_tag,
    normalize_tags,
)

SCHEMA_VERSION = 1


class ReadOnlyError(RuntimeError):
    """Raised when a write is attempted on a profile opened read-only (lock held elsewhere)."""


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


def _ensure_service_dirs(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for sub in SERVICE_DIRS:
        (directory / sub).mkdir(exist_ok=True)


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
    organization: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION
    read_only: bool = False  # runtime-only (never persisted): true when the lock is held elsewhere

    @property
    def profile_json_path(self) -> Path:
        return self.directory / "profile.json"

    @property
    def notes_path(self) -> Path:
        return self.directory / "notes.md"

    @classmethod
    def create(cls, workspace_root: Path, name: str, target: Target) -> Profile:
        directory = Path(workspace_root) / name
        _ensure_service_dirs(directory)
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
        _ensure_service_dirs(directory)
        raw: dict[str, Any] = json.loads((directory / "profile.json").read_text(encoding="utf-8"))
        # normalize organization on load (safe defaults for old/hand-edited profiles). Tags have ONE
        # source of truth: organization.tags. Seed it from the legacy top-level `tags` on first load
        # so pre-feature tags survive + still reach the report/Obsidian frontmatter, which reads
        # profile.tags — kept mirrored to organization.tags below.
        org = Organization.from_dict(raw.get("organization"))
        if not org.tags:
            org.tags = normalize_tags(raw.get("tags"))
        return cls(
            directory=directory,
            profile_name=str(raw.get("profile_name", directory.name)),
            target=_target_from_dict(raw.get("target", {})),
            status=dict(raw.get("status", {})),
            discovered_services=[_service_from_dict(s) for s in raw.get("discovered_services", [])],
            command_history=[dict(c) for c in raw.get("command_history", [])],
            references_visited=[dict(r) for r in raw.get("references_visited", [])],
            module_settings=dict(raw.get("module_settings", {})),
            tags=list(org.tags),  # mirror of organization.tags (the authoritative store)
            organization=org.to_dict(),
            schema_version=int(raw.get("schema_version", SCHEMA_VERSION)),
        )

    def _ensure_writable(self) -> None:
        if self.read_only:
            raise ReadOnlyError(f"profile '{self.profile_name}' is open read-only")

    def save(self) -> None:
        self._ensure_writable()
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
            "organization": Organization.from_dict(self.organization).to_dict(),
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

    def mark_opened(self) -> None:
        self.status["last_opened_at"] = _now_iso()

    # --- workspace organization metadata (status / tags / pinned / archived / display name) ---
    def organization_meta(self) -> Organization:
        return Organization.from_dict(self.organization)

    def _save_organization(self, org: Organization) -> None:
        # round-trip through from_dict so the persisted value is fully normalized (status validated,
        # tags deduped, display name trimmed/capped); never carries secrets.
        normalized = Organization.from_dict(org.to_dict())
        self.organization = normalized.to_dict()
        self.tags = list(normalized.tags)  # keep the report/Obsidian tag mirror in sync
        self.save()

    def set_status(self, status: str) -> None:
        org = self.organization_meta()
        org.status = normalize_status(status)
        self._save_organization(org)

    def set_display_name(self, name: str) -> None:
        org = self.organization_meta()
        org.display_name = name
        self._save_organization(org)

    def set_pinned(self, pinned: bool) -> None:
        org = self.organization_meta()
        org.pinned = bool(pinned)
        self._save_organization(org)

    def set_archived(self, archived: bool) -> None:
        org = self.organization_meta()
        org.archived = bool(archived)
        self._save_organization(org)

    def add_tag(self, tag: str) -> bool:
        normalized = normalize_tag(tag)
        if normalized is None:
            return False
        org = self.organization_meta()
        if any(t.lower() == normalized.lower() for t in org.tags):
            return False  # already present (case-insensitive) — no duplicate, no write
        org.tags.append(normalized)
        self._save_organization(org)
        return True

    def remove_tag(self, tag: str) -> bool:
        org = self.organization_meta()
        kept = [t for t in org.tags if t.lower() != str(tag).strip().lower()]
        if len(kept) == len(org.tags):
            return False
        org.tags = kept
        self._save_organization(org)
        return True

    def set_tags(self, tags: list[str]) -> None:
        org = self.organization_meta()
        org.tags = tags
        self._save_organization(org)

    @property
    def creds_path(self) -> Path:
        return self.directory / "creds.json"

    def credentials(self) -> list[Credential]:
        return creds.load_creds(self.creds_path)

    def add_credential(self, cred: Credential) -> None:
        self._ensure_writable()
        creds.add_credential(self.creds_path, cred)

    def delete_credential(self, cred: Credential) -> None:
        self._ensure_writable()
        creds.delete_credential(self.creds_path, cred)

    @property
    def graph_path(self) -> Path:
        return self.directory / "graph.json"

    def load_graph(self) -> dict[str, Any]:
        try:
            data = json.loads(self.graph_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = None
        if not isinstance(data, dict):
            data = {}
        # coerce, not just setdefault: the GraphBridge write path indexes these directly, so a
        # present-but-wrong-typed value (hand-edited graph.json) must not survive into a mutation.
        if not isinstance(data.get("user_edges"), list):
            data["user_edges"] = []
        if not isinstance(data.get("node_overrides"), dict):
            data["node_overrides"] = {}
        return data

    def save_graph(self, data: dict[str, Any]) -> None:
        self._ensure_writable()
        # why: mirror profile.json's atomic write — a crash mid-write must not corrupt graph.json.
        tmp = self.directory / "graph.json.tmp"
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.graph_path)

    def add_reference_visited(self, service: str, url: str) -> None:
        if any(entry.get("url") == url for entry in self.references_visited):
            return
        self.references_visited.append({"service": service, "url": url, "visited_at": _now_iso()})
        self.touch()
