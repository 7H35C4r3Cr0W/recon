from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from oscprecon import creds
from oscprecon.models import (
    Credential,
    DiscoveredHost,
    DiscoveredService,
    Proto,
    Target,
    is_cidr_range,
    subnet_of,
)
from oscprecon.workspace.models import (
    Organization,
    normalize_status,
    normalize_tag,
    normalize_tags,
)

# v2 adds discovered_hosts (the pivot topology). Loading a v1 profile is unchanged — the field
# simply defaults to [] — so no migration is needed and old projects open exactly as before.
SCHEMA_VERSION = 2


# why: scans now run in PARALLEL (several nmap / content-discovery workers at once), so the
# read-modify-write windows in save() / set_services() / add_command() are reachable from more than
# one thread. _atomic_write_json already stops a torn FILE; this closes the lost-update window that
# produces a valid file with a missing service or a duplicated command id.
#
# One module-level RLock rather than a per-Profile field: the critical sections are microseconds,
# the GUI holds one active Profile, and a shared lock keeps a Profile a plain dataclass (no field to
# accidentally persist, copy or compare). Reentrant because set_hostname() -> save().
#
# In-process only. A `nabu-cli scan` running against the same folder as the GUI is still a separate
# process — that is what the `.lock` file (§6b) is for; this is not cross-process safety.
_STATE_LOCK = threading.RLock()


def _atomic_write_json(path: Path, payload: Any) -> None:
    # a per-process-UNIQUE tmp (not a fixed <name>.tmp): two writers — the GUI thread and a running
    # scan worker's orchestrator — sharing one fixed temp interleave bytes and leave a corrupt file
    # behind the atomic replace. mkstemp gives each writer its own temp; os.replace stays atomic.
    # Mirrors findings.add_findings.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2))
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


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
    # the target is required; surface a clear error (not a bare KeyError traceback) if malformed
    ip = str(data.get("ip") or "")
    if not ip:
        raise ValueError("profile.json is corrupt: the target has no 'ip'")
    return Target(
        ip=ip,
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
        "state": service.state,
    }


def _service_from_dict(data: dict[str, Any]) -> DiscoveredService | None:
    # a single malformed/hand-edited service entry must not abort the whole project open — skip it
    try:
        return DiscoveredService(
            port=int(data["port"]),
            proto=Proto(str(data["proto"])),
            service=str(data.get("service", "")),
            product=str(data.get("product", "")),
            version=str(data.get("version", "")),
            nmap_scripts_output=str(data.get("nmap_scripts_output", "")),
            discovered_at=str(data.get("discovered_at", "")),
            state=str(data.get("state", "open")),
        )
    except (KeyError, ValueError, TypeError):
        return None


def _host_to_dict(host: DiscoveredHost) -> dict[str, Any]:
    return {
        "ip": host.ip,
        "hostname": host.hostname,
        "subnet": host.subnet,
        "pivot_source": host.pivot_source,
        "os_guess": host.os_guess,
        "services": [_service_to_dict(s) for s in host.services],
        "discovered_at": host.discovered_at,
        "notes": host.notes,
    }


def _host_from_dict(data: dict[str, Any]) -> DiscoveredHost | None:
    # a malformed pivoted-host entry (bad ip / hostname) must not abort the project open — skip it
    try:
        ip = str(data.get("ip") or "")
        if not ip:
            return None
        services = [s for s in (_service_from_dict(s) for s in data.get("services", [])) if s]
        return DiscoveredHost(
            ip=ip,
            hostname=str(data.get("hostname", "")),
            subnet=str(data.get("subnet", "")),
            pivot_source=str(data.get("pivot_source", "")),
            os_guess=str(data.get("os_guess", "")),
            services=services,
            discovered_at=str(data.get("discovered_at", "")),
            notes=str(data.get("notes", "")),
        )
    except (ValueError, TypeError):
        return None


@dataclass
class Profile:
    directory: Path
    profile_name: str
    target: Target
    status: dict[str, Any] = field(default_factory=dict)
    discovered_services: list[DiscoveredService] = field(default_factory=list)
    discovered_hosts: list[DiscoveredHost] = field(default_factory=list)
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
        path = directory / "profile.json"
        # a corrupt / hand-edited / foreign profile.json (Import Project) must fail with a clear
        # error, not a raw traceback — and every field is coerced defensively, mirroring the
        # per-entry try/except used for services/hosts, so one bad key can't crash the open.
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"{path} is missing or not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"{path} is not a profile object (got {type(raw).__name__})")

        def _list(key: str) -> list[Any]:
            v = raw.get(key)
            return v if isinstance(v, list) else []

        def _map(key: str) -> dict[str, Any]:
            v = raw.get(key)
            return dict(v) if isinstance(v, dict) else {}

        try:
            schema_version = int(raw.get("schema_version", SCHEMA_VERSION))
        except (TypeError, ValueError):
            schema_version = SCHEMA_VERSION
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
            target=_target_from_dict(_map("target")),
            status=_map("status"),
            discovered_services=[
                s
                for s in (_service_from_dict(s) for s in _list("discovered_services"))
                if s is not None
            ],
            discovered_hosts=[
                h for h in (_host_from_dict(h) for h in _list("discovered_hosts")) if h is not None
            ],
            command_history=[dict(c) for c in _list("command_history") if isinstance(c, dict)],
            references_visited=[
                dict(r) for r in _list("references_visited") if isinstance(r, dict)
            ],
            module_settings=_map("module_settings"),
            tags=list(org.tags),  # mirror of organization.tags (the authoritative store)
            organization=org.to_dict(),
            schema_version=schema_version,
        )

    def _ensure_writable(self) -> None:
        if self.read_only:
            raise ReadOnlyError(f"profile '{self.profile_name}' is open read-only")

    def save(self) -> None:
        self._ensure_writable()
        with _STATE_LOCK:
            self._save_locked()

    def _save_locked(self) -> None:
        payload: dict[str, Any] = {
            # always persist the CURRENT code schema — a v1 file that gains v2 content (hosts)
            # must not keep lying that it is still version 1.
            "schema_version": SCHEMA_VERSION,
            "profile_name": self.profile_name,
            "target": _target_to_dict(self.target),
            "status": self.status,
            "discovered_services": [_service_to_dict(s) for s in self.discovered_services],
            "discovered_hosts": [_host_to_dict(h) for h in self.discovered_hosts],
            "command_history": self.command_history,
            "references_visited": self.references_visited,
            "user_notes_path": "notes.md",
            "module_settings": self.module_settings,
            "tags": self.tags,
            "organization": Organization.from_dict(self.organization).to_dict(),
        }
        # why: a concurrent read (or a crash mid-write) must never see a half-written profile.json,
        # and two concurrent writers (GUI thread + scan worker) must not share a temp — write a
        # per-writer unique sibling temp then atomically replace.
        _atomic_write_json(self.profile_json_path, payload)

    def set_services(self, services: list[DiscoveredService]) -> None:
        self._ensure_writable()  # never mutate in-memory state on a read-only profile [#43]
        with _STATE_LOCK:
            self.discovered_services = services
            self.touch()

    def merge_services(self, services: list[DiscoveredService]) -> None:
        # union by (port, proto) instead of replace — with scans running in parallel, a narrow scan
        # finishing after a broad one must ADD to discovery, never truncate it back to its own view.
        # Same rule the custom-scan path has always used (nmap_scan.merge_services).
        from oscprecon import nmap_scan  # local import: nmap_scan imports models, not profile

        self._ensure_writable()
        with _STATE_LOCK:
            self.discovered_services = nmap_scan.merge_services(self.discovered_services, services)
            self.touch()

    def next_command_id(self) -> str:
        # unique across re-scans AND across concurrent workers — read the length and mint under the
        # same lock the append takes, so two workers can't both mint cmd-014.
        with _STATE_LOCK:
            return f"cmd-{len(self.command_history) + 1:03d}"

    def add_hosts(self, hosts: list[DiscoveredHost]) -> int:
        # Upsert pivoted hosts by ip: a re-scan of the same host updates its services / os / pivot
        # source in place rather than creating a duplicate node. The entry Target is never added
        # here (it stays the profile's primary target). Returns the number of NEW hosts added.
        self._ensure_writable()  # [#43]
        with _STATE_LOCK:
            return self._add_hosts_locked(hosts)

    def _add_hosts_locked(self, hosts: list[DiscoveredHost]) -> int:
        by_ip = {h.ip: h for h in self.discovered_hosts}
        added = 0
        for host in hosts:
            if host.ip == self.target.ip:
                continue  # the entry host is the Target, not a discovered_host
            if not host.discovered_at:
                host.discovered_at = _now_iso()
            if not host.subnet:
                host.subnet = subnet_of(host.ip)
            existing = by_ip.get(host.ip)
            if existing is None:
                self.discovered_hosts.append(host)
                by_ip[host.ip] = host
                added += 1
            else:
                # intentional (#19): an empty service list is treated as "no new data", NOT "the
                # host has no open ports". A pivoted re-scan that momentarily returns nothing (a
                # flaky tunnel, a filtered sweep) must not wipe the ports an earlier scan found —
                # keeping the prior services is the safe default. Use remove_host to clear a host.
                if host.services:
                    existing.services = host.services
                if host.hostname:
                    existing.hostname = host.hostname
                if host.os_guess:
                    existing.os_guess = host.os_guess
                if host.pivot_source:
                    existing.pivot_source = host.pivot_source
        self.touch()
        return added

    def known_host_ips(self) -> list[str]:
        # every host the topology knows about — the entry Target plus discovered hosts. Used to
        # offer a pivot-source picker when importing a new subnet.
        return [self.target.ip, *(h.ip for h in self.discovered_hosts)]

    def remove_host(self, ip: str) -> bool:
        # drop one pivoted host from the topology. A deeper host reached VIA this one keeps its
        # pivot_source string, but the graph simply omits the now-dangling pivot edge — no crash.
        self._ensure_writable()  # [#43]
        before = len(self.discovered_hosts)
        self.discovered_hosts = [h for h in self.discovered_hosts if h.ip != ip]
        if len(self.discovered_hosts) == before:
            return False
        # persist profile.json FIRST, then prune graph.json: if the profile write fails we raise
        # before deleting the host's graph overrides, so the two files can't diverge (host gone from
        # graph but still in profile, losing its overrides on the next reload). [#43]
        self.touch()
        self.save()
        self._prune_graph_for_hosts([ip])
        return True

    def remove_subnet(self, subnet: str) -> int:
        # drop a whole /24 (every host in it) from the topology. Returns the number removed.
        self._ensure_writable()  # [#43]

        def in_subnet(h: DiscoveredHost) -> bool:
            return (h.subnet or subnet_of(h.ip)) == subnet

        removed_ips = [h.ip for h in self.discovered_hosts if in_subnet(h)]
        self.discovered_hosts = [h for h in self.discovered_hosts if not in_subnet(h)]
        if removed_ips:
            self.touch()
            self.save()  # profile.json before graph.json prune (see remove_host) [#43]
            self._prune_graph_for_hosts(removed_ips)
        return len(removed_ips)

    def _prune_graph_for_hosts(self, ips: list[str]) -> None:
        # drop graph.json overrides (status / note / position) + user-edges tied to removed hosts,
        # so re-scanning the same range doesn't resurrect a host pre-marked with stale state, and
        # orphan overrides don't pile up. Node ids: host-<ip>, hostservice-<ip>-*, subnet-<cidr>.
        if not ips or self.read_only:
            return
        graph = self.load_graph()
        dead = {f"host-{ip}" for ip in ips}
        hs_prefixes = tuple(f"hostservice-{ip}-" for ip in ips)
        live_subnets = {f"subnet-{h.subnet}" for h in self.discovered_hosts if h.subnet}
        overrides = graph.get("node_overrides", {})
        changed = False
        if isinstance(overrides, dict):
            for key in list(overrides):
                gone = (
                    key in dead
                    or key.startswith(hs_prefixes)
                    or (key.startswith("subnet-") and key not in live_subnets)
                )
                if gone:
                    del overrides[key]
                    changed = True
        edges = graph.get("user_edges", [])
        if isinstance(edges, list):
            kept = [
                e
                for e in edges
                if not (
                    isinstance(e, dict)
                    and (
                        str(e.get("from", "")) in dead
                        or str(e.get("to", "")) in dead
                        or str(e.get("from", "")).startswith(hs_prefixes)
                        or str(e.get("to", "")).startswith(hs_prefixes)
                    )
                )
            ]
            if len(kept) != len(edges):
                graph["user_edges"] = kept
                changed = True
        if changed:
            self.save_graph(graph)

    def rename(self, new_name: str) -> Path:
        # Move <workspace>/<old>/ -> <workspace>/<new>/. The rename is atomic on one filesystem and
        # carries EVERYTHING inside with it — profile.json, creds.json, graph.json, notes.md, the
        # nmap/ output tree, the audit log, AND the .lock we hold (so the caller must re-point its
        # locked-dir at the new path). Refuses an empty/path-bearing name or existing destination.
        self._ensure_writable()
        cleaned = new_name.strip()
        if not cleaned:
            raise ValueError("project name cannot be empty")
        if cleaned == self.profile_name:
            return self.directory  # no-op — nothing to move
        if "/" in cleaned or "\\" in cleaned or cleaned.startswith(".") or cleaned in (".", ".."):
            raise ValueError(f"invalid project name: {new_name!r}")
        new_dir = self.directory.parent / cleaned
        if new_dir.exists():
            raise FileExistsError(f"a project named '{cleaned}' already exists")
        self.directory.rename(new_dir)
        self.directory = new_dir
        self.profile_name = cleaned
        self.save()
        return new_dir

    def set_target(self, ip: str, hostname: str | None = None) -> None:
        # change the target IP/hostname, or convert to/from a whole /24 range project. Target's
        # __post_init__ validates (rejects injection / a malformed CIDR). A range has no vhost
        # name, so a hostname is dropped when the new target is a network.
        self._ensure_writable()
        cleaned_ip = ip.strip()
        cleaned_host = (hostname or "").strip() or None
        if is_cidr_range(cleaned_ip):
            cleaned_host = None
        self.target = replace(self.target, ip=cleaned_ip, hostname=cleaned_host)
        self.save()

    def set_hostname(self, hostname: str | None) -> None:
        # the vhost name is usually learned AFTER the first scan (a redirect, a cert CN, a contact
        # email) — let it be set later; host-based recon then targets the name instead of the IP.
        self._ensure_writable()  # never mutate in-memory state on a read-only profile [#43]
        cleaned = (hostname or "").strip() or None
        self.target = replace(self.target, hostname=cleaned)  # Target is frozen — replace + resave
        self.save()

    def add_command(self, record: dict[str, Any]) -> None:
        with _STATE_LOCK:
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

    def set_credentials(self, credentials: list[Credential]) -> None:
        # why: bulk write-all for in-place updates (e.g. recording a confirmed spray into
        # tested_against) — the dedup key ignores tested_against, so add_credential can't update it.
        self._ensure_writable()
        creds.save_creds(self.creds_path, credentials)

    def replace_credential(self, current: Credential, updated: Credential) -> None:
        # in-place edit as a SINGLE atomic write (never delete-then-add, which loses the credential
        # if the second write fails [#12] and silently drops a row when the edit collides with a
        # different entry [#37]). Preserve order; on a collision `updated` wins and the dup goes.
        self._ensure_writable()
        old_key = creds.cred_key(current)
        new_key = creds.cred_key(updated)
        out: list[Credential] = []
        replaced = False
        for cred in self.credentials():
            key = creds.cred_key(cred)
            if not replaced and key == old_key:
                out.append(updated)
                replaced = True
            elif key == new_key and key != old_key:
                continue  # a different entry the edit now collides with — drop it, `updated` wins
            else:
                out.append(cred)
        if not replaced:
            out.append(updated)
        creds.save_creds(self.creds_path, out)

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
        # why: mirror profile.json's atomic write (unique temp) — a crash mid-write or a concurrent
        # writer must not corrupt graph.json.
        _atomic_write_json(self.graph_path, data)

    def add_reference_visited(self, service: str, url: str) -> None:
        if any(entry.get("url") == url for entry in self.references_visited):
            return
        self.references_visited.append({"service": service, "url": url, "visited_at": _now_iso()})
        self.touch()
