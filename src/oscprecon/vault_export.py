from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from oscprecon import creds as creds_mod
from oscprecon import findings as findings_mod
from oscprecon import references
from oscprecon.models import Credential, DiscoveredService
from oscprecon.profile import Profile

# why: §17 Mode 2 — a snapshot export of the profile into a folder of Obsidian notes
# (frontmatter + wikilinks). It is a point-in-time copy, not live-linked; re-export to refresh.
_SUBDIRS = ("target", "services", "findings", "credentials", "commands", "notes")


def _slug(text: str, fallback: str = "item") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:60] or fallback


def _frontmatter(fields: dict[str, Any]) -> str:
    # why: values carry free-form target-derived text (e.g. nmap version "smbd 4.6.2 (workgroup: X)"
    # embeds ": ") — hand-formatting produced invalid YAML that Obsidian silently drops. safe_dump
    # quotes/escapes every scalar. sort_keys=False keeps our field order; lists render inline.
    body = yaml.safe_dump(
        fields, sort_keys=False, allow_unicode=True, default_flow_style=None
    ).strip()
    return f"---\n{body}\n---"


def _service_note_name(service: DiscoveredService) -> str:
    return f"{service.port}-{service.proto.value}-{_slug(service.service, 'service')}"


def _finding_note_name(finding: dict[str, Any], index: int) -> str:
    module = str(finding.get("module", "")) or "other"
    label = str(finding.get("kind") or finding.get("path") or finding.get("note") or "finding")
    return f"{index:03d}-{module}-{_slug(label, 'finding')}"


def _write(path: Path, body: str) -> None:
    path.write_text(body.rstrip() + "\n", encoding="utf-8")


def _write_index(profile: Profile, root: Path, raw_findings: list[dict[str, Any]]) -> None:
    front = _frontmatter(
        {
            "type": "recon-index",
            "profile": profile.profile_name,
            "target": profile.target.ip,
            "status": profile.status.get("state", "wip"),
            "tags": ["oscp", *profile.tags],
        }
    )
    lines = [
        front,
        "",
        f"# {profile.profile_name} — recon index",
        "",
        "> [!note] Snapshot export — not live-linked. Re-export to refresh.",
        "",
        f"- **Target:** [[{profile.target.ip}]]",
        f"- **Status:** {profile.status.get('state', 'wip')}",
        "",
        "## Services",
    ]
    if profile.discovered_services:
        for service in profile.discovered_services:
            name = _service_note_name(service)
            detail = " ".join(part for part in (service.product, service.version) if part)
            lines.append(f"- [[{name}]] — {service.service} {detail}".rstrip())
    else:
        lines.append("_No services discovered._")
    lines += [
        "",
        f"## Findings ({len(raw_findings)})",
        f"## Credentials ({len(profile.credentials())})",
        f"## Commands ({len(profile.command_history)})",
    ]
    _write(root / "index.md", "\n".join(lines))


def _write_target(profile: Profile, root: Path) -> None:
    target = profile.target
    front = _frontmatter(
        {
            "type": "target",
            "ip": target.ip,
            "hostname": target.hostname or "",
            "platform": target.platform or "",
            "box": target.box_name or "",
            "os": target.os_guess or "",
        }
    )
    services = [f"- [[{_service_note_name(s)}]]" for s in profile.discovered_services]
    body = "\n".join([front, "", f"# {target.ip}", "", "## Services", *services])
    _write(root / "target" / f"{_slug(target.ip, 'target')}.md", body)


def _write_services(profile: Profile, root: Path) -> None:
    rules = references.load_rules()
    for service in profile.discovered_services:
        ref = references.match(service, rules)
        front = _frontmatter(
            {
                "type": "service",
                "port": service.port,
                "proto": service.proto.value,
                "service": service.service,
                "product": service.product or "",
                "version": service.version or "",
            }
        )
        lines = [
            front,
            "",
            f"# {service.port}/{service.proto.value} — {service.service}",
            "",
            f"- **Target:** [[{profile.target.ip}]]",
            f"- **Product:** {service.product or '—'}",
            f"- **Version:** {service.version or '—'}",
        ]
        if ref is not None:
            lines.append(f"- **HackTricks:** [{ref.label}]({ref.hacktricks})")
        _write(root / "services" / f"{_service_note_name(service)}.md", "\n".join(lines))


def _finding_body(finding: dict[str, Any], target_ip: str) -> str:
    front = _frontmatter(
        {
            "type": "finding",
            "module": finding.get("module", ""),
            "kind": finding.get("kind", ""),
            "port": finding.get("port", ""),
            "tags": [str(finding.get("module", "")) or "other"],
        }
    )
    detail_fields = {
        key: finding[key]
        for key in ("value", "detail", "path", "status", "redirect_to", "note", "size")
        if finding.get(key)
    }
    lines = [front, "", f"# {finding.get('module', 'finding')} finding", ""]
    lines += [f"- **{key}:** {value}" for key, value in detail_fields.items()]
    lines += ["", f"Related: [[{target_ip}]]"]
    return "\n".join(lines)


def _write_findings(root: Path, raw_findings: list[dict[str, Any]], target_ip: str) -> None:
    for index, finding in enumerate(raw_findings, start=1):
        name = _finding_note_name(finding, index)
        _write(root / "findings" / f"{name}.md", _finding_body(finding, target_ip))


def _credential_body(cred: Credential) -> str:
    # why: §6 — the secret VALUE is never written out; only its redacted length + provenance.
    front = _frontmatter(
        {
            "type": "credential",
            "username": cred.username,
            "domain": cred.domain,
            "secret_type": cred.secret_type,
            "secret": creds_mod.redact(cred.secret),
        }
    )
    # why: f-string expressions can't contain a backslash on Python 3.11 — build the prefix first.
    domain_prefix = f"{cred.domain}\\" if cred.domain else ""
    lines = [
        front,
        "",
        f"# {domain_prefix}{cred.username}",
        "",
        f"- **Secret:** {creds_mod.redact(cred.secret)}",
        f"- **Source:** {cred.source or '—'}",
        f"- **Tested against:** {', '.join(cred.tested_against) or '—'}",
    ]
    return "\n".join(lines)


def _write_credentials(profile: Profile, root: Path) -> None:
    for index, cred in enumerate(profile.credentials(), start=1):
        name = f"{index:03d}-{_slug(cred.username, 'user')}"
        _write(root / "credentials" / f"{name}.md", _credential_body(cred))


def _write_commands(profile: Profile, root: Path) -> None:
    for command in profile.command_history:
        cmd_id = str(command.get("id", "cmd"))
        front = _frontmatter(
            {
                "type": "command",
                "id": cmd_id,
                "module": command.get("module", ""),
                "exit": command.get("exit_code", ""),
            }
        )
        lines = [
            front,
            "",
            f"# {cmd_id} — {command.get('module', '')}",
            "",
            "```bash",
            str(command.get("shell_line", "")),
            "```",
            "",
            f"- **Exit:** {command.get('exit_code', '')}",
            f"- **Output:** {command.get('output_file', '')}",
            f"- **Started:** {command.get('started_at', '')}",
        ]
        _write(root / "commands" / f"{_slug(cmd_id, 'command')}.md", "\n".join(lines))


def _write_notes(profile: Profile, root: Path) -> None:
    notes = ""
    if profile.notes_path.exists():
        notes = profile.notes_path.read_text(encoding="utf-8").strip()
    started = str(profile.status.get("started_at", ""))[:10] or "notes"
    front = _frontmatter({"type": "notes", "profile": profile.profile_name})
    body = "\n".join([front, "", f"# {profile.profile_name} — notes", "", notes or "_No notes._"])
    _write(root / "notes" / f"{started}-progress.md", body)


def export_vault(profile: Profile, dest_root: Path) -> Path:
    root = Path(dest_root) / profile.profile_name
    for sub in _SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)
    raw_findings = findings_mod.load_findings(profile.directory)
    _write_index(profile, root, raw_findings)
    _write_target(profile, root)
    _write_services(profile, root)
    _write_findings(root, raw_findings, profile.target.ip)
    _write_credentials(profile, root)
    _write_commands(profile, root)
    _write_notes(profile, root)
    return root
