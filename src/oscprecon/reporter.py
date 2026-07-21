from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from oscprecon import audit, references, shell
from oscprecon import edb as edb_mod
from oscprecon import findings as findings_mod
from oscprecon.graph_data import build_elements
from oscprecon.models import DiscoveredHost
from oscprecon.patterns.engine import suggest_for
from oscprecon.profile import Profile

# why: §6a — the report's Audit-trail appendix shows the most recent events; older ones stay in
# audit.jsonl (and audit-archive/). Cap keeps the report readable on a long engagement.
_AUDIT_CAP = 200

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _now_stamp() -> str:
    # why: microseconds keep two writes in the same second from overwriting each other's archive.
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")


def _inline(value: object) -> str:
    # why: a finding field can carry an embedded newline (a pasted banner / crafted value); left in,
    # it starts a new markdown line in report.md — injecting a real `## heading` / `- list`.
    # Collapse CR/LF to spaces so the whole field stays on the one bullet it belongs to.
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def _finding_line(finding: dict[str, Any]) -> str:
    # why: findings.json carries two shapes — most modules use kind/value/detail (+snmp note);
    # http/vhost use port/path/status/note. Render each into one readable Obsidian bullet.
    kind = _inline(finding.get("kind", ""))
    if kind:
        value = _inline(finding.get("value", ""))
        extra = " · ".join(
            part
            for part in (_inline(finding.get("detail", "")), _inline(finding.get("note", "")))
            if part
        )
        head = f"**{kind}** — {value}" if value else f"**{kind}**"
        return f"{head} ({extra})" if extra else head
    parts: list[str] = []
    path = _inline(finding.get("path", ""))
    if path:
        parts.append(f"`{path}`")
    status = finding.get("status")
    if status:
        parts.append(f"→ {status}")
    redirect = _inline(finding.get("redirect_to", ""))
    if redirect:
        parts.append(f"⇒ {redirect}")
    note = _inline(finding.get("note", ""))
    if note:
        parts.append(note)
    port = finding.get("port")
    prefix = f"[{port}] " if port else ""
    return (prefix + " ".join(parts)).strip() or "(finding)"


def _audit_summary(details: dict[str, Any]) -> str:
    # why: keep the markdown table intact — collapse CR/LF (a pasted multi-line value would break
    # the row and inject raw markdown into report.md), escape pipes, and bound each value.
    parts = []
    for key, value in details.items():
        text = str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
        if len(text) > 60:
            text = text[:57] + "…"
        parts.append(f"{key}={text}")
    return ", ".join(parts)


def _group_findings(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    for finding in raw:
        module = str(finding.get("module", "")).strip() or "other"
        groups.setdefault(module, []).append(_finding_line(finding))
    return [{"module": module, "lines": groups[module]} for module in sorted(groups)]


def _redacted_history(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # scrub any credential embedded in a logged command before it reaches the report's command log,
    # matching the audit layer (§6/§18). Today command_history holds only Tier-1 recon commands, but
    # a future writer that records a credentialed command must not leak it verbatim into report.md.
    out: list[dict[str, Any]] = []
    for entry in history:
        line = entry.get("shell_line")
        if isinstance(line, str) and line:
            entry = {**entry, "shell_line": shell.redact_command(line)}
        out.append(entry)
    return out


def _group_edb(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # group EDB references by service (first-seen order), dedup EDB-IDs within each service.
    groups: dict[str, list[dict[str, str]]] = {}
    seen: dict[str, set[str]] = {}
    for entry in raw:
        service = str(entry.get("service", "")).strip() or "unknown"
        edb_id = str(entry.get("edb_id", "")).strip()
        if not edb_id or edb_id in seen.setdefault(service, set()):
            continue
        seen[service].add(edb_id)
        badge = "·".join(
            part
            for part in (str(entry.get("type", "")), str(entry.get("platform", "")))
            if part.strip()
        )
        groups.setdefault(service, []).append(
            {
                "edb_id": edb_id,
                "title": str(entry.get("title", "")),
                "url": str(entry.get("url", "")),
                "badge": badge,
                "cve": str(entry.get("cve", "")),
            }
        )
    return [{"service": service, "hits": groups[service]} for service in groups]


def _graph_notes(profile: Profile) -> list[dict[str, str]]:
    # graph node annotations (graph.json node_overrides[*].note) surfaced in the report — the graph
    # detail panel promises "saved to graph.json, shown in the report", so a note you drop on a node
    # lands here. Uses the same build_elements() the graph renders, so labels never disagree.
    try:
        elements = build_elements(profile)
    except Exception:  # boundary: a bad graph/profile must never break report generation
        return []
    out: list[dict[str, str]] = []
    for node in elements.get("nodes", []):
        data = node.get("data", {})
        note = str(data.get("note", "")).strip()
        if not note:
            continue
        out.append(
            {
                "label": str(data.get("label", data.get("id", ""))).replace("\n", " · "),
                "note": note,
                "status": str(data.get("status", "")),
            }
        )
    return out


def _host_header(host: DiscoveredHost) -> str:
    # build the pivoted-host bullet header in Python so the template line ends in content (Jinja
    # trim_blocks would otherwise eat the newline after a line-ending {% endif %} and glue the first
    # service bullet onto this line).
    header = f"**{host.ip}**"
    if host.hostname:
        header += f" ({host.hostname})"
    if host.os_guess:
        header += f" — {host.os_guess}"
    if host.pivot_source:
        header += f" — via `{host.pivot_source}`"
    return header


class Reporter:
    def __init__(self, profile: Profile) -> None:
        self.profile = profile
        self.env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        # markdown-table-cell escape: a raw pipe or newline in a command/module/output cell would
        # split the row into extra columns. Collapse CR/LF and escape `|` (mirrors _audit_summary).
        self.env.filters["mdcell"] = lambda v: (
            str(v).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
        )
        # YAML-safe flow sequence for the frontmatter `tags`: quote each item + escape `"`/`\` so a
        # tag containing `]`/`:`/newline can't break the frontmatter block (Obsidian would drop it).
        self.env.filters["yamlflow"] = lambda items: (
            "["
            + ", ".join(
                '"' + str(i).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'
                for i in items
            )
            + "]"
        )
        # YAML-safe scalar for a frontmatter value (profile_name/hostname/platform/box_name/…): a
        # newline or a `:` in an imported/hand-edited profile.json would otherwise inject arbitrary
        # frontmatter keys. Double-quote + escape `\`/`"` + collapse CR/LF.
        self.env.filters["yamlstr"] = lambda v: (
            '"'
            + str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\r", " ").replace("\n", " ")
            + '"'  # noqa: E501
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
                    # fence-safe: a target-influenced NSE line that is exactly ``` would close the
                    # ```text code fence early and let injected markdown render — break any run of
                    # 3+ backticks with a zero-width space so it can never terminate the fence.
                    "scripts": re.sub(
                        r"`{3,}",
                        lambda m: "\u200b".join(m.group()),
                        service.nmap_scripts_output,
                    ),
                    "hacktricks": ref.hacktricks if ref else "",
                    "label": ref.label if ref else "",
                }
            )
        notes = ""
        if profile.notes_path.exists():
            # errors="replace": a non-UTF-8 byte in notes.md must degrade gracefully, not abort the
            # whole report (and the nmap tail that follows) with UnicodeDecodeError.
            notes = profile.notes_path.read_text(encoding="utf-8", errors="replace").strip()
        raw_findings = findings_mod.load_findings(profile.directory)
        edb_groups = _group_edb(edb_mod.load_edb(profile.directory))
        all_audit = audit.load_entries(profile.directory)
        shown_audit = all_audit[-_AUDIT_CAP:]
        audit_rows = [
            {
                "ts": entry.get("ts", ""),
                "actor": entry.get("actor", ""),
                "action": entry.get("action", ""),
                "summary": _audit_summary(
                    entry.get("details", {}) if isinstance(entry.get("details"), dict) else {}
                ),
            }
            for entry in shown_audit
        ]
        suggestions = suggest_for(
            raw_findings,
            target=profile.target.ip,
            domain=profile.target.hostname or "",
            has_credential=bool(profile.credentials()),
        )
        subnets: dict[str, list[Any]] = {}
        for host in profile.discovered_hosts:
            subnets.setdefault(host.subnet or "unknown", []).append(host)
        pivot_networks = [
            {
                "subnet": subnet,
                "host_count": len(subnets[subnet]),
                "hosts": [
                    {
                        "header": _host_header(host),
                        "services": [
                            {
                                "port": s.port,
                                "proto": s.proto.value,
                                "service": s.service,
                                "detail": " ".join(p for p in (s.product, s.version) if p),
                            }
                            for s in sorted(host.services, key=lambda s: (s.port, s.proto.value))
                        ],
                    }
                    for host in sorted(subnets[subnet], key=lambda h: h.ip)
                ],
            }
            for subnet in sorted(subnets)
        ]
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
            "edb_groups": edb_groups,
            "audit_rows": audit_rows,
            "audit_total": len(all_audit),
            "command_history": _redacted_history(profile.command_history),
            "tags": profile.tags,
            "notes": notes,
            "entry_ip": profile.target.ip,
            "pivot_networks": pivot_networks,
            "pivot_host_count": len(profile.discovered_hosts),
            "graph_notes": _graph_notes(profile),
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
