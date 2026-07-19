from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class ManualCommand:
    description: str
    why: str
    command: str
    requires: list[str] = field(default_factory=list)
    category: str = ""  # optional grouping (used by the nmap scan-preset chooser)


def load_manual_commands(path: Path) -> list[ManualCommand]:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(data, list):
        return []
    commands: list[ManualCommand] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        requires_raw = entry.get("requires", [])
        requires = [str(r) for r in requires_raw] if isinstance(requires_raw, list) else []
        commands.append(
            ManualCommand(
                description=str(entry.get("description", "")),
                why=str(entry.get("why", "")),
                command=str(entry.get("command", "")),
                requires=requires,
                category=str(entry.get("category", "")),
            )
        )
    return commands


def expand(
    template: str,
    *,
    target: str = "",
    port: int | str = "",
    url: str = "",
    domain: str = "",
    user: str = "",
    password: str = "",
    basedn: str = "",
) -> str:
    return (
        template.replace("{target}", target)
        .replace("{port}", str(port))
        .replace("{url}", url)
        .replace("{domain}", domain)
        .replace("{user}", user)
        .replace("{password}", password)
        .replace("{basedn}", basedn)
    )
