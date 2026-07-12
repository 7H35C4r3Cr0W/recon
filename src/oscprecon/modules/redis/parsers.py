from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class RedisFinding:
    kind: str  # access | version | role | banner | config | clients
    value: str
    detail: str = ""
    module: str = "redis"

    def to_dict(self, discovered_at: str) -> dict[str, Any]:
        return {
            "module": self.module,
            "kind": self.kind,
            "value": self.value,
            "detail": self.detail,
            "discovered_at": discovered_at,
        }


# redis-cli prints an error string when auth is required; INFO otherwise emits `key:value` lines.
_NOAUTH = re.compile(r"NOAUTH|authentication required|WRONGPASS", re.IGNORECASE)
_INFO_KEYS = (
    ("redis_version", "version", "version"),
    ("role", "role", "role"),
    ("os", "banner", "os"),
    ("redis_mode", "banner", "mode"),
)
# CONFIG GET returns alternating key / value lines; these leak the on-disk write path (RCE-adjacent
# recon) and whether a password is set at all.
_CONFIG_KEYS = frozenset({"requirepass", "dir", "dbfilename", "bind", "protected-mode"})


def parse_redis_info(text: str) -> list[RedisFinding]:
    if _NOAUTH.search(text):
        return [RedisFinding("access", "auth-required", "INFO refused without credentials")]
    findings: list[RedisFinding] = []
    seen_any = False
    for key, kind, label in _INFO_KEYS:
        match = re.search(rf"^{re.escape(key)}:(?P<v>.+)$", text, re.MULTILINE)
        if match is not None and match.group("v").strip():
            seen_any = True
            value = match.group("v").strip()
            findings.append(RedisFinding(kind, value if kind != "banner" else f"{label}: {value}"))
    if seen_any:
        findings.insert(0, RedisFinding("access", "unauth", "INFO returned without authentication"))
    return findings


def parse_redis_config(text: str) -> list[RedisFinding]:
    # `redis-cli CONFIG GET *` output is one value per line, alternating key then value.
    tokens = text.splitlines()
    findings: list[RedisFinding] = []
    for index in range(0, len(tokens) - 1, 2):
        key = tokens[index].strip()
        value = tokens[index + 1].strip()
        if key not in _CONFIG_KEYS:
            continue
        if key == "requirepass" and value == "":
            findings.append(
                RedisFinding("config", "requirepass=<empty>", "no password set — unauth")
            )
        else:
            findings.append(RedisFinding("config", f"{key}={value or '<empty>'}"))
    if findings:
        return findings
    # fallback: some formats print `key value` on one line — catch dir/dbfilename that way too.
    for line in tokens:
        parts = line.split()
        if len(parts) >= 2 and parts[0] in _CONFIG_KEYS:
            findings.append(RedisFinding("config", f"{parts[0]}={parts[1]}"))
    return findings


def parse_redis_clients(text: str) -> list[RedisFinding]:
    count = len(re.findall(r"^id=\d+", text, re.MULTILINE))
    return [RedisFinding("clients", str(count))] if count else []


_PARSERS = {
    "redis-info": parse_redis_info,
    "redis-config": parse_redis_config,
    "redis-clients": parse_redis_clients,
}


def parse_redis_tool(tool: str, text: str) -> list[RedisFinding]:
    parser = _PARSERS.get(tool)
    return parser(text) if parser is not None else []
