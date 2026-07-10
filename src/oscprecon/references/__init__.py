from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from oscprecon import shell
from oscprecon.models import DiscoveredService

_SERVICES_YAML = Path(__file__).parent / "services.yaml"
HACKTRICKS_BASE = "https://book.hacktricks.wiki/en/network-services-pentesting/index.html"
EDB_URL = "https://www.exploit-db.com/exploits/{edb_id}"

# why: nmap product/version banners carry quotes/parens (e.g. "(protocol 2.0)") that break
# shlex.split and are meaningless to searchsploit — keep only characters it matches on.
_SAFE_QUERY = re.compile(r"[^A-Za-z0-9.\- ]+")


@dataclass(frozen=True)
class ToolHint:
    name: str
    purpose: str


@dataclass(frozen=True)
class ServiceRef:
    label: str
    hacktricks: str
    module: str
    tools: list[ToolHint]


@dataclass(frozen=True)
class MatchRule:
    label: str
    hacktricks: str
    module: str
    tools: list[ToolHint]
    port: int | None = None
    proto: str | None = None
    product_contains: str | None = None
    service_name: str | None = None

    def matches(self, service: DiscoveredService) -> bool:
        keys = (self.port, self.proto, self.product_contains, self.service_name)
        if all(key is None for key in keys):
            return False
        if self.port is not None and self.port != service.port:
            return False
        if self.proto is not None and self.proto != service.proto.value:
            return False
        if self.product_contains is not None:
            haystack = f"{service.product} {service.version}".lower()
            if self.product_contains.lower() not in haystack:
                return False
        if self.service_name is not None:
            return self.service_name.lower() == service.service.lower()
        return True

    @property
    def specificity(self) -> int:
        # order mirrors CLAUDE.md §14: port+proto+product > port+proto > port > product > service
        if self.port is not None and self.proto is not None and self.product_contains is not None:
            return 5
        if self.port is not None and self.proto is not None:
            return 4
        if self.port is not None:
            return 3
        if self.product_contains is not None:
            return 2
        if self.service_name is not None:
            return 1
        return 0


def _tool_hints(raw: Any) -> list[ToolHint]:
    hints: list[ToolHint] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                hints.append(ToolHint(str(item.get("name", "")), str(item.get("purpose", ""))))
    return hints


def _opt_str(mapping: dict[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    return str(value) if value is not None else None


def load_rules(path: Path | None = None) -> list[MatchRule]:
    source = path if path is not None else _SERVICES_YAML
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    rules: list[MatchRule] = []
    if not isinstance(data, list):
        return rules
    for entry in data:
        if not isinstance(entry, dict):
            continue
        match_keys = entry.get("match")
        if not isinstance(match_keys, dict):
            match_keys = {}
        port = match_keys.get("port")
        rules.append(
            MatchRule(
                label=str(entry.get("label", "")),
                hacktricks=str(entry.get("hacktricks", HACKTRICKS_BASE)),
                module=str(entry.get("module", "")),
                tools=_tool_hints(entry.get("tools")),
                port=int(port) if port is not None else None,
                proto=_opt_str(match_keys, "proto"),
                product_contains=_opt_str(match_keys, "product_contains"),
                service_name=_opt_str(match_keys, "service_name"),
            )
        )
    return rules


def match(service: DiscoveredService, rules: list[MatchRule] | None = None) -> ServiceRef | None:
    ruleset = rules if rules is not None else load_rules()
    best: MatchRule | None = None
    for rule in ruleset:
        if not rule.matches(service):
            continue
        if best is None or rule.specificity > best.specificity:
            best = rule
    if best is None:
        return None
    return ServiceRef(best.label, best.hacktricks, best.module, best.tools)


def expand_hint(
    template: str,
    *,
    target: str,
    port: int | str = "",
    proto: str = "",
    domain: str = "",
    share: str = "",
) -> str:
    return (
        template.replace("{target}", target)
        .replace("{port}", str(port))
        .replace("{proto}", proto)
        .replace("{domain}", domain)
        .replace("{share}", share)
    )


@dataclass(frozen=True)
class ExploitHit:
    edb_id: str
    title: str
    url: str
    path: str


def parse_searchsploit_json(text: str) -> list[ExploitHit]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    raw = data.get("RESULTS_EXPLOIT", [])
    hits: list[ExploitHit] = []
    if not isinstance(raw, list):
        return hits
    for item in raw:
        if not isinstance(item, dict):
            continue
        edb_id = str(item.get("EDB-ID", "")).strip()
        if not edb_id:
            continue
        hits.append(
            ExploitHit(
                edb_id=edb_id,
                title=str(item.get("Title", "")).strip(),
                url=EDB_URL.format(edb_id=edb_id),
                path=str(item.get("Path", "")).strip(),
            )
        )
    return hits


def _safe_query(product: str, version: str) -> str:
    return " ".join(_SAFE_QUERY.sub(" ", f"{product} {version}").split())


def search_exploits(product: str, version: str, output_file: Path) -> list[ExploitHit]:
    query = _safe_query(product, version)
    if not query:
        return []
    result = shell.run(f"searchsploit --json {query}", output_file)
    if result.missing_tool is not None or result.blocked is not None:
        return []
    try:
        return parse_searchsploit_json(output_file.read_text(encoding="utf-8"))
    except OSError:
        return []
