from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from oscprecon.models import Suggestion

_PATTERN_DIR = Path(__file__).parent
_SOURCE_RE = re.compile(r"#\s*source:\s*(?P<src>\S.*?)\s*$", re.MULTILINE)
# §15 forbids exploit-specific / offensive-tool / cracking content in suggestions. Content-discovery
# wordlists (feroxbuster etc.) stay allowed, so only rockyou / spray / CVE terms are listed here.
_FORBIDDEN = (
    "cve-",
    "metasploit",
    "msfconsole",
    "msfvenom",
    "meterpreter",
    "hydra",
    "medusa",
    "sqlmap",
    "rockyou",
    "--passwords",
)


@dataclass
class PatternRule:
    service: str  # the pattern file stem (smb.yaml -> "smb")
    match: dict[str, Any]
    suggest: list[Any]  # each item is a str, or a {"text": ..., "command": ...} dict
    source: str  # the `# source:` provenance for this entry


def _split_entries(text: str) -> list[str]:
    # Split raw YAML into one block per top-level list item (a `- ` at column 0), so each entry's
    # trailing `# source:` comment — dropped by yaml.safe_load — stays attached to its entry.
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.startswith("- "):
            if current:
                blocks.append("".join(current))
            current = [line]
        elif current:
            current.append(line)  # continuation / trailing comment of the current entry
    if current:
        blocks.append("".join(current))
    return blocks


def _source_of(block: str) -> str:
    match = _SOURCE_RE.search(block)
    return match.group("src").strip() if match is not None else ""


def _item_text(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return " ".join(str(v) for v in item.values() if isinstance(v, str))
    return ""


def load_patterns(directory: Path | None = None) -> list[PatternRule]:
    directory = directory if directory is not None else _PATTERN_DIR
    rules: list[PatternRule] = []
    for path in sorted(directory.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        if not isinstance(data, list):
            continue
        blocks = _split_entries(text)
        for index, entry in enumerate(data):
            if not isinstance(entry, dict):
                continue
            match = entry.get("match")
            suggest = entry.get("suggest")
            rules.append(
                PatternRule(
                    service=path.stem,
                    match=match if isinstance(match, dict) else {},
                    suggest=suggest if isinstance(suggest, list) else [],
                    source=_source_of(blocks[index]) if index < len(blocks) else "",
                )
            )
    return rules


def check_provenance(directory: Path | None = None) -> list[str]:
    """Return an error per pattern entry lacking a `# source:` comment (the §15 build gate)."""
    directory = directory if directory is not None else _PATTERN_DIR
    errors: list[str] = []
    for path in sorted(directory.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        for index, block in enumerate(_split_entries(text)):
            if not _source_of(block):
                errors.append(f"{path.name}: entry #{index + 1} is missing a `# source:` comment")
    return errors


def check_forbidden(directory: Path | None = None) -> list[str]:
    """Return an error per suggestion containing exploit-specific / cracking content (§15)."""
    errors: list[str] = []
    for rule in load_patterns(directory):
        for item in rule.suggest:
            low = _item_text(item).lower()
            for bad in _FORBIDDEN:
                if bad in low:
                    errors.append(f"{rule.service}.yaml: forbidden '{bad}' in a suggestion")
    return errors


def _matches(match: dict[str, Any], finding: dict[str, Any], has_credential: bool) -> bool:
    if "service" in match and str(finding.get("module", "")) != match["service"]:
        return False
    if "port" in match and finding.get("port") != match["port"]:
        return False
    if "proto" in match and finding.get("proto") != match["proto"]:
        return False
    if "has_credential" in match and bool(match["has_credential"]) != has_credential:
        return False
    if "detail_contains" in match:
        # search EVERY finding field — works across shapes (smb kind/value/detail; http path/note)
        haystack = " ".join(str(value) for value in finding.values()).lower()
        if str(match["detail_contains"]).lower() not in haystack:
            return False
    return not (
        "field" in match
        and "value" in match
        and re.search(str(match["value"]), str(finding.get(match["field"], ""))) is None
    )


def _context(finding: dict[str, Any], target: str, domain: str) -> dict[str, str]:
    # expose EVERY finding field for interpolation ({value}/{kind} for smb, {path}/{note}/{port} for
    # http) plus {target}/{domain} and a {<kind>} alias (a `share` finding exposes {share}).
    context: dict[str, str] = {"target": target, "domain": domain}
    for key, value in finding.items():
        context[key] = str(value)
    kind = str(finding.get("kind", ""))
    if kind:
        context[kind] = str(finding.get("value", ""))
    return context


def _interpolate(text: str, context: dict[str, str]) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: context.get(m.group(1), m.group(0)), text)


def suggest_for(
    findings: list[dict[str, Any]],
    *,
    target: str,
    domain: str = "",
    has_credential: bool = False,
    rules: list[PatternRule] | None = None,
) -> list[Suggestion]:
    rules = rules if rules is not None else load_patterns()
    out: list[Suggestion] = []
    seen: set[tuple[str, str | None]] = set()
    for finding in findings:
        context = _context(finding, target, domain)
        for rule in rules:
            if not _matches(rule.match, finding, has_credential):
                continue
            source_pattern = f"{rule.service}: " + ", ".join(
                f"{key}={value}" for key, value in rule.match.items()
            )
            for item in rule.suggest:
                if isinstance(item, str):
                    text, command = _interpolate(item, context), None
                elif isinstance(item, dict):
                    text = _interpolate(str(item.get("text", "")), context)
                    raw_command = item.get("command")
                    command = _interpolate(str(raw_command), context) if raw_command else None
                else:
                    continue
                key = (text, command)
                if not text or key in seen:
                    continue
                seen.add(key)
                out.append(
                    Suggestion(
                        text=text,
                        command_template=command,
                        source_pattern=source_pattern,
                        source_box=rule.source or None,
                    )
                )
    return out
