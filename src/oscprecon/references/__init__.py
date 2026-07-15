from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
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
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []  # a corrupt services.yaml degrades to no matches, never an exception
    rules: list[MatchRule] = []
    if not isinstance(data, list):
        return rules
    for entry in data:
        if not isinstance(entry, dict):
            continue
        match_keys = entry.get("match")
        if not isinstance(match_keys, dict):
            match_keys = {}
        try:
            port = int(match_keys["port"]) if match_keys.get("port") is not None else None
        except (TypeError, ValueError):
            continue  # skip a rule with a non-integer port rather than aborting the load
        rules.append(
            MatchRule(
                label=str(entry.get("label", "")),
                hacktricks=str(entry.get("hacktricks", HACKTRICKS_BASE)),
                module=str(entry.get("module", "")),
                tools=_tool_hints(entry.get("tools")),
                port=port,
                proto=_opt_str(match_keys, "proto"),
                product_contains=_opt_str(match_keys, "product_contains"),
                service_name=_opt_str(match_keys, "service_name"),
            )
        )
    return rules


def _rank(rule: MatchRule) -> tuple[int, int]:
    # tie-break equal specificity by the longer product_contains (the more specific substring)
    return (rule.specificity, len(rule.product_contains or ""))


def match(service: DiscoveredService, rules: list[MatchRule] | None = None) -> ServiceRef | None:
    ruleset = rules if rules is not None else load_rules()
    best: MatchRule | None = None
    for rule in ruleset:
        if not rule.matches(service):
            continue
        if best is None or _rank(rule) > _rank(best):
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
    path: str  # local PoC path — used only to know a hit is real; NEVER persisted or opened (§14)
    type: str = ""  # remote | local | webapps | dos | shellcode
    platform: str = ""  # linux | windows | multiple | php | …
    date: str = ""  # Date_Published (YYYY-MM-DD)
    cve: str = ""  # comma-joined CVE ids parsed from searchsploit's Codes field
    version_match: bool = False  # title names the detected version (ranked + emphasised in the UI)


@dataclass(frozen=True)
class EdbSearch:
    # scope: "version" = product+major.minor produced hits; "product" = version-wide fallback;
    # "none" = no searchable product term. The GUI shows the scope so a fallback isn't mistaken for
    # a version-specific match. `hits` is capped to the top _EDB_MAX_HITS (version-matched first);
    # `total` is the full match count, so the UI can say "showing top N of M".
    hits: list[ExploitHit]
    query: str
    scope: str
    total: int = 0


# cap what one lookup shows so a broad product (e.g. `apache 2.4` -> 31) doesn't flood the pane or
# the report; the top slice keeps the version-matched hits (they sort first).
_EDB_MAX_HITS = 15


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _format_cve(codes: object) -> str:
    # searchsploit "Codes" joins CVE-/OSVDB- ids with ';'. Keep only CVEs, upper-cased + deduped.
    seen: list[str] = []
    for code in _CVE_RE.findall(str(codes or "")):
        upper = code.upper()
        if upper not in seen:
            seen.append(upper)
    return ", ".join(seen)


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
                type=str(item.get("Type", "")).strip(),
                platform=str(item.get("Platform", "")).strip(),
                date=str(item.get("Date_Published", "")).strip(),
                cve=_format_cve(item.get("Codes", "")),
            )
        )
    return hits


def _sanitize_query(text: str) -> str:
    cleaned = _SAFE_QUERY.sub(" ", text)
    # why: a token starting with '-' becomes a searchsploit FLAG after shlex.split — a hostile
    # banner 'product=-m 47080' would run `searchsploit -m` (copies a PoC). Strip leading dashes.
    return " ".join(t.lstrip("-") for t in cleaned.split() if t.lstrip("-"))


def _safe_query(product: str, version: str) -> str:
    # the (product, version) sanitizer the tests pin; the tiered search sanitizes each query term.
    return _sanitize_query(f"{product} {version}")


# nmap leads a few banners with a generic VENDOR word before the real product; search on the
# product, not the vendor. Kept tiny — the default (first banner word) is right for almost all.
_VENDOR_PREFIXES = frozenset({"microsoft"})


def _short_version(version: str) -> str:
    # major.minor is the sweet spot: the exact patch level (2.4.38) rarely appears in an exploit
    # title, but the minor line (2.4) does — searchsploit ANDs terms, so over-specifying returns 0.
    match = re.search(r"(\d+)\.(\d+)", version)
    return f"{match.group(1)}.{match.group(2)}" if match is not None else ""


def normalize_product(product: str, version: str) -> tuple[str, str]:
    """Reduce a noisy nmap product/version banner to (core search term, major.minor version)."""
    blob = f"{product} {version}".lower()
    # MariaDB rides behind a MySQL '5.5.5-' compatibility prefix and nmap often labels it "MySQL";
    # search Exploit-DB for the real engine + its real version, not the fake 5.5.5 prefix.
    if "mariadb" in blob:
        real = re.sub(r"^5\.5\.5-", "", version.strip())
        return "mariadb", _short_version(real)
    words = _sanitize_query(product).split()
    if not words:
        return "", _short_version(version)
    core = words[0].lower()
    if core in _VENDOR_PREFIXES and len(words) > 1:
        core = words[1].lower()
    return core, _short_version(version)


def _title_matches_version(title: str, version: str, short: str) -> bool:
    low = title.lower()
    if version and version.lower() in low:
        return True
    if not short:
        return False
    # match major.minor as a whole version token: "2.4" hits "2.4.49" but not "12.4" or "2.41".
    return re.search(rf"(?<![\d.]){re.escape(short)}(?!\d)", low) is not None


def _as_int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def _rank_hits(hits: list[ExploitHit], version: str, short: str) -> list[ExploitHit]:
    # flag + float hits whose title names the detected version; newest EDB-ID first within a tier.
    flagged = [
        replace(hit, version_match=_title_matches_version(hit.title, version, short))
        for hit in hits
    ]
    return sorted(flagged, key=lambda h: (0 if h.version_match else 1, -_as_int(h.edb_id)))


def _run_searchsploit(query: str, output_file: Path) -> list[ExploitHit]:
    safe = _sanitize_query(query)
    if not safe:
        return []
    result = shell.run(f"searchsploit --json {safe}", output_file)
    if result.missing_tool is not None or result.blocked is not None:
        return []
    try:
        return parse_searchsploit_json(output_file.read_text(encoding="utf-8"))
    except OSError:
        return []


def search_exploits(
    product: str,
    version: str,
    output_file: Path,
    *,
    runner: Callable[[str], list[ExploitHit]] | None = None,
) -> EdbSearch:
    # tiered lookup (never a brute): product + major.minor first (version-relevant), then product-
    # only so a version with no title match still surfaces the product's exploit surface. `runner`
    # is an injection seam for tests; production runs searchsploit once per tier.
    core, short = normalize_product(product, version)
    if not core:
        return EdbSearch([], "", "none", 0)
    run = runner if runner is not None else (lambda q: _run_searchsploit(q, output_file))

    def _capped(ranked: list[ExploitHit], query: str, scope: str) -> EdbSearch:
        return EdbSearch(ranked[:_EDB_MAX_HITS], query, scope, len(ranked))

    if short:
        primary = f"{core} {short}"
        hits = run(primary)
        if hits:
            return _capped(_rank_hits(hits, version, short), primary, "version")
        return _capped(_rank_hits(run(core), version, short), core, "product")
    return _capped(_rank_hits(run(core), version, short), core, "product")
