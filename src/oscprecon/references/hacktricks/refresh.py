"""Maintainer-run vendoring of the HackTricks network-services markdown (offline snapshot).

Run:  python src/oscprecon/references/hacktricks/refresh.py

For each service module it fetches the source markdown from the HackTricks repo, strips mdBook
``{{#include ...}}`` banner/ad directives, and writes ``pages/<module>.md`` + ``index.json`` +
``NOTICE.md``. This is the ONLY place that touches the network (CLAUDE.md § 2/§ 27: build-time
vendoring is allowed; live scraping at runtime is not). The app reads the vendored files offline via
``oscprecon.hacktricks`` and never imports or runs this module.

HackTricks (https://book.hacktricks.wiki) is CC BY-NC-SA 4.0; see NOTICE.md for attribution.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path

_RAW = (
    "https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/"
    "src/network-services-pentesting/{path}"
)
_BOOK = "https://book.hacktricks.wiki/en/network-services-pentesting/{stem}/index.html"

# our module name -> the page's path under network-services-pentesting/ in the HackTricks repo.
# (Most pages are flat `<slug>.md`; a few are `<slug>/README.md`. Book-URL slugs differ from repo
# filenames, so this mapping is explicit rather than derived — verified against the repo listing.)
MODULE_PAGES: dict[str, str] = {
    "smb": "pentesting-smb/README.md",
    "ftp": "pentesting-ftp/README.md",
    "ssh": "pentesting-ssh.md",
    "http": "pentesting-web/README.md",
    "dns": "pentesting-dns.md",
    "ldap": "pentesting-ldap.md",
    "smtp": "pentesting-smtp/README.md",
    "snmp": "pentesting-snmp/README.md",
    "kerberos": "pentesting-kerberos-88/README.md",
    "mssql": "pentesting-mssql-microsoft-sql-server/README.md",
    "mysql": "pentesting-mysql.md",
    "postgresql": "pentesting-postgresql.md",
    "redis": "6379-pentesting-redis.md",
    "mongodb": "27017-27018-mongodb.md",
    "ntp": "pentesting-ntp.md",
    "netbios": "137-138-139-pentesting-netbios.md",
    "ike": "ipsec-ike-vpn-pentesting.md",
    "tftp": "69-udp-tftp.md",
    "nfs": "nfs-service-pentesting.md",
    "rdp": "pentesting-rdp.md",
    "winrm": "5985-5986-pentesting-winrm.md",
}

_HERE = Path(__file__).parent
_PAGES = _HERE / "pages"
_INCLUDE_RE = re.compile(r"^\s*\{\{#.*?\}\}\s*$", re.MULTILINE)  # mdBook include/banner directives

_NOTICE = """# HackTricks — vendored offline snapshot

The markdown under `pages/` is an offline snapshot of the **network-services-pentesting** section of
**HackTricks** (https://book.hacktricks.wiki), vendored at build time so the tool can surface the
relevant reference offline (CLAUDE.md § 2a / § 27). It is **not** scraped at runtime.

- Source: https://github.com/HackTricks-wiki/hacktricks
- Licence: **CC BY-NC-SA 4.0** (Attribution-NonCommercial-ShareAlike). This project is free /
  non-commercial and attributes HackTricks here and, when displayed, next to a link to the page.
- mdBook `{{#include ...}}` banner directives are stripped; content is otherwise verbatim.
- Regenerate with `python src/oscprecon/references/hacktricks/refresh.py`.
"""


def _stem(path: str) -> str:
    return path[: -len("/README.md")] if path.endswith("/README.md") else path[: -len(".md")]


def _title(markdown: str, fallback: str) -> str:
    for line in markdown.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def _clean(markdown: str) -> str:
    return _INCLUDE_RE.sub("", markdown).strip() + "\n"


def refresh() -> None:
    _PAGES.mkdir(parents=True, exist_ok=True)
    for stale in _PAGES.glob("*.md"):
        stale.unlink()  # start clean so a renamed/removed page never lingers
    index: dict[str, dict[str, str]] = {}
    for module, path in sorted(MODULE_PAGES.items()):
        try:
            with urllib.request.urlopen(_RAW.format(path=path), timeout=30) as resp:  # noqa: S310
                raw = resp.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"[skip] {module} ({path}): {exc}")
            continue
        cleaned = _clean(raw)
        (_PAGES / f"{module}.md").write_text(cleaned, encoding="utf-8")
        index[module] = {
            "file": f"pages/{module}.md",
            "url": _BOOK.format(stem=_stem(path)),
            "title": _title(cleaned, module),
        }
        print(f"[ok] {module} <- {path} ({len(cleaned)} bytes)")
    (_HERE / "index.json").write_text(
        json.dumps(dict(sorted(index.items())), indent=2) + "\n", encoding="utf-8"
    )
    (_HERE / "NOTICE.md").write_text(_NOTICE, encoding="utf-8")
    print(f"[done] {len(index)} pages vendored")


if __name__ == "__main__":
    refresh()
