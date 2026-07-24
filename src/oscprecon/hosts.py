from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oscprecon.profile import Profile

# Quick /etc/hosts editing for discovered vhosts. Recon on HTB/PG boxes constantly turns up
# name-based vhosts (research.bedside.htb) that only resolve once mapped to the target IP in
# /etc/hosts — this makes adding one a single action instead of a hand-edited sudo line. Editing
# /etc/hosts needs root; add_entry writes directly when it can and callers fall back to
# sudo_append_command otherwise.

HOSTS_PATH = Path("/etc/hosts")


def hosts_line(ip: str, names: list[str]) -> str:
    return f"{ip}\t{' '.join(names)}"


def sudo_append_command(ip: str, names: list[str]) -> str:
    # copy-only command to add the entry with root, for when we can't write /etc/hosts ourselves.
    return f"echo '{ip} {' '.join(names)}' | sudo tee -a /etc/hosts"


def sudo_append_many(entries: list[tuple[str, str]]) -> str:
    # one copy-only command that adds MANY (ip, hostname) mappings at once, for when we aren't root.
    body = "\\n".join(f"{ip} {name}" for ip, name in entries)
    return f"printf '{body}\\n' | sudo tee -a /etc/hosts"


@dataclass(frozen=True)
class HostsResult:
    changed: bool
    added: tuple[str, ...]  # names newly written
    message: str


def _norm(ip: str, names: list[str]) -> tuple[str, list[str]]:
    ip = ip.strip()
    seen: list[str] = []
    for n in names:
        n = n.strip()
        if n and n not in seen:
            seen.append(n)
    return ip, seen


def add_entry(ip: str, names: list[str], path: Path = HOSTS_PATH) -> HostsResult:
    """Idempotently map `names` to `ip` in a hosts file.

    Merges into the existing line for `ip` (or appends a new one); comments and every other line
    are left untouched. Re-adding an already-present mapping is a no-op. Raises ValueError on empty
    input and OSError/PermissionError when the file can't be written (caller falls back to sudo).
    """
    ip, names = _norm(ip, names)
    if not ip or not names:
        raise ValueError("need an IP and at least one hostname")

    original = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = original.splitlines()

    ip_idx: int | None = None
    existing: list[str] = []
    elsewhere: list[str] = []  # names already mapped to a DIFFERENT ip (ambiguity warning)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if fields[0] == ip and ip_idx is None:
            ip_idx = i
            existing = fields[1:]
        else:
            for n in names:
                if n in fields[1:] and n not in elsewhere:
                    elsewhere.append(n)

    to_add = [n for n in names if n not in existing]
    warn = f"  (note: {', '.join(elsewhere)} already maps to another IP)" if elsewhere else ""

    if ip_idx is not None and not to_add:
        return HostsResult(False, (), f"{ip} already maps {', '.join(names)} — unchanged.{warn}")

    if ip_idx is not None:
        lines[ip_idx] = hosts_line(ip, existing + to_add)
    else:
        lines.append(hosts_line(ip, names))
        to_add = names

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return HostsResult(True, tuple(to_add), f"Added '{ip} {' '.join(to_add)}' to {path}.{warn}")


@dataclass(frozen=True)
class HostCandidate:
    ip: str
    hostname: str
    source: str  # where it was discovered: target / discovered host / vhost / http


def _looks_like_hostname(s: str) -> bool:
    s = s.strip()
    return bool(s) and " " not in s and any(c.isalpha() for c in s)


def collect_profile_hosts(profile: Profile) -> list[HostCandidate]:
    """Every discovered (ip, hostname) worth mapping in /etc/hosts — the profile target, hosts found
    across a pivot, and vhost / redirect-hostname findings — deduped, the primary target first.

    This is the "add everything I discovered" list: after recon turns up a subdomain, an AD domain
    name, or an internal vhost, one call collects them all so you never hand-edit /etc/hosts.
    """
    from oscprecon import findings as findings_mod

    out: list[HostCandidate] = []
    seen: set[tuple[str, str]] = set()

    def add(ip: str, name: str, source: str) -> None:
        ip = (ip or "").strip()
        name = (name or "").strip()
        if not ip or not _looks_like_hostname(name):
            return
        key = (ip, name.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(HostCandidate(ip, name, source))

    t = profile.target
    add(t.ip, t.hostname or "", "target")
    for h in profile.discovered_hosts:
        add(h.ip, h.hostname, "discovered host")
    try:
        for f in findings_mod.load_findings(profile.directory):
            if f.get("service") == "vhost" or f.get("vhost"):
                add(str(f.get("ip") or t.ip), str(f.get("vhost") or f.get("title") or ""), "vhost")
            for field_key in ("page_host", "hostname"):
                if f.get(field_key):
                    add(t.ip, str(f[field_key]), "http")
    except OSError:
        pass
    return out


def add_many(entries: list[tuple[str, str]], path: Path = HOSTS_PATH) -> list[HostsResult]:
    """Idempotently add many (ip, hostname) mappings. Raises OSError on the first unwritable write
    (caller falls back to sudo_append_many)."""
    return [add_entry(ip, [name], path) for ip, name in entries]


def current_mappings(path: Path = HOSTS_PATH) -> dict[str, set[str]]:
    # ip -> {lowercased hostnames} currently in the hosts file, so callers can show what's already
    # mapped. Best-effort: an unreadable file yields an empty map.
    result: dict[str, set[str]] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return result
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        fields = s.split()
        result.setdefault(fields[0], set()).update(n.lower() for n in fields[1:])
    return result
