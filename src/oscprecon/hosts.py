from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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
