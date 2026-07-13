from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path

from oscprecon.models import Credential

# why: OSCP-legal credential spraying (§2a) — built ONLY for the active profile's single target,
# from the user's editable cred vault. This module is PURE command construction + list writing; it
# never executes anything. Execution goes through shell.run(spray=True), which is itself gated on
# config.spray_enabled. Every template is single-target and uses the credential-attempt category the
# gated policy unlocks (netexec list-spray / hydra) — nothing here captures hashes or cracks.


@dataclass(frozen=True)
class SprayService:
    key: str
    label: str
    template: str  # interpolates {target} {users} {passwords}


# netexec for Windows/AD services (native spray + --continue-on-success); hydra for the rest.
SPRAY_SERVICES: tuple[SprayService, ...] = (
    SprayService(
        "smb",
        "SMB (netexec)",
        "netexec smb {target} -u {users} -p {passwords} --continue-on-success",
    ),
    SprayService(
        "winrm",
        "WinRM (netexec)",
        "netexec winrm {target} -u {users} -p {passwords} --continue-on-success",
    ),
    SprayService(
        "ldap",
        "LDAP (netexec)",
        "netexec ldap {target} -u {users} -p {passwords} --continue-on-success",
    ),
    SprayService("ssh", "SSH (hydra)", "hydra -L {users} -P {passwords} ssh://{target}"),
    SprayService("ftp", "FTP (hydra)", "hydra -L {users} -P {passwords} ftp://{target}"),
    SprayService("rdp", "RDP (hydra)", "hydra -L {users} -P {passwords} rdp://{target}"),
)
_BY_KEY = {service.key: service for service in SPRAY_SERVICES}


def _dedup(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in values:
        value = raw.strip()
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def vault_material(creds: list[Credential]) -> tuple[list[str], list[str]]:
    """Distinct usernames + password secrets from the vault, ready to spray (cross-product)."""
    users = _dedup([c.username for c in creds])
    passwords = _dedup([c.secret for c in creds if c.secret_type == "password"])
    return users, passwords


def _write_secret_lines(path: Path, values: list[str]) -> None:
    # passwords.txt holds plaintext secrets -> 0600, mirroring creds.json (§6).
    data = ("\n".join(_dedup(values)) + "\n").encode("utf-8") if values else b""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, data)
    finally:
        os.close(fd)


def write_spray_lists(
    profile_dir: Path, usernames: list[str], passwords: list[str]
) -> tuple[Path, Path]:
    """Write deduped users.txt + passwords.txt (0600) under <profile>/spray/; return their paths."""
    spray_dir = Path(profile_dir) / "spray"
    spray_dir.mkdir(parents=True, exist_ok=True)
    users_path = spray_dir / "users.txt"
    passwords_path = spray_dir / "passwords.txt"
    _write_secret_lines(users_path, usernames)
    _write_secret_lines(passwords_path, passwords)
    return users_path, passwords_path


def build_spray_command(service_key: str, target: str, users: Path, passwords: Path) -> str:
    """Build the single-target spray command for a service. Run it via shell.run(spray=True)."""
    service = _BY_KEY.get(service_key)
    if service is None:
        raise ValueError(f"unknown spray service: {service_key!r}")
    return service.template.format(
        target=target, users=shlex.quote(str(users)), passwords=shlex.quote(str(passwords))
    )


# The generated spray INPUT lists — derived artifacts, NOT the credential store. They hold plaintext
# secrets, so cleaning them up after a run is good hygiene. This tuple is the ONLY thing cleanup
# removes: never creds.json, never the <service>.txt spray OUTPUT evidence, never a user's wordlist.
_GENERATED_SPRAY_FILES = ("users.txt", "passwords.txt")


def clean_spray_artifacts(profile_dir: Path) -> list[str]:
    """Delete the generated users.txt / passwords.txt lists only; return the names removed."""
    removed: list[str] = []
    spray_dir = Path(profile_dir) / "spray"
    for name in _GENERATED_SPRAY_FILES:
        path = spray_dir / name
        try:
            if path.is_file():
                path.unlink()
                removed.append(name)
        except OSError:
            pass  # a cleanup failure is never fatal and never touches the credential store
    return removed


_NETEXEC_SERVICES = frozenset({"smb", "winrm", "ldap"})


def parse_spray_success(
    service_key: str, output: str, candidates: list[tuple[str, str]]
) -> list[tuple[str, str]]:
    """Confirmed (username, secret) pairs — anchored to the vault + service-specific markers.

    Vault-anchored (we never guess creds out of noisy output) and service-specific — netexec marks a
    valid login with ``[+] ...user:secret`` (optionally ``(Pwn3d!)``); hydra prints ``login:``/
    ``password:``. A generic word like "success" is never treated as proof.
    """
    lines = output.splitlines()
    netexec = service_key in _NETEXEC_SERVICES
    confirmed: list[tuple[str, str]] = []
    for user, secret in candidates:
        for line in lines:
            if netexec:
                hit = "[+]" in line and f"{user}:{secret}" in line
            else:
                low = line.lower()
                hit = "login:" in low and "password:" in low and user in line and secret in line
            if hit:
                confirmed.append((user, secret))
                break
    return confirmed
