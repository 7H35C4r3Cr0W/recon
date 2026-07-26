from __future__ import annotations

from dataclasses import dataclass

from oscprecon import nse_matrix, nse_select
from oscprecon.models import Proto

# Per-service NSE scan PROFILES — the six modes an operator actually wants, built from the service's
# script prefixes rather than a hand-maintained list of script names.
#
# The shape comes from the maintainer's own methodology notes, and the reason it works is the
# conjunction: `smb-* and vuln` selects every SMB vulnerability script — including the ones whose
# filename carries no "vuln" (smb-double-pulsar-backdoor) — while selecting no credential attack,
# because brute scripts are not in the vuln category. A filename family like `smb-vuln-*` misses
# those; a bare `smb-*` catches smb-brute. The conjunction is the only form that gets both right.
#
# Every selector also excludes the third-party lookups (§2 — no runtime internet beyond probing the
# target, and never transmit target data). `shell.policy_violation` enforces that independently by
# evaluating the selection; this just means the offered profiles pass it.

MODE_VERSION = "version"
MODE_ENUM = "enum"
MODE_VULN = "vuln"
MODE_AUTH = "auth"
MODE_BRUTE = "brute"
MODE_DANGEROUS = "dangerous"

# ordered as an operator escalates
MODES: tuple[str, ...] = (
    MODE_VERSION,
    MODE_ENUM,
    MODE_VULN,
    MODE_AUTH,
    MODE_BRUTE,
    MODE_DANGEROUS,
)

_NO_THIRD_PARTY = "not (external or *vulners*)"


@dataclass(frozen=True)
class Mode:
    key: str
    label: str
    why: str
    categories: str  # the category expression conjoined with the service's prefixes
    gated: str = ""  # "" = recon-safe; "spray" = §2a Spray mode; "dangerous" = typed confirmation


MODE_SPECS: dict[str, Mode] = {
    MODE_VERSION: Mode(
        key=MODE_VERSION,
        label="Version — every probe",
        why="`-sV --version-all` plus the version-category scripts: identify the product and build "
        "before deciding anything else. Nothing intrusive.",
        categories="version",
    ),
    MODE_ENUM: Mode(
        key=MODE_ENUM,
        label="Safe enumeration",
        why="Everything this service's scripts can tell you without touching anything: shares, "
        "users, headers, capabilities, anonymous access. Explicitly excludes brute, DoS, exploit, "
        "intrusive and fuzzer scripts.",
        categories="(default or safe or discovery or version) "
        "and not (brute or dos or exploit or intrusive or fuzzer)",
    ),
    MODE_VULN: Mode(
        key=MODE_VULN,
        label="Vulnerability checks",
        why="Every vuln-category script for this service — including the ones whose filename has "
        "no 'vuln' in it. Some are DoS-category and can crash a fragile service.",
        categories="vuln",
    ),
    MODE_AUTH: Mode(
        key=MODE_AUTH,
        label="Authentication checks",
        why="What this service accepts without credentials: anonymous access, null sessions, "
        "default and empty accounts. Single attempts, never a list (§11 Tier 2).",
        categories="auth and not brute",
    ),
    MODE_BRUTE: Mode(
        key=MODE_BRUTE,
        label="Credential brute (Spray mode)",
        why="Iterating credentials against this service. OSCP-legal against your own authorized "
        "target, but OFF by default — it runs only in opt-in Spray mode (§2a).",
        categories="brute",
        gated="spray",
    ),
    MODE_DANGEROUS: Mode(
        key=MODE_DANGEROUS,
        label="Intrusive / DoS / exploit",
        why="Scripts that can crash the service or change state on it. Never automatic — this "
        "needs a maintenance window and a target you can revert.",
        categories="(dos or exploit or intrusive or fuzzer) and not brute",
        gated="dangerous",
    ),
}


def selector(prefixes: tuple[str, ...], mode: str) -> str:
    """The `--script` expression for one service in one mode."""
    spec = MODE_SPECS.get(mode)
    if spec is None:
        raise ValueError(f"unknown scan mode: {mode!r}")
    if not prefixes:
        # no prefix family for this service — the category expression alone still applies, and
        # nmap's portrules keep it scoped to the port we pass with -p.
        return f"({spec.categories}) and {_NO_THIRD_PARTY}"
    family = " or ".join(prefixes)
    head = f"({family})" if len(prefixes) > 1 else family
    return f"{head} and ({spec.categories}) and {_NO_THIRD_PARTY}"


def preview(prefixes: tuple[str, ...], mode: str) -> list[str]:
    """Exactly which scripts this profile would run — the `--script-help` preview, offline.

    The operator's own rule: never let a wildcard run unreviewed. This is what makes that possible
    in the GUI, and it is the same evaluation the policy gate uses, so what you see is what runs.
    """
    try:
        return nse_select.selected(selector(prefixes, mode))
    except nse_select.SelectorError:
        return []


def build_command(
    target: str,
    ports: tuple[int, ...],
    prefixes: tuple[str, ...],
    mode: str,
    *,
    proto: Proto = Proto.TCP,
    version_all: bool = True,
) -> str:
    tokens = ["nmap", "-Pn"]
    if proto is Proto.UDP:
        tokens.append("-sU")
    tokens.append("-sV")
    if version_all:
        # the operator's note: -sV's normal probe subset misses services on odd ports; --version-all
        # tries every probe. Slower, and worth it on a box you are stuck on.
        tokens.append("--version-all")
    if ports:
        tokens.append("-p " + ",".join(str(p) for p in sorted(set(ports))))
    if mode != MODE_VERSION:
        tokens.append(f'--script "{selector(prefixes, mode)}"')
        tokens.append("--script-args vulns.showall")
    tokens.append(target)
    return " ".join(tokens)


def gate_for(mode: str) -> str:
    spec = MODE_SPECS.get(mode)
    return spec.gated if spec is not None else ""


def for_service(
    name: str, port: int, product: str = ""
) -> tuple[str, tuple[str, ...], tuple[int, ...]]:
    """(label, script prefixes, the service's declared ports) for a discovered service.

    Matches on the nmap SERVICE NAME first and the port second — the operator's rule: a module is
    triggered by the detected service OR the port, and the detected service is the stronger signal.
    FTP runs on 2121, HTTP on 5000, SSH on 2222.
    """
    entry = nse_matrix.for_service(name, port, product)
    if entry is None:
        return ("this service", (), (port,) if port else ())
    return (entry.label, entry.prefixes, entry.tcp_ports + entry.udp_ports)
