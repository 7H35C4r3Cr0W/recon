from __future__ import annotations

import re
from dataclasses import dataclass

from oscprecon.models import Command, Finding, Port, ScanResults, Target
from oscprecon.modules.base import Module
from oscprecon.modules.ike.parsers import IkeFinding, parse_ike_scan, parse_ike_tool

__all__ = [
    "IKE_SERVICE_NAMES",
    "IkeFinding",
    "IkeModule",
    "IkeStep",
    "parse_ike_scan",
    "parse_ike_tool",
]

IKE_SERVICE_NAMES = frozenset({"isakmp", "ike"})
_IKE_PORTS = frozenset({500})

# ike-scan names ciphers/hashes/groups differently from strongswan's proposal syntax; map the common
# lab transforms so the emitted /etc/ipsec.conf line is copy-ready. Falls back to the raw token.
_ENC_MAP = {"3des": "3des", "des": "des", "aes": "aes"}
_HASH_MAP = {"sha1": "sha1", "sha": "sha1", "sha2-256": "sha256", "sha256": "sha256", "md5": "md5"}
# strongswan DH keywords encode the modulus SIZE, not the IANA group number — 15 is modp3072, 19 is
# ecp256. ike-scan usually prints the authoritative name after a colon (Group=15:modp3072); this map
# is only the fallback when it prints the number alone.
_GROUP_MAP = {
    "1": "modp768", "2": "modp1024", "5": "modp1536", "14": "modp2048", "15": "modp3072",
    "16": "modp4096", "17": "modp6144", "18": "modp8192", "19": "ecp256", "20": "ecp384",
    "21": "ecp521",
}  # fmt: skip


def _strongswan_lines(transform: str) -> tuple[str, str]:
    # transform e.g. "Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK …" -> ("3des-sha1-modp1024",
    # "3des-sha1"). ike= needs the DH group, esp= does not (§ strongswan proposal syntax).
    low = transform.lower()
    enc = _match_token(low, r"enc=(\S+)", _ENC_MAP)
    # AES carries its key length in a SEPARATE attribute (Enc=AES KeyLength=256), not Enc=AES256 —
    # fold it in so an AES-256 responder gets aes256, not a bare aes (=aes128) that won't negotiate.
    if enc == "aes":
        keylen = re.search(r"keylength=(\d+)", low)
        if keylen is not None:
            enc = f"aes{keylen.group(1)}"
    hash_ = _match_token(low, r"hash=(\S+)", _HASH_MAP)
    group_raw = ""
    colon = re.search(r"group=\d+:(\w+)", low)  # authoritative name (modp3072 / ecp256) if present
    if colon is not None:
        group_raw = colon.group(1)
    else:
        grp = re.search(r"group=(\d+)", low)
        if grp is not None:
            group_raw = _GROUP_MAP.get(grp.group(1), "")  # no invalid modp<number> guess
    esp = f"{enc}-{hash_}" if enc and hash_ else "3des-sha1"
    ike = f"{esp}-{group_raw}" if group_raw else esp
    return ike, esp


def _match_token(text: str, pattern: str, table: dict[str, str]) -> str:
    match = re.search(pattern, text)
    if match is None:
        return ""
    raw = match.group(1).strip(",")
    return table.get(raw, raw)


@dataclass
class IkeStep:
    command: Command
    tool: str = ""  # parser key for the output, or "" when the output is not parsed


class IkeModule(Module):
    name = "ike"

    def triggers(self, scan_results: ScanResults) -> bool:
        return any(
            s.service.lower() in IKE_SERVICE_NAMES or s.port in _IKE_PORTS
            for s in scan_results.services
        )

    def recon_steps(self, target: Target) -> list[IkeStep]:
        host = target.ip
        return [
            IkeStep(
                Command(
                    "ike",
                    f"ike-scan -M {host}",
                    "Detect an IKE/ISAKMP VPN responder and its main-mode transform (read-only).",
                    "< 1 min",
                    "ike/ike-scan.txt",
                ),
                "ike-scan",
            ),
            IkeStep(
                Command(
                    "ike",
                    f"ike-scan -M -A {host}",
                    "Aggressive-mode check — does the responder answer aggressive mode? (recon).",
                    "< 1 min",
                    "ike/ike-scan-aggressive.txt",
                ),
                "ike-scan-aggressive",
            ),
        ]

    def commands(self, target: Target, ports: list[Port]) -> list[Command]:
        return [step.command for step in self.recon_steps(target)]

    def parse(self, raw_outputs: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for tool, text in raw_outputs.items():
            for kf in parse_ike_tool(tool, text):
                findings.append(
                    Finding(
                        service="ike",
                        title=f"{kf.kind}: {kf.value}",
                        detail=kf.detail,
                        fields={"kind": kf.kind, "value": kf.value, "detail": kf.detail},
                    )
                )
        return findings

    def suggest(self, findings: list[Finding]) -> list[str]:
        out: list[str] = []
        if any(f.fields.get("kind") == "aggressive" for f in findings):
            out.append(
                "IKE aggressive mode is enabled — the responder discloses PSK-related material; "
                "note it for the report (offline PSK cracking is out of scope for this recon tool)."
            )
        elif any(f.fields.get("kind") == "service" for f in findings):
            out.append(
                "IKE/ISAKMP VPN present — enumerate transforms and check whether aggressive mode "
                "is also accepted (recon)."
            )
        # firewall-bypass decision-aid: an IKE responder with the whole TCP surface filtered is the
        # classic "host only reachable over IPsec" setup (HTB Conceal) — once you have the PSK you
        # establish a transport-mode tunnel and the filtered TCP ports open. Derive the ipsec.conf
        # cipher line from the discovered transform so the config is copy-ready.
        transform = next(
            (
                str(f.fields.get("value", ""))
                for f in findings
                if f.fields.get("kind") == "transform"
            ),
            "",
        )
        if transform:
            ike_line, esp_line = _strongswan_lines(transform)
            out.append(
                "If the target's TCP ports are all filtered but IKE answers, the host is behind an "
                "IPsec firewall — establish a transport-mode tunnel to open them. Find the PSK "
                "(SNMP sysContact/sysDescr often leaks it — HTB Conceal; or crack an aggressive "
                "hash, out of scope here), then with strongswan: put "
                "'<target> : PSK \"<psk>\"' in /etc/ipsec.secrets and a conn in /etc/ipsec.conf: "
                f"type=transport, keyexchange=ikev1, right=<target>, leftprotoport=tcp, "
                f"rightprotoport=tcp, ike={ike_line}, esp={esp_line}, auto=start — then "
                "`ipsec restart` and re-scan TCP (-sT) through the tunnel."
            )
        return out
