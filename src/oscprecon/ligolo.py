from __future__ import annotations

import fcntl
import ipaddress
import socket
import struct
from dataclasses import dataclass, field

# Build the ligolo-ng pivot workflow as copy-paste command steps. Nabu does NOT run ligolo (it is a
# tunnelling relay, not a recon tool, and setting up a tun / route needs root) — this is a guided
# command-builder + reference, the same "shown, you run it" model as the Tier-2 manual commands.
# Once the internal /24 is routable over the ligolo interface, Nabu's "Scan a host / range" scans
# it transparently. Reference: https://docs.ligolo.ng/

_SIOCGIFADDR = 0x8915  # Linux ioctl: get an interface's IPv4 address


@dataclass
class LigoloStep:
    n: int
    title: str
    where: str  # Kali · pivot host · ligolo console · Nabu
    commands: list[str] = field(default_factory=list)
    note: str = ""


def detect_tun_ip(iface: str = "tun0") -> str:
    # best-effort: the VPN/tunnel IP the agent should dial back to. Linux-only ioctl; "" on failure
    # (non-Linux, no such iface) so the dialog just leaves the field blank for the user to fill.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packed = struct.pack("256s", iface[:15].encode())
        return socket.inet_ntoa(fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, packed)[20:24])
    except OSError:
        return ""


def _clean_routes(routes: list[str]) -> list[str]:
    out: list[str] = []
    for route in routes:
        text = (route or "").strip()
        if not text:
            continue
        try:
            ipaddress.ip_network(text, strict=False)  # a real CIDR — never a shell token
        except ValueError:
            continue
        if text not in out:
            out.append(text)
    return out


def build_ligolo_steps(
    kali_ip: str,
    port: int = 11601,
    iface: str = "ligolo",
    routes: list[str] | None = None,
) -> list[LigoloStep]:
    ip = (kali_ip or "<your-tun0-ip>").strip()
    iface = (iface or "ligolo").strip() or "ligolo"
    clean = _clean_routes(routes or [])
    steps: list[LigoloStep] = [
        LigoloStep(
            1,
            "Start the ligolo proxy",
            "Kali",
            [f"./proxy -selfcert -laddr 0.0.0.0:{port}"],
            "Listens for the agent (self-signed cert). Leave it running in its own terminal.",
        ),
        LigoloStep(
            2,
            "Run the agent on the compromised pivot host",
            "pivot host",
            [
                f"./agent -connect {ip}:{port} -ignore-cert       # Linux pivot",
                f"agent.exe -connect {ip}:{port} -ignore-cert     # Windows pivot",
            ],
            "The agent dials back to your proxy; a session then appears in the proxy console.",
        ),
    ]
    console = ["session", f"interface_create --name {iface}"]
    for route in clean or ["<internal_/24>"]:
        console.append(f"interface_add_route --name {iface} --route {route}")
    console.append(f"tunnel_start --tun {iface}")
    steps.append(
        LigoloStep(
            3,
            "In the ligolo proxy console",
            "ligolo console",
            console,
            "Pick the agent's session, create the tun, add the route(s), start the tunnel. "
            "(Older ligolo: the interface auto-creates and you run `start`, not `tunnel_start`.)",
        )
    )
    if clean:
        steps.append(
            LigoloStep(
                4,
                "If traffic doesn't route yet (older ligolo)",
                "Kali",
                [f"sudo ip route add {route} dev {iface}" for route in clean],
                "Modern ligolo's interface_add_route usually handles this — only needed if the "
                "route isn't already present.",
            )
        )
    scan_target = clean[0] if clean else "<internal_/24>"
    steps.append(
        LigoloStep(
            len(steps) + 1,
            "Scan the internal network from Nabu",
            "Nabu",
            [f"Scan → Scan a host / range → target: {scan_target}   (enable -Pn)"],
            "Hosts stream into the recon tree + graph, grouped by subnet, pivoted via this host.",
        )
    )
    return steps
