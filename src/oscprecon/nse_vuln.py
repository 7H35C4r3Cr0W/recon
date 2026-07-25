from __future__ import annotations

import re
from dataclasses import dataclass

from oscprecon.models import Finding, Proto

# Per-service NSE VULN scanning (§8 — "NSE is allowed. --script vuln … opt-in in the GUI").
#
# The driving miss: an operator burned an evening on a Windows Server 2008 box whose only way
# in was smb-vuln-cve2009-3103, because nothing in the tool ever offered `--script vuln` against
# 445. A default -sC -sV sweep does NOT run vuln-category scripts. So every discovered service now
# carries a one-click vuln scan, and a VULNERABLE result is PARSED into a finding — never scrolled
# past.
#
# Selector design: nmap's own PORTRULES do the targeting, so `--script vuln` scoped with
# `-p <ports>` runs exactly the vuln-category scripts that apply. That is complete for EVERY
# service with no hand-maintained per-service script list to rot. Two refinements:
#
#   * `not *vulners*` on every selector. vulners.nse queries vulners.com at scan time with the
#     target's product/version — §2 bans runtime internet and forbids transmitting target data,
#     so it is excluded from every mode. A `not` clause naming an uninstalled script is not an
#     error, so this stays portable to hosts without it.
#   * a per-service FAMILY glob (smb-vuln-*) for a faster focused run, kept because it is the form
#     operators know and type, and because it names what a scan is actually going to do.

VULNERS_EXCLUDE = "not *vulners*"

# Modes offered per service. "all" is the default: the whole vuln category, portrule-filtered.
MODE_ALL = "all"
MODE_TARGETED = "targeted"
MODE_SAFE = "safe"
MODES: tuple[str, ...] = (MODE_ALL, MODE_TARGETED, MODE_SAFE)


@dataclass(frozen=True)
class VulnProfile:
    key: str  # module/service key this covers ("smb", "http", …)
    label: str
    ports: tuple[int, ...]  # the ports that signal it (used when the caller has no discovered port)
    family: tuple[str, ...]  # targeted NSE selectors — the "smb-vuln-*" form operators type
    why: str
    dos_note: str = ""  # set when the family contains DoS-category checks that can crash a service


# nmap service names (and product substrings) -> profile key. Deliberately small: the selector is
# portrule-driven, so an unmatched service still gets a correct, complete `vuln` scan on its port.
_NAME_KEYS: tuple[tuple[str, str], ...] = (
    ("microsoft-ds", "smb"),
    ("netbios-ssn", "smb"),
    ("smb", "smb"),
    ("ssl/http", "http"),
    ("https", "http"),
    ("http-proxy", "http"),
    ("http-alt", "http"),
    ("http", "http"),
    ("ftp", "ftp"),
    ("smtp", "smtp"),
    ("submission", "smtp"),
    ("ms-wbt-server", "rdp"),
    ("rdp", "rdp"),
    ("mysql", "mysql"),
    ("ms-sql", "mssql"),
    ("oracle", "oracle"),
    ("imap", "mail-tls"),
    ("pop3", "mail-tls"),
    ("ldap", "ldap"),
    ("nfs", "nfs"),
    ("rpcbind", "nfs"),
    ("irc", "irc"),
    ("java-rmi", "rmi"),
    ("rmiregistry", "rmi"),
    ("afp", "afp"),
    ("vnc", "vnc"),
    ("ssh", "ssh"),
    ("domain", "dns"),
    ("snmp", "snmp"),
)

PROFILES: tuple[VulnProfile, ...] = (
    VulnProfile(
        key="smb",
        label="SMB / NetBIOS",
        ports=(139, 445),
        family=("smb-vuln-*", "smb2-vuln-*", "smb-double-pulsar-backdoor"),
        why="MS08-067, MS17-010, MS09-050/CVE-2009-3103, conficker, DoublePulsar — the classic "
        "unauthenticated Windows RCE checks. Run this the moment 139/445 is open.",
        dos_note="Several smb-vuln checks are DoS-category (ms06-025, ms07-029, ms08-067, "
        "cve2009-3103) — they can crash a fragile service. Use 'safe checks only' to skip them.",
    ),
    VulnProfile(
        key="http",
        label="HTTP / HTTPS",
        ports=(80, 443, 8000, 8080, 8443, 8888),
        family=("http-vuln-*", "http-shellshock", "http-iis-webdav-vuln", "http-vmware-path-vuln"),
        why="Struts/ColdFusion/Drupalgeddon/IIS-WebDAV/Shellshock and the TLS checks "
        "(heartbleed, POODLE, CCS-injection) when the port is HTTPS.",
        dos_note="http-slowloris-check is a DoS probe — 'safe checks only' skips it.",
    ),
    VulnProfile(
        key="ftp",
        label="FTP",
        ports=(21,),
        family=("ftp-vuln-*", "ftp-vsftpd-backdoor", "ftp-proftpd-backdoor", "ftp-libopie"),
        why="vsftpd 2.3.4 / ProFTPD backdoors and the ProFTPD copy-command vulns.",
    ),
    VulnProfile(
        key="smtp",
        label="SMTP",
        ports=(25, 465, 587),
        family=("smtp-vuln-*",),
        why="Exim heap overflow (CVE-2010-4344) and the Postfix/Exim command-injection checks.",
    ),
    VulnProfile(
        key="rdp",
        label="RDP",
        ports=(3389,),
        family=("rdp-vuln-*",),
        why="MS12-020 (RDP pre-auth). Confirms a legacy, unpatched Windows terminal service.",
        dos_note="rdp-vuln-ms12-020 is a DoS-category check — it can bring the service down.",
    ),
    VulnProfile(
        key="mysql",
        label="MySQL",
        ports=(3306,),
        family=("mysql-vuln-*",),
        why="CVE-2012-2122 auth bypass — a repeated login attempt lands as root.",
    ),
    VulnProfile(
        key="mssql",
        label="MSSQL",
        ports=(1433,),
        family=("ms-sql-*",),
        why="Instance/version disclosure plus the vuln-category MSSQL checks.",
    ),
    VulnProfile(
        key="oracle",
        label="Oracle TNS",
        ports=(1521,),
        family=("oracle-*",),
        why="TNS version + the vuln-category Oracle checks.",
    ),
    VulnProfile(
        key="mail-tls",
        label="IMAP / POP3",
        ports=(110, 143, 993, 995),
        family=("ssl-*", "sslv2-drown"),
        why="The TLS weaknesses on a mail port — heartbleed, POODLE, DROWN, CCS-injection.",
    ),
    VulnProfile(
        key="rmi",
        label="Java RMI",
        ports=(1099, 1098),
        family=("rmi-vuln-*", "rmi-dumpregistry"),
        why="RMI classloader RCE — a registry that accepts remote class loading.",
    ),
    VulnProfile(
        key="irc",
        label="IRC",
        ports=(6667, 6697, 6660),
        family=("irc-unrealircd-backdoor", "irc-botnet-channels"),
        why="UnrealIRCd 3.2.8.1 backdoor — a straight command-execution path.",
    ),
    VulnProfile(
        key="afp",
        label="AFP",
        ports=(548,),
        family=("afp-path-vuln", "afp-*"),
        why="AFP directory traversal (CVE-2010-0533).",
    ),
    VulnProfile(
        key="vnc",
        label="VNC",
        ports=(5900, 5901, 5902),
        family=("realvnc-auth-bypass", "vnc-*"),
        why="RealVNC auth bypass (CVE-2006-2369) and the VNC auth-type dump.",
    ),
    VulnProfile(
        key="nfs",
        label="NFS / RPC",
        ports=(111, 2049),
        family=("nfs-*", "rpcinfo"),
        why="Exported shares and the RPC surface behind them.",
    ),
    VulnProfile(
        key="ldap",
        label="LDAP",
        ports=(389, 636, 3268, 3269),
        family=("ldap-*",),
        why="Root DSE + the vuln-category LDAP checks.",
    ),
    VulnProfile(
        key="ssh",
        label="SSH",
        ports=(22,),
        family=("ssh-*", "sshv1"),
        why="Protocol/algorithm weaknesses. There is no ssh-vuln-* family — the vuln category "
        "covers what exists.",
    ),
    VulnProfile(
        key="dns",
        label="DNS",
        ports=(53,),
        family=("dns-*",),
        why="Recursion, cache-snooping and zone transfer — the DNS misconfigurations.",
    ),
    VulnProfile(
        key="snmp",
        label="SNMP",
        ports=(161,),
        family=("snmp-*",),
        why="Community-string exposure and the SNMP information leaks.",
    ),
)

_BY_KEY: dict[str, VulnProfile] = {p.key: p for p in PROFILES}

# the generic profile — every service that has no specific family still gets a complete, correct
# vuln scan, because the portrule decides what runs. This is what makes the feature true for ALL
# services rather than a curated handful.
GENERIC = VulnProfile(
    key="generic",
    label="this service",
    ports=(),
    family=(),
    why="Every vuln-category NSE script whose portrule matches this port. nmap decides what "
    "applies, so nothing service-specific is missed.",
)


def profile_for(service_name: str, port: int = 0, product: str = "") -> VulnProfile:
    """The vuln profile for a discovered service — by nmap service name, then product, then port."""
    text = f"{service_name} {product}".lower()
    for frag, key in _NAME_KEYS:
        if frag in text:
            found = _BY_KEY.get(key)
            if found is not None:
                return found
    if port:
        for profile in PROFILES:
            if port in profile.ports:
                return profile
    return GENERIC


def selector(mode: str, profile: VulnProfile) -> str:
    """The --script expression for a mode. Always excludes vulners (§2 — no runtime internet)."""
    if mode == MODE_TARGETED and profile.family:
        family = " or ".join(profile.family)
        head = f"({family})" if len(profile.family) > 1 else family
        return f"{head} and {VULNERS_EXCLUDE}"
    if mode == MODE_SAFE:
        return f"(vuln and safe) and {VULNERS_EXCLUDE}"
    return f"vuln and {VULNERS_EXCLUDE}"


def mode_label(mode: str, profile: VulnProfile) -> str:
    if mode == MODE_TARGETED and profile.family:
        return f"targeted — {', '.join(profile.family)}"
    if mode == MODE_SAFE:
        return "safe checks only (no DoS-category scripts)"
    return "all vuln-category NSE for these ports"


def ports_for(profile: VulnProfile, discovered: list[int]) -> list[int]:
    # scan the ports the box actually has open that belong to this service; fall back to the
    # profile's declared ports so a hand-picked service still produces a runnable command.
    hits = [p for p in discovered if p in profile.ports]
    if hits:
        return sorted(set(hits))
    return sorted(set(discovered)) if discovered else list(profile.ports)


@dataclass(frozen=True)
class VulnTarget:
    profile: VulnProfile
    ports: tuple[int, ...]
    proto: Proto
    service_name: str  # the nmap name of the representative port (what the GUI/CLI was asked for)
    port: int  # the representative port — what a finding is attributed to

    @property
    def label(self) -> str:
        return f"{self.profile.label} on {','.join(str(p) for p in self.ports)}"


def plan_scans(services: list[tuple[int, Proto, str, str]]) -> list[VulnTarget]:
    """Collapse discovered services into ONE scan per service family.

    139 and 445 are both SMB: scanning "each discovered service" naively runs the identical
    `smb-vuln-*` command twice and records every verdict twice. nmap already covers a port list in
    one pass, so group by (profile, proto) and scan each group once. Ordering follows discovery, so
    the first thing checked is the first thing found.
    """
    grouped: dict[tuple[str, Proto], list[tuple[int, str]]] = {}
    specs: dict[str, VulnProfile] = {}
    for port, proto, name, product in services:
        spec = profile_for(name, port, product)
        specs[spec.key] = spec
        grouped.setdefault((spec.key, proto), []).append((port, name))
    out: list[VulnTarget] = []
    for (key, proto), members in grouped.items():
        spec = specs[key]
        ports = tuple(sorted({p for p, _ in members}))
        first_port, first_name = members[0]
        out.append(
            VulnTarget(
                profile=spec,
                ports=ports,
                proto=proto,
                service_name=first_name,
                port=first_port,
            )
        )
    return out


def build_command(
    target: str,
    ports: list[int],
    *,
    mode: str = MODE_ALL,
    profile: VulnProfile | None = None,
    proto: Proto = Proto.TCP,
    showall: bool = True,
) -> str:
    """`nmap -Pn -sV -p <ports> --script "<selector>" --script-args vulns.showall <target>`.

    -Pn because a Windows box that answers SMB often drops ICMP; -sV because many vuln scripts
    gate on the detected version. The selector is quoted: it contains spaces (an NSE expression).

    `vulns.showall` is ON by default and it matters: without it nmap prints NOTHING for a check that
    came back negative, so a silent run is indistinguishable from a check that never ran. With it,
    every script states its verdict — the operator can see MS08-067 was tested and came back NOT
    VULNERABLE, instead of wondering. That doubt is exactly what let a missed SMB vuln happen.
    """
    spec = profile if profile is not None else GENERIC
    port_list = ",".join(str(p) for p in ports) if ports else ""
    tokens = ["nmap", "-Pn"]
    if proto is Proto.UDP:
        tokens.append("-sU")
    tokens.append("-sV")
    if port_list:
        tokens.append(f"-p {port_list}")
    tokens.append(f'--script "{selector(mode, spec)}"')
    if showall:
        tokens.append("--script-args vulns.showall")
    tokens.append(target)
    return " ".join(tokens)


def output_name(profile: VulnProfile, ports: list[int], mode: str) -> str:
    port_part = "-".join(str(p) for p in ports) if ports else "all"
    suffix = "" if mode == MODE_ALL else f"-{mode}"
    return f"nse-vuln-{profile.key}-{port_part}{suffix}.txt"


# --- parsing -------------------------------------------------------------------------------------
# NSE output shape (both port scripts and "Host script results" blocks):
#
#   | smb-vuln-cve2009-3103:
#   |   VULNERABLE:
#   |   SMBv2 exploit (CVE-2009-3103, Microsoft Security Bulletin MS09-050)
#   |     State: VULNERABLE
#   |     IDs:  CVE:CVE-2009-3103
#   |     Risk factor: HIGH
#   |_smb-vuln-ms10-054: false
#
# A script name sits ONE character after the pipe (`| name:` / `|_name:`); continuation lines are
# indented further, so the start-of-block match stays unambiguous.

_BLOCK_RE = re.compile(r"^\|(?:_| )([a-z0-9][A-Za-z0-9._-]*):(.*)$")
_PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)\s+(\S+)\s*(\S*)")
_STATE_RE = re.compile(r"^\s*State:\s*(.+?)\s*$")
_IDS_RE = re.compile(r"(CVE-\d{4}-\d{3,7}|MS\d{2}-\d{3}|BID:\d+)", re.IGNORECASE)
_RISK_RE = re.compile(r"^\s*Risk factor:\s*(.+?)\s*$")

VULNERABLE = "VULNERABLE"
LIKELY_VULNERABLE = "LIKELY VULNERABLE"

# a check that neither confirmed nor cleared the host. §13 of the operator's own write-up: "Do not
# treat a timeout as a negative vulnerability result." So these are reported as loudly as a hit —
# an ACCESS_DENIED on ms10-061 means UNKNOWN, and the operator has to decide, not the tool.
_INCONCLUSIVE_MARKERS = (
    "ERROR",
    "TIMEOUT",
    "COULD NOT",
    "NT_STATUS",
    "FALSE POSITIVE",
    "UNKNOWN",
    "NO RESPONSE",
)


@dataclass
class VulnResult:
    script: str
    port: int
    proto: Proto
    state: str  # "VULNERABLE" | "LIKELY VULNERABLE" | "NOT VULNERABLE" | "" (no verdict)
    title: str
    ids: tuple[str, ...]
    risk: str
    detail: str

    @property
    def vulnerable(self) -> bool:
        return self.state.upper().startswith(("VULNERABLE", "LIKELY VULNERABLE"))

    @property
    def inconclusive(self) -> bool:
        # no verdict at all, or a verdict-shaped line that is really an error/refusal
        if self.vulnerable or self.state.upper().startswith("NOT VULNERABLE"):
            return False
        if not self.state:
            return True
        upper = f"{self.state} {self.detail}".upper()
        return any(marker in upper for marker in _INCONCLUSIVE_MARKERS)


def _finish(
    script: str,
    body: list[str],
    port: int,
    proto: Proto,
    inline: str,
) -> VulnResult | None:
    text = "\n".join(body).strip()
    joined = f"{inline}\n{text}".strip()
    if not joined:
        return None
    state = ""
    risk = ""
    title = ""
    for raw in body:
        line = raw.strip()
        match = _STATE_RE.match(raw)
        if match is not None and not state:
            state = match.group(1).strip()
            continue
        risk_match = _RISK_RE.match(raw)
        if risk_match is not None and not risk:
            risk = risk_match.group(1).strip()
            continue
        # the human title is the first content line that isn't the VULNERABLE: marker or a field
        if (
            not title
            and line
            and not line.upper().startswith(("VULNERABLE", "NOT VULNERABLE", "LIKELY VULNERABLE"))
            and ":" not in line.split(" ", 1)[0]
        ):
            title = line
    if not state:
        # blocks that only carry the bare marker line ("|   VULNERABLE:") still state a verdict
        upper = joined.upper()
        if "NOT VULNERABLE" in upper:
            state = "NOT VULNERABLE"
        elif "LIKELY VULNERABLE" in upper:
            state = LIKELY_VULNERABLE
        elif VULNERABLE in upper:
            state = VULNERABLE
        elif inline.strip().lower() in ("false", "no", "not vulnerable"):
            state = "NOT VULNERABLE"
            inline = ""  # the verdict word is not a title
    ids = tuple(dict.fromkeys(m.upper() for m in _IDS_RE.findall(joined)))
    return VulnResult(
        script=script,
        port=port,
        proto=proto,
        state=state,
        title=title or inline.strip(),
        ids=ids,
        risk=risk,
        detail=joined,
    )


def parse_vuln_output(
    text: str, default_port: int = 0, proto: Proto = Proto.TCP
) -> list[VulnResult]:
    """Every NSE script block in an nmap run, with its verdict.

    `default_port` is used for "Host script results" blocks (smb-vuln-* are HOST scripts and carry
    no port line) — the caller passes the port it aimed the scan at.
    """
    results: list[VulnResult] = []
    port = default_port
    current_proto = proto
    script = ""
    inline = ""
    body: list[str] = []

    def flush() -> None:
        nonlocal script, body, inline
        if script:
            result = _finish(script, body, port, current_proto, inline)
            if result is not None:
                results.append(result)
        script = ""
        inline = ""
        body = []

    for raw in text.splitlines():
        line = raw.rstrip()
        port_match = _PORT_RE.match(line)
        if port_match is not None:
            flush()
            port = int(port_match.group(1))
            current_proto = Proto.UDP if port_match.group(2) == "udp" else Proto.TCP
            continue
        if line.startswith("Host script results"):
            flush()
            port = default_port
            current_proto = proto
            continue
        block = _BLOCK_RE.match(line)
        if block is not None:
            flush()
            script = block.group(1)
            inline = block.group(2).strip()
            continue
        if line.startswith("|") and script:
            body.append(line[1:])
            continue
        if not line.startswith("|"):
            flush()
    flush()
    return results


def to_findings(results: list[VulnResult], service: str = "nmap") -> list[Finding]:
    """Confirmed hits AND checks that could not reach a verdict, as findings.

    A clean NOT VULNERABLE is not recorded — findings.json is the "what is true about this box"
    store, not the scan transcript (the raw output file keeps every check that ran). But an
    INCONCLUSIVE check is recorded, because "we never actually established this" is a fact the
    operator has to act on, and it is the one that gets scrolled past.
    """
    findings: list[Finding] = []
    for result in results:
        if not result.vulnerable and not result.inconclusive:
            continue
        ids = ", ".join(result.ids)
        title = result.title or result.script
        detail = f"{result.script}: {title}"
        if ids:
            detail += f" [{ids}]"
        if result.vulnerable:
            headline = f"NSE {result.state}: {result.script}"
            severity = "vulnerable"
            kind = "vuln"
        else:
            headline = f"NSE check inconclusive: {result.script}"
            severity = "info"
            kind = "vuln-check"
            detail += " — no verdict reached (not the same as 'not vulnerable'); re-run this "
            detail += "single check against the port on its own."
        findings.append(
            Finding(
                service=service,
                title=headline,
                detail=detail,
                port=result.port or None,
                proto=result.proto,
                fields={
                    "kind": kind,
                    "value": result.script,
                    "severity": severity,
                    "state": result.state or "no verdict",
                    "ids": ids,
                    "risk": result.risk,
                    "note": detail,
                },
            )
        )
    return findings


def summary_lines(results: list[VulnResult]) -> list[str]:
    """The verdict readout the panels / CLI show: hits, then checks that reached no verdict, then
    how many came back clean — so 'nothing found' is always backed by a count of what ran."""
    lines: list[str] = []
    hits = [r for r in results if r.vulnerable]
    unknown = [r for r in results if r.inconclusive]
    for result in hits:
        ids = f"  [{', '.join(result.ids)}]" if result.ids else ""
        risk = f"  risk: {result.risk}" if result.risk else ""
        lines.append(f"‼ {result.state}: {result.script}{ids}{risk}")
        if result.title and result.title != result.script:
            lines.append(f"    {result.title}")
    for result in unknown:
        reason = result.state or result.title or "no verdict"
        lines.append(
            f"⚠ could not check: {result.script} — {reason} (NOT the same as 'not vulnerable')"
        )
    clean = len(results) - len(hits) - len(unknown)
    if not results:
        lines.append("No NSE script output — the scan found nothing to check on these ports.")
    elif not hits:
        lines.append(f"No script reported VULNERABLE. {clean} check(s) came back clean.")
    else:
        lines.append(f"{len(hits)} hit(s); {clean} check(s) clean.")
    return lines
