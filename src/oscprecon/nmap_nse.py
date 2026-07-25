from __future__ import annotations

from pathlib import Path

# NSE script names for the scan dialog's searchable picker. Sourced LIVE from the host's nmap
# scripts dir when present (so it reflects the installed nmap — full coverage), else a curated
# offline fallback so the picker still works on a non-Kali/dev box and stays deterministic in tests.
# Brute scripts are filtered out: the shell policy blocks them at run time (§2), so offering one
# would only build a command that then gets refused. oracle-sid-brute is the single allowed
# exception — it enumerates SIDs (identifiers), not passwords (mirrors shell._NMAP_RECON_BRUTE).

_SCRIPTS_DIR = Path("/usr/share/nmap/scripts")
_ALLOWED_RECON_BRUTE = frozenset({"oracle-sid-brute"})

# Always offered alongside individual scripts — the common `--script <category>` selectors. The
# 'brute' category is deliberately absent (it's the credential-attack category, blocked by §2).
_CATEGORIES: tuple[str, ...] = ("default", "discovery", "safe", "version", "vuln")

# Curated offline fallback — the NSE most useful for OSCP recon, one line per service group.
_CURATED: tuple[str, ...] = (
    "banner",
    "address-info",
    # FTP
    "ftp-anon",
    "ftp-syst",
    "ftp-bounce",
    "ftp-vsftpd-backdoor",
    "ftp-proftpd-backdoor",
    # SSH
    "ssh-hostkey",
    "ssh2-enum-algos",
    "ssh-auth-methods",
    # SMTP / mail
    "smtp-commands",
    "smtp-open-relay",
    "smtp-ntlm-info",
    "smtp-enum-users",
    "smtp-strangeport",
    "imap-capabilities",
    "pop3-capabilities",
    # DNS
    "dns-nsid",
    "dns-recursion",
    "dns-cache-snoop",
    "dns-service-discovery",
    "dns-zone-transfer",
    # HTTP
    "http-title",
    "http-headers",
    "http-methods",
    "http-enum",
    "http-robots.txt",
    "http-server-header",
    "http-security-headers",
    "http-webdav-scan",
    "http-git",
    "http-config-backup",
    "http-cors",
    "http-auth",
    "http-wordpress-enum",
    "http-shellshock",
    "http-put",
    "http-favicon",
    "http-generator",
    "http-ntlm-info",
    "http-userdir-enum",
    "http-slowloris-check",
    "http-vuln-cve2017-5638",
    "http-vuln-cve2015-1635",
    # TLS / SSL
    "ssl-cert",
    "ssl-enum-ciphers",
    "ssl-heartbleed",
    "ssl-poodle",
    "ssl-dh-params",
    "ssl-ccs-injection",
    "sslv2",
    "sslv2-drown",
    "tls-alpn",
    "tls-nextprotoneg",
    # SMB / Windows
    "smb-os-discovery",
    "smb-protocols",
    "smb-security-mode",
    "smb2-security-mode",
    "smb2-capabilities",
    "smb2-time",
    "smb-enum-shares",
    "smb-enum-users",
    "smb-enum-sessions",
    "smb-enum-domains",
    "smb-enum-groups",
    "smb-enum-services",
    "smb-mbenum",
    "smb-system-info",
    "smb-vuln-ms17-010",
    "smb-vuln-ms08-067",
    "smb-vuln-cve-2017-7494",
    "smb-double-pulsar-backdoor",
    # RPC / NetBIOS / LDAP
    "msrpc-enum",
    "rpcinfo",
    "rpc-grind",
    "nbstat",
    "ldap-rootdse",
    "ldap-search",
    # SNMP
    "snmp-info",
    "snmp-sysdescr",
    "snmp-processes",
    "snmp-interfaces",
    "snmp-netstat",
    "snmp-win32-services",
    "snmp-win32-users",
    "snmp-win32-software",
    # NFS
    "nfs-showmount",
    "nfs-statfs",
    "nfs-ls",
    # RDP / VNC
    "rdp-ntlm-info",
    "rdp-enum-encryption",
    "vnc-info",
    "vnc-title",
    "realvnc-auth-bypass",
    # Databases
    "ms-sql-info",
    "ms-sql-ntlm-info",
    "mysql-info",
    "mysql-variables",
    "mysql-databases",
    "oracle-tns-version",
    "oracle-sid-brute",
    "redis-info",
    "mongodb-info",
    "mongodb-databases",
    # Misc services
    "rsync-list-modules",
    "tftp-enum",
    "finger",
    "irc-info",
    "rmi-dumpregistry",
    "ajp-methods",
    "x11-access",
    "ike-version",
    "ntp-info",
    "clock-skew",
    "telnet-ntlm-info",
)


def _is_allowed(name: str) -> bool:
    return "brute" not in name or name in _ALLOWED_RECON_BRUTE


# the credential-attack scripts the recon policy refuses. Read from the installed nmap when present
# so the check reflects reality; the curated fallback keeps a dev/CI box (no nmap) deterministic.
_FALLBACK_BRUTE: tuple[str, ...] = (
    "afp-brute",
    "ajp-brute",
    "backorifice-brute",
    "cassandra-brute",
    "cics-user-brute",
    "citrix-brute-xml",
    "cvs-brute",
    "cvs-brute-repository",
    "deluge-rpc-brute",
    "dpap-brute",
    "drda-brute",
    "ftp-brute",
    "http-brute",
    "http-form-brute",
    "http-joomla-brute",
    "http-proxy-brute",
    "http-wordpress-brute",
    "iax2-brute",
    "imap-brute",
    "impress-remote-brute",
    "informix-brute",
    "ipmi-brute",
    "irc-brute",
    "irc-sasl-brute",
    "iscsi-brute",
    "ldap-brute",
    "membase-brute",
    "metasploit-msgrpc-brute",
    "metasploit-xmlrpc-brute",
    "mikrotik-routeros-brute",
    "mmouse-brute",
    "mongodb-brute",
    "ms-sql-brute",
    "mysql-brute",
    "nessus-brute",
    "netbus-brute",
    "nexpose-brute",
    "nje-node-brute",
    "nje-pass-brute",
    "nping-brute",
    "omp2-brute",
    "openvas-otp-brute",
    "oracle-brute",
    "oracle-brute-stealth",
    "pcanywhere-brute",
    "pgsql-brute",
    "pop3-brute",
    "redis-brute",
    "rexec-brute",
    "rlogin-brute",
    "rpcap-brute",
    "rsync-brute",
    "rtsp-url-brute",
    "sip-brute",
    "smb-brute",
    "smtp-brute",
    "snmp-brute",
    "socks-brute",
    "ssh-brute",
    "svn-brute",
    "telnet-brute",
    "vmauthd-brute",
    "vnc-brute",
    "vtam-brute",
    "xmpp-brute",
)


def brute_script_names(scripts_dir: Path | None = None) -> frozenset[str]:
    """Every installed NSE script the recon policy treats as a credential attack.

    Needed because a GLOB selector is judged by expansion, not by its own text: `--script 'smb-*'`
    contains no "brute" substring but matches smb-brute. See shell.policy_violation.
    """
    directory = scripts_dir if scripts_dir is not None else _SCRIPTS_DIR
    try:
        names = {p.stem for p in directory.glob("*.nse")}
    except OSError:
        names = set()
    if not names:
        names = set(_FALLBACK_BRUTE)
    return frozenset(n for n in names if not _is_allowed(n))


def list_scripts(scripts_dir: Path | None = None) -> tuple[str, ...]:
    """Sorted NSE script names + category selectors, brute scripts filtered (§2).

    Reads the host's nmap scripts dir if it exists; otherwise uses the curated offline set.
    """
    directory = scripts_dir if scripts_dir is not None else _SCRIPTS_DIR
    names: set[str] = set()
    try:
        names = {p.stem for p in directory.glob("*.nse")}
    except OSError:
        names = set()
    if not names:
        names = set(_CURATED)
    return tuple(sorted(n for n in (names | set(_CATEGORIES)) if _is_allowed(n)))
