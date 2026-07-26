from __future__ import annotations

from dataclasses import dataclass

# Per-service nmap/NSE scan matrix — DATA ONLY.
#
# What this answers: "nmap found <name> on <port>; which NSE scripts are worth running, and what
# do I get out of them?" Every row names the ports that signal the service, the nmap service names
# that identify it, and the NSE filename prefixes that target it.
#
# DERIVED, NOT GUESSED. Three sources, all on a stock Kali box:
#   * /usr/share/nmap/scripts/script.db  — the 612 installed scripts. Every prefix below was
#     resolved against it; counts are recorded in the table at the bottom of this comment.
#   * /usr/share/nmap/nmap-services     — the port -> service-name table nmap uses with no -sV.
#   * /usr/share/nmap/nmap-service-probes — the names -sV actually PRINTS (they differ: 6443/tcp
#     is "sun-sr-https" in nmap-services but a Kubernetes API server answers as ssl/http).
#
# MATCH ORDER IS THE POINT. for_service() resolves the nmap SERVICE NAME first and the port only
# as a fallback, because a default port is the weakest signal on the board: FTP runs on 2121, HTTP
# on 5000, SSH on 2222, and 8080 is as often a bare web server as it is a proxy. A port-first
# lookup would call all three wrong. Product strings refine the generic web rows (nmap reports
# Tomcat, Jenkins and IIS all as plain "http" — the app name only ever appears in the product).
#
# DEAD PREFIXES ARE DROPPED. A prefix matching no installed script is not a no-op — nmap exits
# with "'x-*' did not match a category, filename, or directory" and the whole scan dies. Four
# prefixes from the requested matrix resolve to ZERO scripts on a stock install and were dropped:
#   * zookeeper-*  — nmap ships no ZooKeeper scripts (the 4lw commands have no NSE equivalent)
#   * radius-*     — no RADIUS scripts; radius has no prefix at all here, only ports + names
#   * dnp3-*       — no DNP3 scripts; ditto
#   * rsh-*        — no RSH scripts; the r-services fall back to `banner`
# Two more were left out on POLICY, not availability: rexec-* and rlogin-* each resolve to exactly
# one script and both are brute-category (rexec-brute, rlogin-brute). A prefix whose only member
# is a credential brute has no place in a recon-default catalog (CLAUDE.md 2, Tier 3), so those
# rows carry `banner` instead. Broad prefixes (ftp-*, smb-*) do contain brute scripts; excluding
# them is the policy layer's job, not this table's.
#
# WHERE A SERVICE HAS NO SCRIPTS OF ITS OWN, the row is still worth having: it carries the ports
# and names so a caller can identify the service, and it borrows the prefix that actually applies
# — http-*/ssl-* for the many HTTP-fronted APIs (Kubernetes, etcd, Consul, Prometheus, Grafana,
# Splunk, Elasticsearch, Neo4j, RabbitMQ's management UI), or `banner` for a plain TCP listener.
# Two rows (radius, dnp3) have NO prefixes at all; that is the honest answer, not an oversight.
#
# PREFIX -> INSTALLED SCRIPT COUNT, resolved against a stock Kali script.db:
#   smb-* 31 · smb2-* 4 · nbstat 1 · nbns-* 1 · broadcast-netbios-master-browser 1 · msrpc-* 1
#   rdp-* 3 · ldap-* 4 · krb5-* 1 · dns-* 18 · ftp-* 8 · ssh-* 5 · telnet-* 3 · tftp-* 2
#   rsync-* 2 · afp-* 5 · nfs-* 3 · rpcinfo 1 · rpc-grind 1 · rusers 1 · vnc-* 3 · realvnc-* 1
#   x11-* 1 · iscsi-* 2 · http-* 134 · ssl-* 9 · tls-* 3 · sslv2-* 1 · ajp-* 5
#   socks-auth-info 1 · socks-open-proxy 1 · http-webdav-scan 1 · http-iis-webdav-vuln 1
#   http-wordpress-* 3 · http-drupal-* 2 · http-joomla-* 1 · http-iis-* 2 · http-aspnet-* 1
#   http-ntlm-info 1 · http-apache-* 2 · http-coldfusion-* 1 · http-adobe-coldfusion-apsa1301 1
#   smtp-* 9 · pop3-* 3 · imap-* 3 · nntp-* 1 · ms-sql-* 11 · mysql-* 11 · pgsql-* 1 · oracle-* 5
#   db2-* 1 · drda-* 2 · mongodb-* 3 · redis-* 2 · couchdb-* 2 · cassandra-* 2 · memcached-* 1
#   informix-* 3 · riak-http-info 1 · docker-* 1 · amqp-* 1 · mqtt-* 1 · http-svn-* 2 · jdwp-* 4
#   rmi-* 2 · epmd-* 1 · distcc-* 1 · dhcp-* 1 · broadcast-dhcp-* 1 · ntp-* 2 · snmp-* 12
#   ipmi-* 3 · supermicro-ipmi-conf 1 · ike-* 1 · sip-* 4 · rtsp-* 2 · upnp-* 1 · broadcast-upnp-* 1
#   llmnr-resolve 1 · dns-service-discovery 1 · broadcast-dns-service-discovery 1 · wsdd-discover 1
#   broadcast-wsdd-discover 1 · cups-* 2 · pjl-* 1 · rpcap-* 2 · nbd-* 1 · finger 1 · auth-owners 1
#   auth-spoof 1 · irc-* 5 · banner 1 · pgsql-* 1 · modbus-* 1 · s7-* 1 · bacnet-* 1 · enip-* 1
#   iec61850-* 1 · iec-identify 1 · coap-* 1 · knx-* 2 · hartip-* 1 · omron-* 1 · profinet-* 1
#
# tests/test_nse_matrix.py re-derives every one of those counts from script.db, so the table above
# is checkable rather than a claim.


@dataclass(frozen=True)
class ServiceScripts:
    key: str  # stable slug — also a valid Python identifier fragment
    label: str
    tcp_ports: tuple[int, ...]
    udp_ports: tuple[int, ...]
    prefixes: tuple[str, ...]  # NSE filename prefixes, e.g. ("smb-*", "smb2-*")
    # nmap service names that identify this service. App-server / CMS rows (tomcat, jenkins, iis,
    # wordpress …) carry -sV PRODUCT tokens here instead: nmap reports every one of them as the
    # service name "http", so the product string is the only thing that names the app.
    names: tuple[str, ...]
    note: str = ""  # what an operator gets from this service's scripts
    fragile: bool = False  # OT/ICS and similar — even a discovery script can disturb it


# Ordering is load-bearing in two places: the port fallback is first-declared-wins (so the generic
# `http` row owns 8080, not tomcat/jenkins), and the OT rows sit last so a shared port like 102 or
# 2222 resolves to the mainstream service before the ICS one.
MATRIX: tuple[ServiceScripts, ...] = (
    # ── Windows / Active Directory / identity ────────────────────────────────────────────────
    ServiceScripts(
        key="netbios",
        label="NetBIOS name service",
        # why: declared BEFORE smb, and with no TCP port of its own. Both rows legitimately claim
        # 137/138 — this one wins them because nbstat/nbns are the scripts that run there — while
        # 139 stays with smb, where the smb-*/smb2-* portrules actually fire.
        tcp_ports=(),
        udp_ports=(137, 138),
        prefixes=("nbstat", "nbns-*", "broadcast-netbios-master-browser"),
        names=("netbios-ns", "netbios-dgm"),
        note="NetBIOS name table, MAC address and logged-on workstation name — often names the "
        "host and domain when 445 is filtered.",
    ),
    ServiceScripts(
        key="smb",
        label="SMB / CIFS",
        tcp_ports=(139, 445),
        udp_ports=(137, 138),
        prefixes=("smb-*", "smb2-*"),
        # why: 139 is the SMB-over-NetBIOS session port, so netbios-ssn belongs to SMB, not to the
        # netbios row — nbstat is a 137/udp name-service check and answers a different question.
        names=("microsoft-ds", "netbios-ssn"),
        note="OS/domain/build, dialects and signing state, share list, users, sessions, services "
        "— the single richest unauthenticated surface on a Windows box.",
    ),
    ServiceScripts(
        key="msrpc",
        label="MSRPC / DCE-RPC endpoint mapper",
        tcp_ports=(135, 593),
        udp_ports=(135,),
        prefixes=("msrpc-*",),
        names=("msrpc", "ncacn_http", "http-rpc-epmap"),
        note="Endpoint-mapper dump: which RPC interfaces the host exposes and on which dynamic "
        "high ports, so the 49152+ range stops being noise.",
    ),
    ServiceScripts(
        key="rdp",
        label="RDP / Terminal Services",
        tcp_ports=(3389,),
        udp_ports=(3389,),
        prefixes=("rdp-*",),
        names=("ms-wbt-server", "ms-wbt-server-proxy"),
        note="Encryption/NLA level and an NTLM handshake that leaks hostname, domain, forest and "
        "OS build without credentials.",
    ),
    ServiceScripts(
        key="winrm",
        label="WinRM (HTTP)",
        tcp_ports=(5985, 47001),
        udp_ports=(),
        prefixes=("http-*",),
        names=("wsman", "winrm"),
        note="WinRM is HTTP underneath — http-ntlm-info against /wsman leaks the domain and "
        "hostname, and confirms the port is a real management endpoint.",
    ),
    ServiceScripts(
        key="winrm_https",
        label="WinRM (HTTPS)",
        tcp_ports=(5986,),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=("wsmans",),
        note="Same as WinRM/HTTP plus the certificate — the cert CN/SAN routinely names the host "
        "and domain outright.",
    ),
    ServiceScripts(
        key="ldap",
        label="LDAP",
        tcp_ports=(389,),
        udp_ports=(389,),
        prefixes=("ldap-*",),
        names=("ldap",),
        note="Root DSE and naming contexts anonymously: domain/forest FQDN, DC name, functional "
        "level — then ldap-search for users and groups if the bind is open.",
    ),
    ServiceScripts(
        key="ldaps",
        label="LDAPS",
        tcp_ports=(636,),
        udp_ports=(),
        prefixes=("ldap-*", "ssl-*"),
        names=("ldapssl", "ldaps"),
        note="LDAP over TLS — the same root-DSE enumeration, plus a certificate that names the DC.",
    ),
    ServiceScripts(
        key="globalcat",
        label="Global Catalog (LDAP)",
        tcp_ports=(3268, 3269),
        udp_ports=(),
        prefixes=("ldap-*", "ssl-*"),
        names=("globalcatldap", "globalcatldapssl"),
        note="Forest-wide LDAP view — returns objects from every domain in the forest, not just "
        "this DC's own.",
    ),
    ServiceScripts(
        key="kerberos",
        label="Kerberos",
        tcp_ports=(88, 464),
        udp_ports=(88, 464),
        prefixes=("krb5-*",),
        names=("kerberos-sec", "kerberos", "kpasswd5", "kpasswd"),
        note="Confirms the host is a KDC and gives the realm; krb5-enum-users separates valid "
        "principals from invalid ones by error code alone.",
    ),
    ServiceScripts(
        key="dns",
        label="DNS / AD-integrated DNS",
        tcp_ports=(53, 853),
        udp_ports=(53,),
        prefixes=("dns-*",),
        names=("domain", "domain-s"),
        note="Zone transfer, SRV records (_ldap/_kerberos name every DC), NSID, recursion state "
        "and cache snooping — on a DC this maps the whole domain.",
    ),
    # ── File transfer / remote access ────────────────────────────────────────────────────────
    ServiceScripts(
        key="ftp",
        label="FTP",
        tcp_ports=(20, 21, 2121),
        udp_ports=(),
        prefixes=("ftp-*",),
        names=("ftp",),
        note="Anonymous login and the resulting directory listing, SYST fingerprint, bounce-scan "
        "support, and the vsftpd/ProFTPD backdoor checks.",
    ),
    ServiceScripts(
        key="ftps",
        label="FTPS (implicit TLS)",
        tcp_ports=(989, 990),
        udp_ports=(),
        prefixes=("ftp-*", "ssl-*"),
        names=("ftps", "ftps-data"),
        note="Same FTP checks over TLS, plus the certificate and cipher inventory.",
    ),
    ServiceScripts(
        key="ssh",
        label="SSH / SFTP",
        tcp_ports=(22, 2222),
        udp_ports=(),
        prefixes=("ssh-*",),
        names=("ssh",),
        note="Host-key fingerprints and accepted auth methods — 'publickey only' vs 'password' "
        "decides whether a found credential is even usable here.",
    ),
    ServiceScripts(
        key="telnet",
        label="Telnet",
        tcp_ports=(23,),
        udp_ports=(),
        prefixes=("telnet-*",),
        names=("telnet",),
        note="Whether the session encrypts at all, and an NTLM info leak on Windows telnet.",
    ),
    ServiceScripts(
        key="tftp",
        label="TFTP",
        tcp_ports=(),
        udp_ports=(69,),
        prefixes=("tftp-*",),
        names=("tftp",),
        note="TFTP has no listing protocol, so enumeration is filename guessing — this is the "
        "cheap way to find router configs and backups sitting on 69/udp.",
    ),
    ServiceScripts(
        key="rexec",
        label="Rexec (r-services)",
        tcp_ports=(512,),
        udp_ports=(),
        # why: nmap's only rexec script is rexec-brute (brute category) — deliberately not listed;
        # `banner` still confirms the daemon is live.
        prefixes=("banner",),
        names=("exec", "rexec"),
        note="A live r-service means cleartext credentials on the wire and probable .rhosts trust.",
    ),
    ServiceScripts(
        key="rlogin",
        label="Rlogin (r-services)",
        tcp_ports=(513,),
        udp_ports=(),
        prefixes=("banner",),  # only rlogin-brute exists; brute category, excluded
        names=("login", "rlogin"),
        note="Pairs with rexec/rsh — check for a permissive .rhosts or hosts.equiv trust.",
    ),
    ServiceScripts(
        key="rsh",
        label="RSH (r-services)",
        tcp_ports=(514,),
        udp_ports=(),
        prefixes=("banner",),  # nmap ships no rsh-* scripts at all
        names=("shell", "rsh"),
        note="No NSE coverage exists; the useful signal is simply that it is open next to 512/513.",
    ),
    ServiceScripts(
        key="rsync",
        label="rsync",
        tcp_ports=(873,),
        udp_ports=(),
        prefixes=("rsync-*",),
        names=("rsync",),
        note="Module list without authentication — an unauth module is a readable (often "
        "writable) filesystem tree.",
    ),
    ServiceScripts(
        key="afp",
        label="AFP (Apple Filing Protocol)",
        tcp_ports=(548,),
        udp_ports=(),
        prefixes=("afp-*",),
        names=("afp",),
        note="Server info (machine name, AFP versions, UAMs), guest-accessible share list and a "
        "recursive listing of what guest can read.",
    ),
    ServiceScripts(
        key="rpcbind",
        label="RPC portmapper (SunRPC)",
        tcp_ports=(111,),
        udp_ports=(111,),
        prefixes=("rpcinfo", "rpc-grind", "rusers"),
        names=("rpcbind", "portmap", "portmapper", "sunrpc"),
        note="The program/version/port table for every RPC service on the host — the way you find "
        "mountd, nlockmgr, ypserv and NFS on their real high ports.",
    ),
    ServiceScripts(
        key="nfs",
        label="NFS",
        tcp_ports=(111, 2049),
        udp_ports=(111, 2049),
        prefixes=("nfs-*", "rpcinfo"),
        names=("nfs", "nfs_acl", "mountd", "nlockmgr"),
        note="Exported shares and who may mount them, plus a read-only recursive listing with "
        "uid/gid and mode — no_root_squash shows up here.",
    ),
    ServiceScripts(
        key="vnc",
        label="VNC",
        # why: the real range is 5900-5999 (one port per display) plus the 5800 Java viewer;
        # listing the first handful keeps the tuple usable — name matching covers the rest.
        tcp_ports=(5800, 5801, 5900, 5901, 5902, 5903, 5904, 5905, 5906),
        udp_ports=(),
        prefixes=("vnc-*", "realvnc-*"),
        names=("vnc", "vnc-http", "nuuo-vnc"),
        note="Protocol version, offered security types (type 1 = none at all) and the desktop "
        "title, which frequently names the logged-on user.",
    ),
    ServiceScripts(
        key="x11",
        label="X11",
        tcp_ports=(6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009),
        udp_ports=(),
        prefixes=("x11-*",),
        names=("x11",),
        note="Whether the display accepts unauthenticated clients (xhost +) — that is keylogging "
        "and screenshots of a live desktop.",
    ),
    ServiceScripts(
        key="iscsi",
        label="iSCSI",
        tcp_ports=(3260,),
        udp_ports=(),
        prefixes=("iscsi-*",),
        names=("iscsi",),
        note="Target IQNs and whether they need CHAP — an unauthenticated target is a raw block "
        "device you can attach and mount.",
    ),
    # ── Web / TLS / application servers ──────────────────────────────────────────────────────
    ServiceScripts(
        key="http",
        label="HTTP",
        tcp_ports=(80, 81, 591, 5000, 8000, 8008, 8080, 8081, 8180, 8880, 8888, 9000),
        udp_ports=(),
        prefixes=("http-*",),
        # why: "http-proxy" lives here, not on the proxy row. nmap labels a plain web server on
        # 8080 "http-proxy" far more often than it finds an actual open proxy, so treating the
        # name as a proxy would misroute most 8080 findings.
        names=("http", "http-alt", "http-proxy"),
        note="Title, headers, methods, server banner, robots.txt, favicon hash, exposed .git and "
        "the whole http-enum sweep — the widest script family nmap ships (134 scripts).",
    ),
    ServiceScripts(
        key="https",
        label="HTTPS",
        tcp_ports=(443, 4443, 8443, 9443, 10443),
        udp_ports=(),
        prefixes=("http-*", "ssl-*", "tls-*", "sslv2-*"),
        names=("https", "https-alt", "ssl/http", "ssl/https"),
        note="Everything the HTTP row gives, plus the certificate — CN and SAN entries hand you "
        "vhosts and internal hostnames a port scan never sees.",
    ),
    ServiceScripts(
        key="tls",
        label="TLS on any port",
        # why: no ports and no names on purpose. This row is not something for_service() returns —
        # it is the set a caller layers onto ANY port -sV reported as ssl/…, which is where these
        # checks actually belong (SMTPS, LDAPS, a TLS-wrapped database).
        tcp_ports=(),
        udp_ports=(),
        prefixes=("ssl-*", "tls-*", "sslv2-*"),
        names=(),
        note="Certificate, expiry, cipher/protocol inventory, DH parameters and the classic TLS "
        "flaws (Heartbleed, POODLE, DROWN, CCS injection, ticketbleed).",
    ),
    ServiceScripts(
        key="ajp",
        label="AJP (Apache JServ)",
        tcp_ports=(8009,),
        udp_ports=(),
        prefixes=("ajp-*",),
        names=("ajp13", "ajp12"),
        note="Allowed methods and response headers over AJP — an exposed 8009 is a back door "
        "into the servlet container that bypasses the HTTP connector's controls.",
    ),
    ServiceScripts(
        key="proxy",
        label="HTTP proxy",
        tcp_ports=(3128, 8118),
        udp_ports=(),
        prefixes=("http-*",),
        names=("squid-http", "squid", "http-proxy-ctrl", "privoxy"),
        note="http-open-proxy decides whether the box will relay for you — an open proxy is a "
        "pivot into whatever network it can reach.",
    ),
    ServiceScripts(
        key="socks",
        label="SOCKS proxy",
        tcp_ports=(1080, 9050),
        udp_ports=(),
        # why: socks-brute exists but is brute category and stays out; these two are pure recon.
        prefixes=("socks-auth-info", "socks-open-proxy"),
        names=("socks", "socks4", "socks5"),
        note="Which SOCKS auth methods are offered, and whether it will proxy for a client with "
        "no credentials — same pivot value as an open HTTP proxy.",
    ),
    ServiceScripts(
        key="tomcat",
        label="Apache Tomcat",
        tcp_ports=(8080, 8009, 8443, 8180),
        udp_ports=(),
        prefixes=("http-*", "ajp-*"),
        names=("tomcat", "apache tomcat", "coyote"),
        note="Version from the error pages, /manager and /host-manager exposure, and the AJP "
        "connector alongside — the two doors are usually the same box.",
    ),
    ServiceScripts(
        key="jenkins",
        label="Jenkins",
        tcp_ports=(8080,),
        udp_ports=(),
        prefixes=("http-*",),
        names=("jenkins",),
        note="Whether /script, /asynchPeople and the job list answer anonymously; the X-Jenkins "
        "header in http-headers gives the exact version.",
    ),
    ServiceScripts(
        key="webdav",
        label="WebDAV",
        tcp_ports=(80, 443, 8080),
        udp_ports=(),
        prefixes=("http-webdav-scan", "http-iis-webdav-vuln"),
        names=("webdav",),
        note="Which DAV methods the server accepts and on which paths — a writable PUT/MOVE pair "
        "is a file upload primitive.",
    ),
    ServiceScripts(
        key="wordpress",
        label="WordPress",
        tcp_ports=(80, 443),
        udp_ports=(),
        prefixes=("http-wordpress-*", "http-*"),
        names=("wordpress",),
        note="Core version plus installed themes and plugins with their versions, and the author "
        "enumeration that turns ?author=N into real usernames.",
    ),
    ServiceScripts(
        key="drupal",
        label="Drupal",
        tcp_ports=(80, 443),
        udp_ports=(),
        prefixes=("http-drupal-*", "http-*"),
        names=("drupal",),
        note="Enabled modules and themes with versions, and username enumeration via the user "
        "endpoints.",
    ),
    ServiceScripts(
        key="joomla",
        label="Joomla",
        tcp_ports=(80, 443),
        udp_ports=(),
        # why: nmap's only joomla script is http-joomla-brute (brute category), so the useful work
        # here comes from the generic web family; the prefix is kept because the row must still
        # name what exists.
        prefixes=("http-joomla-*", "http-*"),
        names=("joomla",),
        note="Version comes from the generic web checks (README.txt, /administrator, meta "
        "generator) — nmap has no Joomla enumeration script, only a brute.",
    ),
    ServiceScripts(
        key="iis",
        label="Microsoft IIS / ASP.NET",
        tcp_ports=(80, 443),
        udp_ports=(),
        prefixes=("http-iis-*", "http-aspnet-*", "http-ntlm-info", "http-*"),
        names=("iis", "microsoft iis", "microsoft-iis", "httpapi"),
        note="8.3 short-name disclosure, the WebDAV auth bypass, ASP.NET debug state, and the "
        "NTLM leak that names the host, domain and OS build.",
    ),
    ServiceScripts(
        key="apache",
        label="Apache httpd",
        tcp_ports=(80, 443),
        udp_ports=(),
        prefixes=("http-apache-*", "http-*"),
        names=("apache httpd",),
        note="Exposed /server-status and /server-info, and mod_negotiation filename disclosure "
        "that leaks file names the wordlist never had.",
    ),
    ServiceScripts(
        key="coldfusion",
        label="Adobe ColdFusion",
        # why: ColdFusion's built-in web server sits on 8500, but that port is left to the consul
        # row — a bare 8500 is far more often Consul, and ColdFusion is identified by product.
        tcp_ports=(80, 443),
        udp_ports=(),
        prefixes=("http-coldfusion-*", "http-adobe-coldfusion-apsa1301", "http-*"),
        names=("coldfusion", "adobe coldfusion"),
        note="CFIDE administrator exposure and the version behind it — ColdFusion's admin panel "
        "is a routine foothold when it answers unauthenticated; also check 8500.",
    ),
    # ── Email ───────────────────────────────────────────────────────────────────────────────
    ServiceScripts(
        key="smtp",
        label="SMTP",
        tcp_ports=(25,),
        udp_ports=(),
        prefixes=("smtp-*",),
        names=("smtp",),
        note="EHLO capability list, open-relay test, and VRFY/EXPN/RCPT user enumeration — a "
        "valid-username oracle before any credential is in hand.",
    ),
    ServiceScripts(
        key="smtps",
        label="SMTPS (implicit TLS)",
        tcp_ports=(465,),
        udp_ports=(),
        prefixes=("smtp-*", "ssl-*"),
        names=("smtps",),
        note="The SMTP checks over TLS, plus the certificate (which often names the mail domain).",
    ),
    ServiceScripts(
        key="submission",
        label="SMTP submission",
        tcp_ports=(587,),
        udp_ports=(),
        prefixes=("smtp-*", "ssl-*"),
        names=("submission",),
        note="The authenticated-submission port: its EHLO list shows which SASL mechanisms are "
        "offered, and whether STARTTLS is enforced before AUTH.",
    ),
    ServiceScripts(
        key="pop3",
        label="POP3",
        tcp_ports=(110,),
        udp_ports=(),
        prefixes=("pop3-*",),
        names=("pop3", "pop3pw"),
        note="CAPA list and the NTLM leak — on Exchange, pop3-ntlm-info returns the hostname, "
        "domain and OS build unauthenticated.",
    ),
    ServiceScripts(
        key="pop3s",
        label="POP3S",
        tcp_ports=(995,),
        udp_ports=(),
        prefixes=("pop3-*", "ssl-*"),
        names=("pop3s",),
        note="Same POP3 checks over TLS, plus certificate details.",
    ),
    ServiceScripts(
        key="imap",
        label="IMAP",
        tcp_ports=(143,),
        udp_ports=(),
        prefixes=("imap-*",),
        names=("imap",),
        note="Capability list and the same NTLM information leak Exchange gives on POP3.",
    ),
    ServiceScripts(
        key="imaps",
        label="IMAPS",
        tcp_ports=(993,),
        udp_ports=(),
        prefixes=("imap-*", "ssl-*"),
        names=("imaps",),
        note="Same IMAP checks over TLS, plus certificate details.",
    ),
    ServiceScripts(
        key="nntp",
        label="NNTP",
        tcp_ports=(119, 563),
        udp_ports=(),
        prefixes=("nntp-*", "ssl-*"),
        names=("nntp", "snews"),
        note="nmap's only NNTP script is the NTLM info leak — on a Windows news server that is "
        "still a free hostname/domain/build disclosure.",
    ),
    # ── Databases ───────────────────────────────────────────────────────────────────────────
    ServiceScripts(
        key="mssql",
        label="Microsoft SQL Server",
        tcp_ports=(1433,),
        udp_ports=(1434,),
        prefixes=("ms-sql-*",),
        names=("ms-sql-s", "ms-sql-m", "mssql"),
        note="Instance name, version and the browser-service reply on 1434/udp; with credentials, "
        "database and table enumeration and the hash dump.",
    ),
    ServiceScripts(
        key="mysql",
        label="MySQL / MariaDB",
        tcp_ports=(3306, 33060),
        udp_ports=(),
        prefixes=("mysql-*",),
        names=("mysql", "mysqlx", "mariadb"),
        note="Version and capability flags, the empty-root-password check, and with access, the "
        "user list, grants, variables and a CIS-style audit.",
    ),
    ServiceScripts(
        key="postgresql",
        label="PostgreSQL",
        tcp_ports=(5432, 5433),
        udp_ports=(),
        # why: pgsql-* resolves to exactly one script and it is brute category — kept because the
        # prefix is live and the policy layer gates brute, but it is NOT enumeration.
        prefixes=("pgsql-*", "ssl-*"),
        names=("postgresql", "postgres", "psql"),
        note="nmap has no unauthenticated PostgreSQL enumeration script (pgsql-brute is the only "
        "one) — take the version from -sV and the certificate from the ssl family.",
    ),
    ServiceScripts(
        key="oracle",
        label="Oracle TNS",
        tcp_ports=(1521, 2483, 2484),
        udp_ports=(),
        prefixes=("oracle-*",),
        names=("oracle", "oracle-tns", "oracle-nm", "ttc", "ttc-ssl"),
        note="TNS listener version and the SID — without a valid SID nothing else on Oracle is "
        "reachable, so this is the gate.",
    ),
    ServiceScripts(
        key="db2",
        label="IBM DB2 / DRDA",
        tcp_ports=(523, 50000),
        udp_ports=(523,),
        prefixes=("db2-*", "drda-*"),
        names=("ibm-db2", "drda", "db2"),
        note="DAS server version and instance details, plus DRDA server/platform identification.",
    ),
    ServiceScripts(
        key="mongodb",
        label="MongoDB",
        tcp_ports=(27017, 27018, 27019),
        udp_ports=(),
        prefixes=("mongodb-*",),
        names=("mongod", "mongos", "mongodb"),
        note="Build info and, when authentication is off, the full database list — an unauth "
        "MongoDB is a data dump with no further work.",
    ),
    ServiceScripts(
        key="redis",
        label="Redis",
        tcp_ports=(6379, 6380),
        udp_ports=(),
        prefixes=("redis-*",),
        names=("redis",),
        note="INFO output when no AUTH is required: version, role, config file path and connected "
        "clients — the config path is what makes an unauth Redis dangerous.",
    ),
    ServiceScripts(
        key="couchdb",
        label="CouchDB",
        tcp_ports=(5984, 6984),
        udp_ports=(),
        prefixes=("couchdb-*", "http-*"),
        names=("couchdb",),
        note="Database list and server statistics over its HTTP API — an admin-party CouchDB "
        "answers both without credentials.",
    ),
    ServiceScripts(
        key="cassandra",
        label="Cassandra",
        tcp_ports=(9042, 9160),
        udp_ports=(),
        prefixes=("cassandra-*",),
        names=("cassandra", "cassandra-native", "apani1"),
        note="Cluster name and version over the Thrift port; the native CQL port on 9042 needs a "
        "client for anything deeper.",
    ),
    ServiceScripts(
        key="memcached",
        label="Memcached",
        tcp_ports=(11211,),
        udp_ports=(11211,),
        prefixes=("memcached-*",),
        names=("memcache", "memcached"),
        note="Version, uptime and slab statistics with no authentication — memcached has none, so "
        "an exposed port is already a data leak.",
    ),
    ServiceScripts(
        key="informix",
        label="IBM Informix",
        tcp_ports=(1526, 9088),
        udp_ports=(),
        prefixes=("informix-*",),
        names=("informix", "sqlexec", "pdap-np"),
        note="With credentials, the database and table inventory; without, the version from -sV "
        "is the whole story.",
    ),
    ServiceScripts(
        key="riak",
        label="Riak",
        tcp_ports=(8087, 8098),
        udp_ports=(),
        prefixes=("riak-http-info", "http-*"),
        names=("riak", "riak-pbc"),
        note="Node name, ring size and version over the HTTP interface.",
    ),
    ServiceScripts(
        key="elasticsearch",
        label="Elasticsearch",
        tcp_ports=(9200, 9300),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=("elasticsearch",),
        note="No dedicated script — the generic web family against /, /_cat/indices and "
        "/_cluster/health is what enumerates an open cluster.",
    ),
    ServiceScripts(
        key="neo4j",
        label="Neo4j",
        tcp_ports=(7473, 7474, 7687),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=("neo4j", "bolt"),
        note="The HTTP endpoints answer with version and whether auth is enabled; 7687 is the "
        "binary Bolt protocol and needs a client.",
    ),
    # ── Containers / DevOps / messaging ──────────────────────────────────────────────────────
    ServiceScripts(
        key="docker",
        label="Docker Engine API",
        tcp_ports=(2375, 2376),
        udp_ports=(),
        prefixes=("docker-*", "http-*", "ssl-*"),
        names=("docker", "docker-swarm"),
        note="API version and, on an unauthenticated 2375, /info and /containers/json — which is "
        "root on the host by design.",
    ),
    ServiceScripts(
        key="kubernetes",
        label="Kubernetes API server",
        tcp_ports=(6443, 8080),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=("kubernetes", "kube-apiserver", "sun-sr-https"),
        note="No dedicated script — the certificate names the cluster and its SANs, and /version "
        "and /api answer before authentication on most clusters.",
    ),
    ServiceScripts(
        key="kubelet",
        label="Kubelet",
        tcp_ports=(10248, 10250, 10255, 10256),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=("kubelet",),
        note="The read-only port (10255) and an anonymous-auth 10250 expose /pods and /runningpods "
        "— pod specs carry environment variables and mounted secrets.",
    ),
    ServiceScripts(
        key="k8s_control",
        label="Kubernetes controller / scheduler",
        tcp_ports=(10257, 10259),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=(),
        note="Controller-manager and scheduler health/metrics endpoints — mostly a confirmation "
        "that this host is a control-plane node.",
    ),
    ServiceScripts(
        key="etcd",
        label="etcd",
        tcp_ports=(2379, 2380),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=("etcd", "etcd-client", "etcd-server"),
        note="No dedicated script — /version and /v2/keys over the web family. An unauthenticated "
        "etcd holds the entire Kubernetes cluster state, secrets included.",
    ),
    ServiceScripts(
        key="consul",
        label="Consul HTTP API",
        tcp_ports=(8500, 8501),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=("consul",),
        note="Service catalog, node list and the KV store over HTTP — Consul ships with its ACL "
        "system disabled, so all three usually answer anonymously.",
    ),
    ServiceScripts(
        key="consul_dns",
        label="Consul DNS",
        tcp_ports=(8600,),
        udp_ports=(8600,),
        prefixes=("dns-*",),
        names=(),
        note="Consul's DNS interface — SRV lookups under .consul enumerate registered services "
        "and the nodes behind them.",
    ),
    ServiceScripts(
        key="zookeeper",
        label="Apache ZooKeeper",
        tcp_ports=(2181, 2888, 3888),
        udp_ports=(),
        # why: zookeeper-* is DEAD — nmap ships no ZooKeeper scripts. `banner` at least confirms
        # the listener; the 4lw commands (ruok/mntr/conf) need a raw client.
        prefixes=("banner",),
        names=("zookeeper", "eforward"),
        note="No NSE coverage — the four-letter commands (ruok, conf, envi, mntr) are the real "
        "enumeration and need a raw TCP client.",
    ),
    ServiceScripts(
        key="amqp",
        label="AMQP / RabbitMQ",
        tcp_ports=(5671, 5672),
        udp_ports=(),
        prefixes=("amqp-*", "ssl-*"),
        names=("amqp", "amqps"),
        note="Server product, version, cluster name and the SASL mechanisms offered — the "
        "mechanism list tells you whether guest/guest is even reachable.",
    ),
    ServiceScripts(
        key="rabbitmq_mgmt",
        label="RabbitMQ management UI",
        tcp_ports=(15671, 15672),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=(),
        note="The management plugin's web UI and REST API — default guest credentials on a "
        "non-loopback listener give queue and user administration.",
    ),
    ServiceScripts(
        key="mqtt",
        label="MQTT",
        tcp_ports=(1883, 8883),
        udp_ports=(),
        prefixes=("mqtt-*", "ssl-*"),
        names=("mqtt", "secure-mqtt"),
        note="mqtt-subscribe joins the broker and dumps topics and retained messages — on an IoT "
        "or OT broker that is live telemetry and sometimes control traffic.",
        # why: fragile because an open broker is usually attached to real devices; subscribing is
        # read-only but joining an OT broker is still touching production plant.
        fragile=True,
    ),
    ServiceScripts(
        key="git",
        label="Git protocol daemon",
        tcp_ports=(9418,),
        udp_ports=(),
        # why: http-git targets a web-exposed .git directory, not the git:// daemon — listing it
        # here would run a check whose portrule can never fire on 9418.
        prefixes=("banner",),
        names=("git", "git-daemon"),
        note="An anonymous git daemon serves whole repositories with history — clone it and read "
        "the deleted secrets, rather than scanning it.",
    ),
    ServiceScripts(
        key="svn",
        label="Subversion",
        tcp_ports=(3690,),
        udp_ports=(),
        # why: http-svn-* only fires on an HTTP(S)-hosted repository (mod_dav_svn); it is kept
        # because that is where most exposed SVN lives, but it will not touch svnserve on 3690.
        prefixes=("http-svn-*", "banner"),
        names=("svn", "svnserve"),
        note="Repository list and per-repo commit history — svnserve on 3690 needs an svn client; "
        "the http-svn scripts cover the mod_dav_svn case on 80/443.",
    ),
    ServiceScripts(
        key="prometheus",
        label="Prometheus",
        tcp_ports=(9090, 9091),
        udp_ports=(),
        prefixes=("http-*",),
        names=("prometheus",),
        note="No dedicated script — /targets and /api/v1/targets over the web family map every "
        "host and port Prometheus scrapes, which is an internal network inventory.",
    ),
    ServiceScripts(
        key="grafana",
        label="Grafana",
        tcp_ports=(3000,),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=("grafana",),
        note="Version from /login and /api/health over the web family; the datasource list names "
        "the backing databases once you are in.",
    ),
    ServiceScripts(
        key="splunk",
        label="Splunk",
        tcp_ports=(8000, 8089),
        udp_ports=(),
        prefixes=("http-*", "ssl-*"),
        names=("splunk", "splunkd"),
        note="8000 is the web UI and 8089 the management API — the API answers its version "
        "unauthenticated over TLS.",
    ),
    ServiceScripts(
        key="jdwp",
        label="Java Debug Wire Protocol",
        tcp_ports=(5005, 8000, 8787),
        udp_ports=(),
        prefixes=("jdwp-*",),
        names=("jdwp",),
        note="JDWP has no authentication at all — jdwp-version and jdwp-info confirm the JVM and "
        "its class path, which is code execution as the JVM user.",
    ),
    ServiceScripts(
        key="rmi",
        label="Java RMI registry",
        tcp_ports=(1050, 1098, 1099),
        udp_ports=(),
        prefixes=("rmi-*",),
        names=("java-rmi", "rmiregistry", "ormi", "oracle-db-rmi"),
        note="The registry dump names every bound remote object and its class, and the "
        "classloader check says whether the endpoint accepts remote codebases.",
    ),
    ServiceScripts(
        key="epmd",
        label="Erlang port mapper (EPMD)",
        tcp_ports=(4369,),
        udp_ports=(),
        prefixes=("epmd-*",),
        names=("epmd",),
        note="Node names and the high ports they listen on — the way in to RabbitMQ/CouchDB "
        "clusters once you have the Erlang cookie.",
    ),
    ServiceScripts(
        key="distcc",
        label="distcc",
        tcp_ports=(3632,),
        udp_ports=(),
        prefixes=("distcc-*",),
        names=("distcc",),
        note="An unrestricted distcc daemon compiles whatever it is sent — the script confirms it "
        "without needing a wordlist or credential.",
    ),
    # ── Network infrastructure ───────────────────────────────────────────────────────────────
    ServiceScripts(
        key="dhcp",
        label="DHCP",
        tcp_ports=(),
        udp_ports=(67, 68),
        prefixes=("dhcp-*", "broadcast-dhcp-*"),
        names=("dhcps", "dhcpc", "bootps", "bootpc"),
        note="A DHCPINFORM reply hands over the domain name, DNS and WINS servers, default "
        "gateway and NTP servers — the network's layout, for free.",
    ),
    ServiceScripts(
        key="ntp",
        label="NTP",
        tcp_ports=(123,),
        udp_ports=(123,),
        prefixes=("ntp-*",),
        names=("ntp",),
        note="Version and system variables, and monlist on an old daemon — monlist returns the "
        "last 600 clients, which is an internal host list.",
    ),
    ServiceScripts(
        key="snmp",
        label="SNMP",
        tcp_ports=(161,),
        udp_ports=(161,),
        prefixes=("snmp-*",),
        names=("snmp",),
        note="With a readable community: system description, interfaces, routes, listening "
        "sockets, running processes, and on Windows the users, shares and installed software.",
    ),
    ServiceScripts(
        key="snmptrap",
        label="SNMP trap receiver",
        tcp_ports=(162,),
        udp_ports=(162,),
        prefixes=("snmp-*",),
        names=("snmptrap",),
        note="A trap sink rather than an agent — its presence says the host is a monitoring "
        "station, which is usually a well-connected one.",
    ),
    ServiceScripts(
        key="ipmi",
        label="IPMI / RMCP (BMC)",
        tcp_ports=(623,),
        udp_ports=(623,),
        prefixes=("ipmi-*", "supermicro-ipmi-conf"),
        names=("asf-rmcp", "ipmi"),
        note="IPMI version and the cipher-zero authentication bypass — a BMC is out-of-band root "
        "on the physical host and is almost never patched.",
    ),
    ServiceScripts(
        key="ike",
        label="IKE / IPsec",
        tcp_ports=(500,),
        udp_ports=(500, 4500),
        prefixes=("ike-*",),
        names=("isakmp", "nat-t-ike"),
        note="Vendor ID and the accepted transform set; aggressive mode with a group name is what "
        "makes a PSK recoverable.",
    ),
    ServiceScripts(
        key="sip",
        label="SIP",
        tcp_ports=(5060, 5061),
        udp_ports=(5060, 5061),
        prefixes=("sip-*",),
        names=("sip", "sips", "sip-tls"),
        note="Supported methods and extension enumeration — valid extensions answer differently "
        "from invalid ones, which is a free user list on a PBX.",
    ),
    ServiceScripts(
        key="rtsp",
        label="RTSP",
        tcp_ports=(554, 8554),
        udp_ports=(),
        prefixes=("rtsp-*",),
        names=("rtsp", "rtsps", "rtsp-alt"),
        note="Allowed methods and the stream URL discovery that finds unauthenticated camera "
        "feeds.",
    ),
    ServiceScripts(
        key="upnp",
        label="UPnP / SSDP",
        tcp_ports=(1900, 2869),
        udp_ports=(1900,),
        prefixes=("upnp-*", "broadcast-upnp-*"),
        names=("upnp", "ssdp", "icslap"),
        note="Device description: manufacturer, model, firmware and the service list — and on a "
        "router, the port-mapping service.",
    ),
    ServiceScripts(
        key="llmnr",
        label="LLMNR",
        tcp_ports=(5355,),
        udp_ports=(5355,),
        prefixes=("llmnr-resolve",),
        names=("llmnr",),
        note="LLMNR responding at all is the finding — it is the name-resolution fallback that "
        "makes NTLM relay and hash capture possible on a Windows segment.",
    ),
    ServiceScripts(
        key="mdns",
        label="mDNS / Bonjour",
        tcp_ports=(5353,),
        udp_ports=(5353,),
        prefixes=("dns-service-discovery", "broadcast-dns-service-discovery"),
        names=("mdns", "zeroconf"),
        note="Advertised services with their ports and TXT records — printers, AirPlay, SSH and "
        "file shares announce themselves, hostname included.",
    ),
    ServiceScripts(
        key="wsd",
        label="WS-Discovery",
        tcp_ports=(3702, 5357, 5358),
        udp_ports=(3702,),
        prefixes=("wsdd-discover", "broadcast-wsdd-discover"),
        names=("ws-discovery", "wsd", "wsdapi", "wsdapi-s"),
        note="Windows and printer/camera devices announcing their types and addresses — a host "
        "inventory on a segment with no other enumeration.",
    ),
    ServiceScripts(
        key="ipp",
        label="CUPS / IPP",
        tcp_ports=(631,),
        udp_ports=(631,),
        prefixes=("cups-*", "http-*"),
        names=("ipp", "cups", "printer"),
        note="CUPS version and the print queue with job owners — job owners are real usernames, "
        "and the CUPS admin interface is plain HTTP on the same port.",
    ),
    ServiceScripts(
        key="jetdirect",
        label="HP JetDirect / raw print",
        tcp_ports=(9100, 9101, 9102),
        udp_ports=(9100,),
        prefixes=("pjl-*",),
        names=("jetdirect", "hp-pdl-datastr", "pdl-datastream"),
        note="The PJL ready message — printers are routinely left with a default password and a "
        "filesystem you can read over PJL.",
    ),
    ServiceScripts(
        key="radius",
        label="RADIUS",
        tcp_ports=(1812, 1813),
        udp_ports=(1645, 1646, 1812, 1813),
        # why: radius-* is DEAD — nmap ships no RADIUS scripts, and `banner` is TCP-only so it is
        # useless on the UDP ports that matter. An empty tuple is the honest answer.
        prefixes=(),
        names=("radius", "radacct"),
        note="No NSE coverage at all — the value of finding it is knowing the host is the "
        "network's authentication server, and that a shared secret exists to be found.",
    ),
    ServiceScripts(
        key="tacacs",
        label="TACACS+",
        tcp_ports=(49,),
        udp_ports=(49,),
        prefixes=("banner",),  # nmap ships no tacacs scripts
        names=("tacacs",),
        note="Like RADIUS, no NSE coverage — its presence marks the device-administration "
        "authentication server for the network gear.",
    ),
    ServiceScripts(
        key="rpcap",
        label="RPCAP (remote packet capture)",
        tcp_ports=(2002,),
        udp_ports=(),
        prefixes=("rpcap-*",),
        names=("rpcapd",),
        note="Interface list and whether the daemon needs authentication — an open rpcapd is "
        "remote traffic capture on someone else's segment.",
    ),
    ServiceScripts(
        key="nbd",
        label="Network Block Device",
        tcp_ports=(10809,),
        udp_ports=(),
        prefixes=("nbd-*",),
        names=("nbd",),
        note="Exported block devices and their sizes — an unauthenticated export is a raw disk "
        "you can attach and read.",
    ),
    ServiceScripts(
        key="finger",
        label="Finger",
        tcp_ports=(79,),
        udp_ports=(),
        prefixes=("finger",),
        names=("finger",),
        note="Logged-in users and, on many implementations, the full account list — a username "
        "oracle that needs no credential.",
    ),
    ServiceScripts(
        key="ident",
        label="Ident / auth",
        tcp_ports=(113,),
        udp_ports=(),
        prefixes=("auth-owners", "auth-spoof"),
        names=("ident", "auth"),
        note="The local username owning each open port — it maps every listening service to the "
        "account that runs it.",
    ),
    ServiceScripts(
        key="irc",
        label="IRC",
        tcp_ports=(194, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697),
        udp_ports=(),
        prefixes=("irc-*",),
        names=("irc", "ircs", "ircs-u"),
        note="Server info and channel list, plus the UnrealIRCd backdoor check that a 3.2.8.1 "
        "banner always warrants.",
    ),
    # ── OT / ICS / IoT — fragile: even a discovery probe can disturb these ───────────────────
    ServiceScripts(
        key="modbus",
        label="Modbus TCP",
        tcp_ports=(502,),
        udp_ports=(502,),
        prefixes=("modbus-*",),
        names=("modbus", "mbap"),
        note="Enumerates responding slave/unit IDs and device identification — read-only, but it "
        "is still traffic to a live PLC.",
        fragile=True,
    ),
    ServiceScripts(
        key="s7",
        label="Siemens S7 (ISO-TSAP)",
        tcp_ports=(102,),
        udp_ports=(),
        prefixes=("s7-*",),
        names=("iso-tsap", "s7"),
        note="Module, hardware and firmware identification for an S7 PLC, plus the plant and "
        "serial identifiers.",
        fragile=True,
    ),
    ServiceScripts(
        key="bacnet",
        label="BACnet",
        tcp_ports=(47808,),
        udp_ports=(47808,),
        prefixes=("bacnet-*",),
        names=("bacnet",),
        note="Device instance number, vendor, model and firmware for building-automation "
        "controllers.",
        fragile=True,
    ),
    ServiceScripts(
        key="enip",
        label="EtherNet/IP (CIP)",
        tcp_ports=(44818,),
        udp_ports=(2222, 44818),
        prefixes=("enip-*",),
        names=("ethernetip-1", "ethernetip-2", "ethernetip"),
        note="Vendor, product name, serial number and device type from the CIP identity object.",
        fragile=True,
    ),
    ServiceScripts(
        key="dnp3",
        label="DNP3",
        tcp_ports=(20000,),
        udp_ports=(20000,),
        # why: dnp3-* is DEAD — nmap ships no DNP3 scripts, and `banner` is not offered here
        # because reading from a live RTU is exactly what fragile=True is warning about.
        prefixes=(),
        names=("dnp", "dnp3"),
        note="No NSE coverage — treat an open 20000 as a SCADA outstation and leave it alone "
        "unless the engagement explicitly covers it.",
        fragile=True,
    ),
    ServiceScripts(
        key="iec61850",
        label="IEC 61850 MMS / IEC 60870-5-104",
        tcp_ports=(102, 2404),
        udp_ports=(),
        prefixes=("iec61850-*", "iec-identify"),
        names=("iec-104", "iec61850"),
        note="MMS server identification on 102 (shared with S7) and IEC-104 ASDU addressing on "
        "2404 — substation automation, the most consequential thing on this list.",
        fragile=True,
    ),
    ServiceScripts(
        key="coap",
        label="CoAP",
        tcp_ports=(5683, 5684),
        udp_ports=(5683, 5684),
        prefixes=("coap-*",),
        names=("coap", "coaps"),
        note="The /.well-known/core resource list — the device's entire API surface, and often "
        "unauthenticated on an IoT endpoint.",
        fragile=True,
    ),
    ServiceScripts(
        key="knx",
        label="KNXnet/IP",
        tcp_ports=(3671,),
        udp_ports=(3671,),
        prefixes=("knx-*",),
        names=("knx", "efcp"),
        note="Gateway name, KNX address, MAC and supported services for building control (lights, "
        "HVAC, access).",
        fragile=True,
    ),
    ServiceScripts(
        key="hartip",
        label="HART-IP",
        tcp_ports=(5094,),
        udp_ports=(5094,),
        prefixes=("hartip-*",),
        names=("hart-ip", "hartip"),
        note="Gateway identity and session response for HART field instruments.",
        fragile=True,
    ),
    ServiceScripts(
        key="omron",
        label="Omron FINS",
        tcp_ports=(9600,),
        udp_ports=(9600,),
        prefixes=("omron-*",),
        names=("omron",),
        note="Controller model and firmware version from an Omron PLC over FINS.",
        fragile=True,
    ),
    ServiceScripts(
        key="profinet",
        label="PROFINET",
        tcp_ports=(34962, 34963, 34964),
        udp_ports=(34962, 34963, 34964),
        prefixes=("profinet-*",),
        names=("profinet-rt", "profinet-rtm", "profinet-cm"),
        note="Device name, vendor and module layout from the PROFINET context manager.",
        fragile=True,
    ),
)

BY_KEY: dict[str, ServiceScripts] = {entry.key: entry for entry in MATRIX}

# Exact nmap-service-name -> row. Built once; a duplicate name across rows is a data bug and the
# test suite fails on it rather than letting one row silently shadow another.
_BY_NAME: dict[str, ServiceScripts] = {
    name.lower(): entry for entry in MATRIX for name in entry.names
}

# Port -> row, TCP claims before UDP claims and first-declared-wins, so `http` keeps 8080 (tomcat
# and jenkins are reachable by product name) and `ssh` on 2222 does not become EtherNet/IP.
_BY_PORT: dict[int, ServiceScripts] = {}
for _entry in MATRIX:
    for _port in _entry.tcp_ports:
        _BY_PORT.setdefault(_port, _entry)
for _entry in MATRIX:
    for _port in _entry.udp_ports:
        _BY_PORT.setdefault(_port, _entry)

# The rows a bare service name of "http"/"https" can be refined into once -sV supplies a product.
# Ordered most-specific-first: "Apache Tomcat/Coyote" must hit tomcat before "apache httpd" is
# even considered, and "Apache CouchDB" must hit couchdb for the same reason.
_GENERIC_WEB: frozenset[str] = frozenset({"http", "https", "proxy", "tls"})
_PRODUCT_KEYS: tuple[tuple[str, str], ...] = (
    ("apache tomcat", "tomcat"),
    ("coyote", "tomcat"),
    ("tomcat", "tomcat"),
    ("jenkins", "jenkins"),
    ("wordpress", "wordpress"),
    ("drupal", "drupal"),
    ("joomla", "joomla"),
    ("coldfusion", "coldfusion"),
    ("couchdb", "couchdb"),
    ("elasticsearch", "elasticsearch"),
    ("kibana", "elasticsearch"),
    ("grafana", "grafana"),
    ("prometheus", "prometheus"),
    ("splunk", "splunk"),
    ("rabbitmq", "rabbitmq_mgmt"),
    ("kubernetes", "kubernetes"),
    ("kubelet", "kubelet"),
    ("kube-apiserver", "kubernetes"),
    ("etcd", "etcd"),
    ("consul", "consul"),
    ("docker", "docker"),
    ("webdav", "webdav"),
    ("neo4j", "neo4j"),
    ("riak", "riak"),
    ("jdwp", "jdwp"),
    ("squid", "proxy"),
    ("microsoft iis", "iis"),
    ("microsoft-iis", "iis"),
    ("httpapi", "iis"),
    ("apache httpd", "apache"),
)


def for_service(name: str, port: int, product: str = "") -> ServiceScripts | None:
    """The matrix row for a discovered service — by nmap service name, then product, then port.

    Name beats port on purpose: a default port is the weakest signal there is (FTP on 2121, HTTP
    on 5000, SSH on 2222), so the port is only consulted when the name says nothing.
    """
    normalized = name.strip().lower()
    hit = _BY_NAME.get(normalized)
    if hit is None and "/" in normalized:
        # -sV prints tunnelled services as "ssl/http"; fall back to the inner name.
        hit = _BY_NAME.get(normalized.rsplit("/", 1)[-1])

    if hit is None or hit.key in _GENERIC_WEB:
        text = f"{normalized} {product}".strip().lower()
        for token, key in _PRODUCT_KEYS:
            if token in text:
                refined = BY_KEY.get(key)
                if refined is not None:
                    return refined

    if hit is not None:
        return hit
    if port:
        return _BY_PORT.get(port)
    return None
