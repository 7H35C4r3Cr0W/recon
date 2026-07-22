from oscprecon.models import DiscoveredService, Finding, Port, Proto, ScanResults, Target
from oscprecon.modules.http import (
    EXTENSION_PRESETS,
    STATUS_PRESETS,
    HttpModule,
    HttpScanSettings,
    build_command,
    default_output,
    default_url,
    is_tls,
    wide_net_extensions,
)

REFERENCE_EXTS = [
    "php",
    "phps",
    "asp",
    "aspx",
    "jsp",
    "cfm",
    "js",
    "css",
    "html",
    "htm",
    "txt",
    "log",
    "bak",
    "backup",
    "old",
    "swp",
    "zip",
    "tar",
    "tar.gz",
    "tgz",
    "7z",
    "rar",
    "sql",
    "sqlite",
    "xml",
    "json",
    "conf",
    "config",
    "ini",
    "inc",
]


def test_feroxbuster_matches_section_9_reference() -> None:
    settings = HttpScanSettings(
        tool="feroxbuster",
        url="http://10.129.95.192/",
        wordlist="/usr/share/seclists/Discovery/Web-Content/big.txt",
        extensions=REFERENCE_EXTS,
        threads=100,
        depth=4,
        timeout=25,
        rate_limit=40,
        skip_tls=True,
        status_codes=[200, 204, 301, 302, 307, 401, 403, 404, 500],
        output_file="ferox_10.129.95.192.txt",
    )
    expected = (
        "feroxbuster -u http://10.129.95.192/ "
        "-w /usr/share/seclists/Discovery/Web-Content/big.txt "
        "-x php,phps,asp,aspx,jsp,cfm,js,css,html,htm,txt,log,bak,backup,old,swp,zip,tar,"
        "tar.gz,tgz,7z,rar,sql,sqlite,xml,json,conf,config,ini,inc "
        "-d 4 -t 100 --timeout 25 --rate-limit 40 -k "
        "-s 200,204,301,302,307,401,403,404,500 -o ferox_10.129.95.192.txt"
    )
    assert build_command(settings) == expected


def test_tool_translations() -> None:
    common = {
        "url": "http://x/",
        "wordlist": "/w.txt",
        "extensions": ["php", "html"],
        "threads": 40,
        "depth": 2,
        "timeout": 10,
        "status_codes": [200, 301],
        "output_file": "o.txt",
    }
    gobuster = build_command(HttpScanSettings(tool="gobuster", **common))
    assert gobuster.startswith("gobuster dir -u http://x/ -w /w.txt -x php,html")
    assert "-s 200,301" in gobuster
    ffuf = build_command(HttpScanSettings(tool="ffuf", **common))
    assert "http://x/FUZZ" in ffuf
    assert "-mc 200,301" in ffuf
    assert "-e .php,.html" in ffuf
    dirsearch = build_command(HttpScanSettings(tool="dirsearch", **common))
    assert dirsearch.startswith("dirsearch -u http://x/ -w /w.txt -e php,html")
    assert "-i 200,301" in dirsearch


def test_wide_net_and_presets() -> None:
    wide = wide_net_extensions()
    assert {"php", "bak", "json", "zip", "conf"} <= set(wide)
    assert len(wide) == len(set(wide))  # de-duplicated
    assert "Wide net" not in EXTENSION_PRESETS  # computed, not a stored group
    assert STATUS_PRESETS["All informative"] == [200, 204, 301, 302, 307, 401, 403, 404, 500]


def test_default_url_output_and_tls() -> None:
    assert default_url("10.10.10.5", 80, False) == "http://10.10.10.5/"
    assert default_url("10.10.10.5", 443, True) == "https://10.10.10.5/"
    assert default_url("10.10.10.5", 8080, False) == "http://10.10.10.5:8080/"
    assert is_tls("ssl/http", 8443) is True
    assert is_tls("http", 80) is False
    assert default_output(8080, "feroxbuster", "/x/Discovery/big.txt") == (
        "http/8080/feroxbuster-big.txt"
    )


def test_default_url_brackets_ipv6() -> None:
    assert default_url("dead:beef::1", 8080, False) == "http://[dead:beef::1]:8080/"
    assert default_url("::1", 80, False) == "http://[::1]/"
    assert default_url("10.10.10.5", 8080, False) == "http://10.10.10.5:8080/"
    assert default_url("target.htb", 80, False) == "http://target.htb/"


def test_triggers_and_http_ports() -> None:
    scan = ScanResults(
        target=Target(ip="10.10.10.5"),
        services=[
            DiscoveredService(80, Proto.TCP, "http"),
            DiscoveredService(8443, Proto.TCP, "ssl/https"),
            DiscoveredService(22, Proto.TCP, "ssh"),
        ],
    )
    module = HttpModule()
    assert module.triggers(scan) is True
    assert dict(module.http_ports(scan)) == {80: False, 8443: True}


def test_light_probe_commands() -> None:
    module = HttpModule()
    cmds = module.commands(Target(ip="10.10.10.5"), [Port(80, Proto.TCP, "http")])
    lines = [c.shell_line for c in cmds]
    assert any(line.startswith("whatweb --colour=never http://10.10.10.5/") for line in lines)
    assert any(".git/HEAD" in line for line in lines)
    assert all(c.output_file.startswith("http/80/") for c in cmds)


def test_suggest_wordpress() -> None:
    module = HttpModule()
    out = module.suggest([Finding(service="http", title="200 /", detail="whatweb: WordPress")])
    assert out
    assert "wpscan --enumerate" in out[0]
    assert "--passwords" not in out[0]


def test_suggest_api_server_enumeration() -> None:
    # Spooktrol: a uvicorn/FastAPI fingerprint should nudge toward enumerating the API schema
    # (/openapi.json, /docs) rather than only dir-busting for files.
    module = HttpModule()
    out = module.suggest(
        [Finding(service="http", title="200 /", detail="whatweb: HTTPServer[uvicorn]")]
    )
    api = [line for line in out if "openapi.json" in line]
    assert api and "/docs" in api[0]
    # a plain Apache page gets no API nudge
    assert not any(
        "openapi.json" in line
        for line in module.suggest(
            [Finding(service="http", title="200 /", detail="whatweb: Apache[2.4.52]")]
        )
    )


def test_suggest_ua_gate_hint() -> None:
    # HTB Holiday: a Node/Express app that 404s the root to a non-browser UA. whatweb sees
    # Title[Error]/X-Powered-By[Express]; suggest() must nudge to re-probe with a full browser UA.
    module = HttpModule()
    out = module.suggest(
        [
            Finding(
                service="http", title="404 /", detail="whatweb: Title[Error], X-Powered-By[Express]"
            )
        ]
    )
    ua = [line for line in out if "User-Agent filter" in line]
    assert ua and "curl -A" in ua[0] and "AppleWebKit" in ua[0]
    # a normal 200 page with real content gets no UA-gate nudge
    assert not any(
        "User-Agent filter" in line
        for line in module.suggest(
            [Finding(service="http", title="200 /", detail="whatweb: Apache[2.4.52], Title[Home]")]
        )
    )


def test_suggest_invalid_hostname_vhost_gate() -> None:
    # HTB Ethereal: port 8080 answers the bare IP with 400 Invalid Hostname (host-header-gated).
    module = HttpModule()
    out = module.suggest(
        [
            Finding(
                service="http",
                title="400 /",
                detail="host-header-gated: bare IP returns 400 Invalid Hostname",
            )
        ]
    )
    hits = [line for line in out if "Invalid Hostname" in line]
    assert hits and "Host:" in hits[0]
    # a normal 200 page never triggers the vhost-gate nudge
    assert not any(
        "Invalid Hostname" in line
        for line in module.suggest(
            [Finding(service="http", title="200 /", detail="whatweb: Apache[2.4.52], Title[Home]")]
        )
    )


def test_effective_web_host_falls_back_on_unresolvable_hostname(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # HTB Falafel/Holiday: a profile hostname not in /etc/hosts makes every http probe fail with
    # "no address" → recon silently returns nothing. effective_web_host must fall back to the IP.
    from oscprecon.modules import http as httpmod

    monkeypatch.setattr(
        httpmod, "host_resolves", lambda _n: True
    )  # resolvable → keep the vhost name
    host, unresolved = httpmod.effective_web_host(Target(ip="10.10.10.5", hostname="box.htb"))
    assert host == "box.htb" and unresolved is False
    monkeypatch.setattr(
        httpmod, "host_resolves", lambda _n: False
    )  # unresolvable → fall back to IP
    host, unresolved = httpmod.effective_web_host(Target(ip="10.10.10.5", hostname="box.htb"))
    assert host == "10.10.10.5" and unresolved is True
    # no hostname → the IP, no warning (nothing to resolve)
    host, unresolved = httpmod.effective_web_host(Target(ip="10.10.10.5"))
    assert host == "10.10.10.5" and unresolved is False
    # and commands() must build probe URLs against the IP, not the dead hostname
    cmds = httpmod.HttpModule().commands(
        Target(ip="10.10.10.5", hostname="box.htb"), [Port(80, Proto.TCP, "http")]
    )
    assert all("box.htb" not in c.shell_line for c in cmds)
    assert any("http://10.10.10.5/" in c.shell_line for c in cmds)


def test_ua_gate_detector() -> None:
    from oscprecon.modules.http import detect_ua_gate

    assert detect_ua_gate("<pre>Cannot GET /login</pre>") is True
    assert detect_ua_gate("whatweb: Title[Error], X-Powered-By[Express]") is True
    # a page that merely mentions "error" in prose must NOT fire
    assert detect_ua_gate("Login error: invalid password. Title[Dashboard]") is False


def test_suggest_vhost_from_redirect() -> None:
    # Responder: whatweb's Meta-Refresh-Redirect surfaces a vhost the bare IP won't serve.
    module = HttpModule()
    finding = Finding(
        service="http",
        title="200 /",
        detail="redirect -> unika.htb",
        fields={"redirect_to": "unika.htb"},
    )
    out = module.suggest([finding])
    assert any("unika.htb" in line and "/etc/hosts" in line for line in out)
    # a dir-bust path redirect must NOT be mistaken for a vhost
    path_redirect = Finding(
        service="http", title="301 /a", detail="", fields={"redirect_to": "/a/"}
    )
    assert not module.suggest([path_redirect])


def test_suggest_email_domain_leads_to_vhost_enum() -> None:
    # Snoopy: the page discloses info@snoopy.htb — surface the domain as a vhost/subdomain-enum lead
    # (the prerequisite for finding mm.snoopy.htb). It's the box's whole entry point.
    module = HttpModule()
    finding = Finding(
        service="http",
        title="200 /",
        detail="page discloses an email at snoopy.htb",
        fields={"path": "/", "status": "200", "email_domain": "snoopy.htb"},
    )
    out = module.suggest([finding])
    assert any("snoopy.htb" in line and "vhost" in line.lower() for line in out)
    assert any("/etc/hosts" in line for line in out)
    # no email domain -> no such suggestion (empty string must not fire)
    bare = Finding(service="http", title="200 /", detail="whatweb: nginx", fields={"path": "/"})
    assert not any("disclosed" in line for line in module.suggest([bare]))


def test_suggest_page_host_leads_to_vhost_enum() -> None:
    # Carpediem: a lab hostname printed in the page body (carpediem.htb) becomes a vhost/domain lead
    # (vhost enum against it finds portal.carpediem.htb, the foothold surface).
    module = HttpModule()
    finding = Finding(
        service="http",
        title="0 /",
        detail="page content discloses host 'carpediem.htb'",
        fields={"path": "/", "status": "0", "page_host": "carpediem.htb"},
    )
    out = module.suggest([finding])
    assert any("carpediem.htb" in line and "vhost" in line.lower() for line in out)
    assert any("/etc/hosts" in line for line in out)
    # no page_host -> no such suggestion
    bare = Finding(service="http", title="200 /", detail="whatweb: nginx", fields={"path": "/"})
    assert not any("disclosed in the page content" in line for line in module.suggest([bare]))


def test_suggest_base_path_from_root_redirect() -> None:
    # Race: the site root redirects to /racers/ — surface it so content discovery pivots off /.
    module = HttpModule()
    finding = Finding(
        service="http",
        title="200 /",
        detail="root redirects to /racers/",
        fields={"path": "/", "status": "200", "base_path": "/racers/", "redirect_to": "/racers/"},
    )
    out = module.suggest([finding])
    assert any("/racers/" in line and "base path" in line for line in out)
    assert any("racers/" in line for line in out)  # the feroxbuster example points at the subdir


def test_suggest_basic_auth_default_cred_on_401() -> None:
    # Race: phpsysinfo returns 401 (Basic auth) and admin:admin works. Surface a Tier-2 single-shot
    # default-cred hint on a 401 — but NOT on a 403 (forbidden, not an auth prompt).
    module = HttpModule()
    finding = Finding(
        service="http",
        title="401 /phpsysinfo",
        detail="whatweb: WWW-Authenticate[phpsysinfo][Basic]",
        fields={"path": "/phpsysinfo", "status": "401"},
    )
    out = module.suggest([finding])
    hint = next((line for line in out if "/phpsysinfo" in line), "")
    assert "401" in hint and "admin:admin" in hint
    assert "spray" in hint  # explicitly framed as a single attempt, not a spray
    forbidden = Finding(
        service="http", title="403 /x", detail="", fields={"path": "/x", "status": "403"}
    )
    assert not module.suggest([forbidden])
