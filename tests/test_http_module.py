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
