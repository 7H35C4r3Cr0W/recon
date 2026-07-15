from pathlib import Path

from oscprecon.modules.http.parsers import (
    detect_wordpress,
    parse_dirsearch,
    parse_feroxbuster,
    parse_ffuf,
    parse_gobuster,
    parse_nikto,
    parse_tool,
    parse_whatweb,
    parse_wpscan,
)

FIX = Path(__file__).parent / "fixtures" / "http"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_feroxbuster() -> None:
    findings = parse_feroxbuster(_read("feroxbuster.json"), 80)
    by_path = {f.path: f for f in findings}
    assert len(findings) == 3  # statistics line skipped
    assert by_path["/admin"].status == 301
    assert by_path["/admin"].size == 154
    assert by_path["/admin"].redirect_to == "/admin/"
    assert by_path["/index.html"].size == 10918
    assert all(f.port == 80 for f in findings)


def test_feroxbuster_plain_output() -> None:
    # the §9 reference uses plain -o (no --json) — the columnar format must parse too
    findings = parse_feroxbuster(_read("feroxbuster-plain.txt"), 80)
    by_path = {f.path: f for f in findings}
    assert len(findings) == 3
    assert by_path["/admin"].status == 301
    assert by_path["/admin"].size == 154
    assert by_path["/admin"].redirect_to == "/admin/"
    assert by_path["/index.html"].size == 10918


def test_gobuster() -> None:
    findings = parse_gobuster(_read("gobuster.txt"), 80)
    by_path = {f.path: f for f in findings}
    assert len(findings) == 4
    assert by_path["/admin"].status == 301
    assert "admin/" in by_path["/admin"].redirect_to
    assert by_path["/index.html"].size == 10918
    assert by_path["/server-status"].status == 403


def test_ffuf() -> None:
    findings = parse_ffuf(_read("ffuf.json"), 8080)
    by_path = {f.path: f for f in findings}
    assert by_path["/admin"].status == 301
    assert by_path["/admin"].size == 154
    assert by_path["/admin"].redirect_to.endswith("/admin/")
    assert by_path["/login"].status == 200
    assert all(f.port == 8080 for f in findings)


def test_dirsearch() -> None:
    findings = parse_dirsearch(_read("dirsearch.txt"), 80)
    by_path = {f.path: f for f in findings}
    assert by_path["/admin"].status == 301
    assert by_path["/admin"].size == 154
    assert by_path["/index.html"].size == 10240  # 10KB
    assert by_path["/server-status"].status == 403


def test_nikto_and_wordpress_detection() -> None:
    findings = parse_nikto(_read("nikto.txt"), 80)
    path_list = [f.path for f in findings]
    assert "/admin/" in path_list
    assert "/wp-login.php" in path_list
    assert "/backup/" in path_list  # from the OSVDB-####: /backup/ line
    assert "/2.4.41" not in path_list  # the 'Server: Apache/2.4.41' banner is a note, not a path
    assert detect_wordpress(_read("nikto.txt")) is True


def test_whatweb() -> None:
    findings = parse_whatweb(_read("whatweb.json"), 443)
    assert len(findings) == 1
    assert findings[0].status == 200
    assert findings[0].path == "/"
    assert "WordPress" in findings[0].note
    assert detect_wordpress(_read("whatweb.json")) is True


def test_whatweb_plain_summary() -> None:
    # the default `whatweb --colour=never <url>` emits the human summary, not JSON — it must still
    # parse (Appointment: the login form surfaces as PasswordField + Title[Login]).
    findings = parse_whatweb(_read("whatweb-plain.txt"), 80)
    assert len(findings) == 1
    assert findings[0].status == 200
    assert findings[0].path == "/"
    assert findings[0].port == 80
    # plugin names extracted at bracket depth 0, so Title[Login] and HTTPServer[..., ...] stay whole
    assert "PasswordField" in findings[0].note
    assert "Title" in findings[0].note
    assert "Apache" in findings[0].note


def test_whatweb_plain_surfaces_redirect_vhost() -> None:
    # Responder: whatweb skips the ERROR line, fingerprints the IP, AND surfaces the meta-refresh
    # redirect target (unika.htb) as a separate vhost finding — the box's key pivot.
    findings = parse_whatweb(_read("whatweb-redirect.txt"), 80)
    assert len(findings) == 2
    fingerprint, redirect = findings
    assert "Apache" in fingerprint.note and fingerprint.redirect_to == ""
    assert redirect.redirect_to == "unika.htb"
    assert "/etc/hosts" in redirect.note and "vhost" in redirect.note


def test_whatweb_redirect_ignores_ip_and_self() -> None:
    from oscprecon.modules.http.parsers import vhost_from_redirect

    assert vhost_from_redirect("http://unika.htb/") == "unika.htb"
    assert vhost_from_redirect("//sub.example.com:8080/x") == "sub.example.com"
    assert vhost_from_redirect("http://10.129.32.225/") == ""  # a bare IP is not a vhost
    assert vhost_from_redirect("/local/path") == ""  # a path redirect is not a vhost


def test_whatweb_plain_strips_ansi_colour() -> None:
    coloured = (
        "\x1b[1m\x1b[34mhttp://t/\x1b[0m [200 OK] "
        "\x1b[1mApache\x1b[0m[\x1b[32m2.4.38\x1b[0m], "
        "\x1b[1mTitle\x1b[0m[\x1b[33mDashboard, home\x1b[0m]\n"
    )
    findings = parse_whatweb(coloured, 80)
    assert len(findings) == 1
    assert findings[0].status == 200
    # the comma inside Title[Dashboard, home] must not split into a bogus plugin name
    assert findings[0].note == "whatweb: Apache, Title"


def test_wpscan() -> None:
    findings = parse_wpscan(_read("wpscan.json"), 80)
    notes = " ".join(f.note for f in findings)
    assert "WordPress 5.8" in notes
    assert "akismet" in notes
    assert "admin" in notes


def test_parse_tool_dispatch_and_garbage() -> None:
    assert parse_tool("unknown-tool", "x", 80) == []
    assert parse_ffuf("not json", 80) == []
    assert parse_whatweb("not json", 80) == []
    assert parse_wpscan("[]", 80) == []
    assert detect_wordpress("nginx 1.18") is False
