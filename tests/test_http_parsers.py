from pathlib import Path

from oscprecon.modules.http.parsers import (
    detect_api_server,
    detect_wordpress,
    parse_dirsearch,
    parse_feroxbuster,
    parse_ffuf,
    parse_gobuster,
    parse_nikto,
    parse_robots,
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


def test_feroxbuster_captures_method_lines_words() -> None:
    # the Discovered URLs table needs the method + line/word counts, not just status/size (Markup)
    sample = (
        "200      GET     1561l     8361w   679324c http://10.129.34.153/Images/background.jpg\n"
        "301      GET        9l       30w      340c http://10.129.34.153/Images => "
        "http://10.129.34.153/Images/\n"
    )
    findings = parse_feroxbuster(sample, 80)
    by_path = {f.path: f for f in findings}
    bg = by_path["/Images/background.jpg"]
    assert (bg.method, bg.lines, bg.words, bg.size) == ("GET", 1561, 8361, 679324)
    assert by_path["/Images"].redirect_to == "http://10.129.34.153/Images/"
    # the extra columns round-trip through to_dict (persisted to findings.json for the table)
    d = bg.to_dict("t")
    assert d["method"] == "GET" and d["lines"] == 1561 and d["words"] == 8361


def test_gobuster() -> None:
    findings = parse_gobuster(_read("gobuster.txt"), 80)
    by_path = {f.path: f for f in findings}
    assert len(findings) == 4
    assert by_path["/admin"].status == 301
    assert "admin/" in by_path["/admin"].redirect_to
    assert by_path["/index.html"].size == 10918
    assert by_path["/server-status"].status == 403


def test_gobuster_unknown_length_size_not_dropped() -> None:
    # gobuster emits [Size: -1] for unknown-length responses (HEAD / chunked); the endpoint must
    # still be captured, with the negative size clamped to 0
    findings = parse_gobuster("/admin (Status: 200) [Size: -1]\n/ok (Status: 200) [Size: 512]", 80)
    by_path = {f.path: f for f in findings}
    assert set(by_path) == {"/admin", "/ok"}
    assert by_path["/admin"].size == 0
    assert by_path["/ok"].size == 512


def test_ffuf() -> None:
    findings = parse_ffuf(_read("ffuf.json"), 8080)
    by_path = {f.path: f for f in findings}
    assert by_path["/admin"].status == 301
    assert by_path["/admin"].size == 154
    assert by_path["/admin"].redirect_to.endswith("/admin/")
    assert by_path["/login"].status == 200
    assert all(f.port == 8080 for f in findings)


def test_ffuf_json_prefixed_and_trailing_noise() -> None:
    # HTB Fighter: ffuf's JSON shares one output file with shell.run's captured stdout+stderr, so
    # the JSON object arrives PREFIXED by matched words and FOLLOWED by ANSI progress lines. A plain
    # json.loads raises → the parser must still recover it (else every finding is lost).
    clean = _read("ffuf.json")
    noisy = (
        "admin\nlogin\n" + clean + "\n\x1b[2K:: Progress: [4989/4989] :: Job [1/1] :: 0 errors\n"
    )
    findings = parse_ffuf(noisy, 8080)
    by_path = {f.path: f for f in findings}
    assert by_path["/admin"].status == 301 and by_path["/login"].status == 200


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


def test_whatweb_root_redirect_surfaces_base_path() -> None:
    # Race: the site root meta-refreshes to /racers/ (a subdirectory, not a vhost). The whole app
    # lives there, so surface it as a base_path finding — content discovery must pivot off /.
    findings = parse_whatweb(_read("whatweb-basepath.txt"), 80)
    assert len(findings) == 2
    fingerprint, base = findings
    assert fingerprint.base_path == "" and "Apache" in fingerprint.note
    assert base.base_path == "/racers/"
    assert base.redirect_to == "/racers/"
    assert "base path" in base.note and "content discovery" in base.note


def test_whatweb_surfaces_email_domain_as_vhost_lead() -> None:
    # Snoopy: the landing page discloses info@snoopy.htb (whatweb's Email[] plugin). The email's
    # domain IS the box's domain — the prerequisite for the vhost enum that finds mm.snoopy.htb.
    # Surface it as a separate finding carrying email_domain so suggest() can lead there.
    findings = parse_whatweb(_read("whatweb-email.txt"), 80)
    assert len(findings) == 2
    fingerprint, lead = findings
    assert fingerprint.email_domain == "" and "nginx" in fingerprint.note
    assert lead.email_domain == "snoopy.htb"
    assert "/etc/hosts" in lead.note and "snoopy.htb" in lead.note


def test_whatweb_email_domain_json_path() -> None:
    import json

    doc = json.dumps(
        [
            {
                "target": "http://x/",
                "http_status": 200,
                "plugins": {
                    "Email": {"string": ["info@snoopy.htb"]},
                    "Title": {"string": ["Home"]},
                },
            }
        ]
    )
    domains = [f.email_domain for f in parse_whatweb(doc, 80) if f.email_domain]
    assert domains == ["snoopy.htb"]


def test_email_domains_filters_public_providers() -> None:
    from oscprecon.modules.http.parsers import email_domains_from_plugins

    # public mailboxes / RFC-2606 placeholders are contact noise, never a target-domain lead
    assert email_domains_from_plugins([("Email", "support@gmail.com")]) == []
    assert email_domains_from_plugins([("Email", "a@example.com")]) == []
    # a real (lab) domain surfaces; multiple addresses in one value are all mined + deduped
    assert email_domains_from_plugins([("Email", "a@gmail.com,admin@corp.local,b@snoopy.htb")]) == [
        "corp.local",
        "snoopy.htb",
    ]
    # only the Email plugin is mined — a Title that happens to contain an '@' is not a lead
    assert email_domains_from_plugins([("Title", "chat@snoopy.htb portal")]) == []


def test_parse_webpage_mines_lab_host_from_body() -> None:
    # Carpediem: the domain lives only in an <h1>carpediem.htb</h1> — whatweb never sees body text,
    # so the index snapshot is mined for lab hostnames. CDN/vendor domains must stay ignored.
    from oscprecon.modules.http.parsers import parse_webpage

    findings = parse_webpage(_read("index-page-host.html"), 80)
    assert len(findings) == 1
    assert findings[0].page_host == "carpediem.htb"
    assert findings[0].path == "/"
    assert "/etc/hosts" in findings[0].note and "carpediem.htb" in findings[0].note


def test_lab_hostnames_from_text_shapes() -> None:
    from oscprecon.modules.http.parsers import lab_hostnames_from_text

    # only pentesting-lab TLDs (real CDN/vendor .com/.org are never a lab lead)
    assert lab_hostnames_from_text("https://cdn.bootstrapcdn.com/x https://www.w3.org/") == []
    # multiple lab hosts incl a subdomain -> deduped, first-seen order, case-insensitive
    assert lab_hostnames_from_text("<h1>Carpediem.htb</h1> portal.carpediem.htb CARPEDIEM.HTB") == [
        "carpediem.htb",
        "portal.carpediem.htb",
    ]
    assert lab_hostnames_from_text("a.htb b.vl c.thm d.local e.corp f.internal") == [
        "a.htb",
        "b.vl",
        "c.thm",
        "d.local",
        "e.corp",
        "f.internal",
    ]


def test_base_path_from_redirect_shapes() -> None:
    from oscprecon.modules.http.parsers import base_path_from_redirect

    assert base_path_from_redirect("/racers/") == "/racers/"
    assert base_path_from_redirect("/racers") == "/racers/"  # bare dir gets a trailing slash
    assert base_path_from_redirect("http://race.vl/racers/") == "/racers/"
    assert base_path_from_redirect("/wordpress/wp-login.php") == "/wordpress/"  # keep the dir
    assert base_path_from_redirect("/") == ""  # root -> nothing to pivot into
    assert base_path_from_redirect("/index.php") == ""  # a file at root is not a base path
    assert base_path_from_redirect("http://unika.htb/") == ""  # a vhost is not a base path


def test_deep_path_redirect_is_not_a_base_path() -> None:
    # a normal trailing-slash 301 on a deep path (/admin -> /admin/) must NOT be flagged as the
    # app's base path — only a redirect observed AT the site root counts.
    findings = parse_feroxbuster(
        "301      GET        9l       28w      315c "
        "http://10.129.234.209/admin => http://10.129.234.209/admin/",
        80,
    )
    assert findings and all(f.base_path == "" for f in findings)


def test_whatweb_plain_strips_ansi_colour() -> None:
    coloured = (
        "\x1b[1m\x1b[34mhttp://t/\x1b[0m [200 OK] "
        "\x1b[1mApache\x1b[0m[\x1b[32m2.4.38\x1b[0m], "
        "\x1b[1mTitle\x1b[0m[\x1b[33mDashboard, home\x1b[0m]\n"
    )
    findings = parse_whatweb(coloured, 80)
    assert len(findings) == 1
    assert findings[0].status == 200
    # the comma inside Title[Dashboard, home] must not split into a bogus plugin name, and the
    # plugin VALUES are kept (Apache version, page title) — they are the real recon signal
    assert findings[0].note == "whatweb: Apache[2.4.38], Title[Dashboard, home]"


def test_whatweb_plain_keeps_plugin_values() -> None:
    # the identifying signal is the plugin VALUE (Title[UniFi Network], HTTPServer[Apache/2.4.38]),
    # not just the bare plugin name — Unified: whatweb on 8443 must surface "UniFi Network". Country
    # and IP values are dropped as noise (RESERVED/ZZ, the target IP we already know).
    line = (
        "https://10.129.34.143:8443/manage/account/login [200 OK] "
        "Country[RESERVED][ZZ], HTML5, IP[10.129.34.143], Script, "
        "Title[UniFi Network], X-Frame-Options[SAMEORIGIN]\n"
    )
    findings = parse_whatweb(line, 8443)
    assert len(findings) == 1
    note = findings[0].note
    assert "Title[UniFi Network]" in note  # the app identity is preserved
    assert "X-Frame-Options[SAMEORIGIN]" in note
    assert "Country[" not in note and "IP[" not in note  # noise values dropped
    assert "Country" in note and "IP" in note  # ...but the names are kept


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


def test_parse_robots_surfaces_disclosed_paths_and_sitemap() -> None:
    findings = parse_robots(_read("robots-wordpress.txt"), 443)
    assert len(findings) == 1
    f = findings[0]
    assert f.path == "/robots.txt"
    # every disallowed/allowed path is disclosed, the catch-all "/" is dropped, sitemap surfaced
    assert "/wp-admin/" in f.note
    assert "/backup/" in f.note
    assert "/secret-admin/" in f.note
    assert "sitemap: https://phoenix.htb/sitemap.xml" in f.note
    assert parse_tool("robots", _read("robots-wordpress.txt"), 443)[0].path == "/robots.txt"


def test_parse_robots_empty_and_catch_all_yield_nothing() -> None:
    # a blank robots or one that only disallows everything ("/") discloses no specific path
    assert parse_robots("", 80) == []
    assert parse_robots("User-agent: *\nDisallow: /\n", 80) == []


def test_parse_robots_strips_inline_comments() -> None:
    # RFC 9309: a rule line may carry a trailing '#' comment — it must not leak into the disclosed
    # path, and two lines for the same path with different comments must still dedup.
    note = parse_robots("Disallow: /admin/   # hide it\nDisallow: /admin/ # again", 80)[0].note
    assert "1 path(s): /admin/" in note
    assert "#" not in note  # comment text stripped, not swallowed into the path
    # a comment-only value is dropped; a '#' fused to the path (no preceding space) is kept
    assert parse_robots("Disallow: # nothing\nDisallow: /real/", 80)[0].note.endswith("/real/")
    assert parse_robots("Disallow: /a#b", 80)[0].note.endswith("/a#b")


def test_detect_api_server_fires_on_asgi_and_json_signals() -> None:
    # Spooktrol: an ASGI server (uvicorn) / FastAPI banner / JSON content-type marks a JSON API —
    # the tell to enumerate the API schema, not dir-bust for files.
    assert detect_api_server("whatweb: HTTPServer[uvicorn], Country[RESERVED][ZZ]") is True
    assert detect_api_server("http-server-header: uvicorn") is True
    assert detect_api_server("Site doesn't have a title (application/json)") is True
    assert detect_api_server("X-Powered-By[FastAPI]") is True
    assert detect_api_server("Server[hypercorn]") is True
    # ordinary sites must NOT trip it — gunicorn is excluded (it fronts HTML Django/Flask too)
    assert detect_api_server("Apache[2.4.52], PHP[8.1], WordPress") is False
    assert detect_api_server("HTTPServer[gunicorn], Django") is False
    assert detect_api_server("nginx 1.18") is False


def test_detect_api_server_no_false_positive_on_bodies_and_names() -> None:
    # the name markers must sit in a SERVER-header context, and the JSON type must be anchored —
    # else the most common web targets false-fire (adversarial-review regressions):
    assert detect_api_server('<link type="application/json+oembed" href="/wp-json/">') is False
    assert detect_api_server("Content-Type: application/ld+json") is False
    assert detect_api_server("Computer name: DAPHNE") is False  # SMB host name, not a server header
    assert detect_api_server("<h1>Growing Daphne odora</h1>") is False  # a shrub in page text
    assert detect_api_server("whatweb: Title[Daphne's Blog], HTTPServer[nginx]") is False
    # a real content-type / server header still fires
    assert detect_api_server("Content-Type: application/json") is True
    assert detect_api_server("http-server-header: uvicorn") is True


def test_parse_robots_no_redos_on_hostile_input() -> None:
    # the target serves robots.txt (untrusted) — a long internal whitespace run or a huge
    # unique-path file must parse in linear time, never the O(n^2) a lazy regex + anchor incurs.
    import time

    hostile = "Disallow: /a" + " " * 200_000 + "b"
    start = time.perf_counter()
    parse_robots(hostile, 80)
    parse_robots("\n".join(f"Disallow: /p{i}" for i in range(50_000)), 80)
    assert time.perf_counter() - start < 2.0  # was ~18s combined before the fix


def test_detect_wordpress_fires_on_robots_wp_admin_signal() -> None:
    # the canonical WordPress robots.txt fingerprint (Disallow: /wp-admin/) must be detected even
    # when whatweb never emits the product name — both on the raw text and the parse_robots note.
    robots = _read("robots-wordpress.txt")
    assert detect_wordpress(robots) is True
    assert detect_wordpress(parse_robots(robots, 443)[0].note) is True
    # the wp-includes / wp-json markers are recognised too
    assert detect_wordpress("Disallow: /wp-includes/") is True
    assert detect_wordpress('<link rel="https://api.w.org/" href="/wp-json/">') is True
    # and no false positive on an unrelated page that merely mentions "admin"
    assert detect_wordpress("Apache index of /uploads/ admin login") is False


def test_is_source_disclosure_flags_swap_backup_vcs() -> None:
    from oscprecon.modules.http.parsers import is_source_disclosure

    assert is_source_disclosure("/login/login.php.swp")  # HTB Base — the box's key signal
    assert is_source_disclosure("/index.php.bak")
    assert is_source_disclosure("/config.old")
    assert is_source_disclosure("/.git/HEAD")
    assert is_source_disclosure("/.git")  # the VCS dir itself, no trailing content
    assert is_source_disclosure("/backup/.svn/entries")  # VCS dir not at the root
    assert is_source_disclosure("/db/dump.sql")
    assert is_source_disclosure("/app/index.php~")
    # normal pages / dirs are NOT source disclosures
    assert not is_source_disclosure("/config.php")  # executes, doesn't leak source
    assert not is_source_disclosure("/index.php")
    assert not is_source_disclosure("/login/")
    assert not is_source_disclosure("/assets/js/main.js")
    # regression: a VCS marker must be a whole path SEGMENT, not a bare substring
    assert not is_source_disclosure("/.gitignore")
    assert not is_source_disclosure("/.gitlab-ci.yml")
    assert not is_source_disclosure("/.svnfoo")


def test_interesting_path_reason_flags_upload_dirs_and_disclosures() -> None:
    # HTB Breadcrumbs: /portal/uploads/ is the webshell-drop target — a discovered upload directory
    # gets its own flag in the Discovered-URLs table, distinct from a source/backup disclosure.
    from oscprecon.modules.http.parsers import interesting_path_reason, is_upload_dir

    assert is_upload_dir("/portal/uploads/") and is_upload_dir("/fileupload")
    assert interesting_path_reason("/portal/uploads/") == "upload directory"
    assert interesting_path_reason("/login/login.php.swp") == "source/backup disclosure"
    # high-signal only — generic dirs are NOT flagged as upload targets (no noise)
    for noise in ("/files/", "/images/", "/media/", "/books/", "/portal/", "/", "/index.php"):
        assert interesting_path_reason(noise) == "", noise


def test_is_source_archive_flags_root_source_dumps() -> None:
    # HTB Intense: the app advertises "open source" and serves src.zip at the web root — the single
    # highest-value HTTP finding. Flag source/backup ARCHIVES, but only for a high-signal stem.
    from oscprecon.modules.http.parsers import (
        interesting_path_reason,
        is_source_archive,
        is_source_disclosure,
    )

    for p in ("/src.zip", "/source.tar.gz", "/www.zip", "/backup.7z", "/site.tgz", "/app.rar"):
        assert is_source_archive(p), p
        assert is_source_disclosure(p), p  # rolls up into the disclosure flag
        assert interesting_path_reason(p) == "leaked source archive", p
    # noise stays quiet — an archive without a source/backup stem is NOT a disclosure
    for noise in ("/jquery.zip", "/report-2021.zip", "/downloads/manual.pdf.zip", "/photos.tar"):
        assert not is_source_archive(noise), noise
        assert interesting_path_reason(noise) == "", noise


def test_whatweb_json_yields_redirect_vhost() -> None:
    # regression: the JSON path dropped the redirect->vhost finding the plain path produces
    import json

    doc = json.dumps(
        [
            {
                "target": "http://10.10.10.5/",
                "http_status": 200,
                "plugins": {
                    "Meta-Refresh-Redirect": {"string": ["http://unika.htb/"]},
                    "HTTPServer": {"string": ["Apache/2.4.38"]},
                },
            }
        ]
    )
    vhosts = [f.redirect_to for f in parse_whatweb(doc, 80) if f.redirect_to]
    assert vhosts == ["unika.htb"]
    # the bare-list plugin shape (older whatweb) is handled too
    doc2 = json.dumps(
        [{"target": "http://10.10.10.5/", "plugins": {"RedirectLocation": ["http://blog.x.htb/"]}}]
    )
    assert [f.redirect_to for f in parse_whatweb(doc2, 80) if f.redirect_to] == ["blog.x.htb"]


def test_detect_invalid_hostname_and_parse_headers() -> None:
    from oscprecon.modules.http.parsers import detect_invalid_hostname, parse_headers

    # a bare-IP HTTP 400 from a host-header-gated service (IIS/Microsoft-HTTPAPI — HTB Ethereal)
    hdr = (
        "HTTP/1.1 400 Bad Request\nServer: Microsoft-HTTPAPI/2.0\n"
        "<h2>Bad Request - Invalid Hostname</h2>\n"
        "<p>HTTP Error 400. The request hostname is invalid.</p>\n"
    )
    assert detect_invalid_hostname(hdr) is True
    hits = parse_headers(hdr, 8080)
    assert len(hits) == 1 and hits[0].status == 400
    assert "vhost" in hits[0].note.lower() or "host header" in hits[0].note.lower()
    assert parse_tool("headers", hdr, 8080)  # wired into the dispatch


def test_detect_invalid_hostname_negative_on_normal_response() -> None:
    from oscprecon.modules.http.parsers import detect_invalid_hostname, parse_headers

    ok = "HTTP/1.1 200 OK\nServer: Microsoft-IIS/10.0\nContent-Type: text/html; charset=utf-8\n"
    assert detect_invalid_hostname(ok) is False
    assert parse_headers(ok, 80) == []


def test_lab_hostnames_is_linear_no_redos() -> None:
    import time

    from oscprecon.modules.http.parsers import lab_hostnames_from_text

    # a crafted contiguous dotted run (no lab TLD) used to backtrack O(n^2) -> minutes. Bounded now.
    payload = "a." * 40000 + "a"
    start = time.perf_counter()
    lab_hostnames_from_text(payload)
    assert time.perf_counter() - start < 1.0  # linear, well under a second
    # real lab hostnames still mined
    assert lab_hostnames_from_text("see admin.sizzle.htb and dev.htb") == [
        "admin.sizzle.htb",
        "dev.htb",
    ]
