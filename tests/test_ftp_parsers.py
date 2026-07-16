from pathlib import Path

from oscprecon.modules.ftp.parsers import (
    FtpFinding,
    dedup_ftp_findings,
    nmap_anon_ok,
    parse_curl_list,
    parse_ftp_listing,
    parse_ftp_tool,
    parse_nmap_ftp,
    subdirs,
)

FIX = Path(__file__).parent / "fixtures" / "ftp"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_parse_unix_listing() -> None:
    entries = {e.name: e for e in parse_ftp_listing(_read("curl-list-unix.txt"))}
    assert entries["backups"].is_dir
    assert not entries["readme.txt"].is_dir
    assert entries["readme.txt"].size == 452
    assert entries["archive.zip"].size == 10240
    # a symlink keeps its own name (target stripped) and is treated as a non-dir (no recursion)
    assert "www" in entries and not entries["www"].is_dir
    # a directory name with a space survives
    assert entries["New Folder"].is_dir


def test_parse_dos_listing() -> None:
    entries = {e.name: e for e in parse_ftp_listing(_read("curl-list-dos.txt"))}
    assert entries["uploads"].is_dir
    assert entries["web.config"].size == 452
    assert entries["backup.zip"].size == 10240
    assert not entries["web.config"].is_dir


def test_subdirs_only_returns_directories() -> None:
    assert set(subdirs(_read("curl-list-unix.txt"))) == {"backups", "New Folder"}


def test_curl_list_findings_paths() -> None:
    findings = {f.value: f for f in parse_curl_list(_read("curl-list-unix.txt"))}
    assert "/backups" in findings and findings["/backups"].kind == "dir"
    assert findings["/readme.txt"].kind == "file"
    assert findings["/readme.txt"].detail == "452 bytes"


def test_parse_nmap_ftp() -> None:
    text = _read("nmap-ftp.txt")
    assert nmap_anon_ok(text) is True
    findings = parse_nmap_ftp(text)
    kinds = {(f.kind, f.value) for f in findings}
    assert ("auth", "anonymous") in kinds
    assert ("banner", "vsftpd 3.0.3") in kinds
    assert ("dir", "/pub") in kinds
    assert ("dir", "/uploads") in kinds
    assert ("file", "/note.txt") in kinds
    # the ftp-syst STAT block must not be misparsed as listing entries
    assert not any(f.value in ("/ASCII", "/ftp") for f in findings)


def test_multi_space_filenames_preserved() -> None:
    # a filename with 2+ consecutive spaces must survive (split()/join collapsed it before)
    unix = "drwxr-xr-x    2 0        0            4096 Jun 20  2023 two  dirs\n"
    names = {e.name for e in parse_ftp_listing(unix)}
    assert "two  dirs" in names
    assert "two dirs" not in names


def test_nmap_writeable_marker_stripped_and_noted() -> None:
    # nmap ftp-anon appends " [NSE: writeable]" to writable entries — it must not land in the name
    nmap = (
        "| ftp-anon: Anonymous FTP login allowed (FTP code 230)\n"
        "|_drwxr-srwt   2 1170  924  2048 Jul 19 18:48 incoming [NSE: writeable]\n"
    )
    findings = parse_nmap_ftp(nmap)
    dirs = {f.value for f in findings if f.kind == "dir"}
    notes = {f.value for f in findings if f.kind == "note"}
    assert "/incoming" in dirs
    assert "/incoming [NSE: writeable]" not in dirs
    assert "writable: /incoming" in notes


def test_nmap_anon_denied() -> None:
    denied = "21/tcp open  ftp\n|_ftp-anon: Anonymous login not permitted\n"
    assert nmap_anon_ok(denied) is False
    assert not any(f.kind == "auth" for f in parse_nmap_ftp(denied))


def test_dispatch_and_garbage() -> None:
    assert parse_ftp_tool("unknown", "x") == []
    assert parse_ftp_tool("curl-list", _read("curl-list-unix.txt"))
    assert parse_ftp_listing("total 8\nnot a listing line") == []


def test_dedup_collapses_nmap_and_curl_root_overlap() -> None:
    # Crocodile: nmap ftp-anon AND the curl walk both list the root, so each file arrived twice.
    findings = [
        FtpFinding("auth", "anonymous", "Anonymous FTP login allowed"),
        FtpFinding("file", "/allowed.userlist", "33 bytes"),  # from nmap ftp-anon (thinner detail)
        FtpFinding("file", "/allowed.userlist.passwd", "62 bytes"),
        FtpFinding("file", "/allowed.userlist", "33 bytes (no ext)"),  # from the walk (richer)
        FtpFinding("file", "/allowed.userlist.passwd", "62 bytes (passwd)"),
    ]
    deduped = dedup_ftp_findings(findings)
    values = [f.value for f in deduped]
    assert values == ["anonymous", "/allowed.userlist", "/allowed.userlist.passwd"]  # once each
    by_val = {f.value: f.detail for f in deduped}
    assert by_val["/allowed.userlist"] == "33 bytes (no ext)"  # richer detail kept


def test_ftp_entry_extension() -> None:
    from oscprecon.modules.ftp.parsers import FtpEntry

    assert FtpEntry("db.conf", False, 10).extension == "conf"
    assert FtpEntry("README", False, 10).extension == ""  # no extension
    assert FtpEntry(".bashrc", False, 10).extension == ""  # dotfile, not an extension
    assert FtpEntry("ARCHIVE.TAR.GZ", False, 10).extension == "gz"


def test_peek_snippet_is_safe_and_bounded() -> None:
    from oscprecon.modules.ftp.parsers import peek_snippet

    assert peek_snippet("root:x:0:0:root:/root") == "root:x:0:0:root:/root"
    assert peek_snippet("line1\nline2\ttab") == "line1 line2 tab"  # whitespace collapsed
    assert peek_snippet("\x00\x01\x02\xff\xfe binary \x00\x00") == "(binary or non-text content)"
    assert peek_snippet("") == "(empty)" and peek_snippet("   ") == "(empty)"
    long = "A" * 200
    out = peek_snippet(long, limit=60)
    assert len(out) == 61 and out.endswith("…")  # capped + ellipsis
    assert "\x1b" not in peek_snippet("\x1b[31mred\x1b[0m text")  # control/ANSI stripped


def test_is_peekable_only_small_text_files() -> None:
    from oscprecon.modules.ftp import PEEK_MAX_BYTES, is_peekable
    from oscprecon.modules.ftp.parsers import FtpEntry

    assert is_peekable(FtpEntry("db.conf", False, 200)) is True
    assert is_peekable(FtpEntry("readme", False, 1600)) is True  # no-ext small file
    assert is_peekable(FtpEntry("etc", True, 0)) is False  # directory
    assert is_peekable(FtpEntry("huge.log", False, PEEK_MAX_BYTES + 1)) is False  # too big
    assert is_peekable(FtpEntry("photo.jpg", False, 500)) is False  # binary extension
    assert is_peekable(FtpEntry("weird", False, 0)) is False  # unknown/zero size
    # secret material is never peeked — its head would land unredacted in findings/report (#44)
    assert is_peekable(FtpEntry("id_rsa", False, 1600)) is False  # private key (no ext)
    assert is_peekable(FtpEntry("server.key", False, 1600)) is False  # private key ext
    assert is_peekable(FtpEntry(".htpasswd", False, 200)) is False  # password-hash store


def test_ftp_file_url_and_peek_step() -> None:
    from oscprecon.models import Target
    from oscprecon.modules.ftp import FtpModule, ftp_file_url

    assert ftp_file_url("10.0.0.1", 21, "/pub/db.conf") == "ftp://10.0.0.1/pub/db.conf"
    step = FtpModule().peek_step(Target(ip="10.0.0.1"), "/pub/db.conf")
    assert step.tool == "peek"
    assert (
        "curl -s" in step.command.shell_line
        and "ftp://10.0.0.1/pub/db.conf" in step.command.shell_line
    )
    assert "--max-time" in step.command.shell_line  # bounded even if the listed size was wrong
