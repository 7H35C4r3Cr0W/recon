from pathlib import Path

from oscprecon.modules.ftp.parsers import (
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
