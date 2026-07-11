from pathlib import Path

from oscprecon.modules.nfs.parsers import parse_nfs_tool, parse_nmap_nfs, parse_showmount

FIX = Path(__file__).parent / "fixtures" / "nfs"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_showmount_exports() -> None:
    exports = {f.value for f in parse_showmount(_read("showmount.txt")) if f.kind == "export"}
    assert exports == {"/var/nfs/general", "/home", "/opt/backups", "/srv/restricted"}


def test_showmount_world_readable() -> None:
    world = {f.value for f in parse_showmount(_read("showmount.txt")) if f.kind == "world-readable"}
    # '*' and '(everyone)' are world-readable; a CIDR ACL is not
    assert world == {"/var/nfs/general", "/opt/backups"}
    assert "/home" not in world  # 10.11.1.0/24 is restricted
    assert "/srv/restricted" not in world  # 192.168.56.0/24,10.0.0.0/8 is restricted


def test_showmount_skips_header_and_errors() -> None:
    assert parse_showmount("Export list for 10.0.0.1:\nclnt_create: RPC: Timed out\n") == []
    assert parse_showmount("[missing] showmount — install with: apt install nfs-common\n") == []


def test_nmap_nfs_banner() -> None:
    banners = [f.value for f in parse_nmap_nfs(_read("nmap-nfs.txt")) if f.kind == "banner"]
    assert banners and banners[0].startswith("2-3")


def test_nmap_nfs_exports_and_world_readable() -> None:
    findings = parse_nmap_nfs(_read("nmap-nfs.txt"))
    exports = {f.value for f in findings if f.kind == "export"}
    assert {"/var/nfs/general", "/opt/backups"} <= exports
    world = {f.value for f in findings if f.kind == "world-readable"}
    assert world == {"/opt/backups"}  # only the '*' export, not the /24-restricted one


def test_nmap_nfs_lists_files_and_skips_dot_entries() -> None:
    files = {f.value for f in parse_nmap_nfs(_read("nmap-nfs.txt")) if f.kind == "file"}
    assert files == {"id_rsa", "notes.txt"}  # '.' and '..' excluded
    id_rsa = next(f for f in parse_nmap_nfs(_read("nmap-nfs.txt")) if f.value == "id_rsa")
    assert "/opt/backups" in id_rsa.detail and id_rsa.detail.startswith("rw-------")


def test_nmap_nfs_access_detects_writable() -> None:
    access = [f for f in parse_nmap_nfs(_read("nmap-nfs.txt")) if f.kind == "access"]
    assert access and access[0].value == "/opt/backups"
    assert "writable" in access[0].detail  # 'Modify' present, not 'NoModify'


def test_access_read_only_not_misread_as_writable() -> None:
    text = (
        "| nfs-ls: Volume /ro\n"
        "|   access: Read Lookup NoModify NoExtend NoDelete NoExecute\n"
        "|_  rw-r--r--   0 0 10 2026-01-01T00:00:00 file\n"
    )
    access = [f for f in parse_nmap_nfs(text) if f.kind == "access"]
    assert access and "read-only" in access[0].detail  # 'NoModify' must not match \bModify\b


def test_dispatch_and_garbage() -> None:
    assert parse_nfs_tool("unknown", "x") == []
    assert parse_nfs_tool("showmount", _read("showmount.txt"))
    assert parse_nfs_tool("nmap-nfs", _read("nmap-nfs.txt"))
    assert parse_nmap_nfs("total 8\nnot an nmap line") == []
    assert parse_showmount("no exports here\n") == []
