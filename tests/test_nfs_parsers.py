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
    findings = parse_nmap_nfs(_read("nmap-nfs.txt"))
    files = {f.value for f in findings if f.kind == "file"}
    assert files == {"motd", "id_rsa", "notes.txt"}  # '.' and '..' excluded
    id_rsa = next(f for f in findings if f.value == "id_rsa")
    # per-volume attribution: id_rsa lives in /opt/backups, not the header volume /var/nfs/general
    assert "/opt/backups" in id_rsa.detail
    # real nmap emits a 10-char perm with a leading type char — it must survive intact
    assert id_rsa.detail.startswith("-rw-------")
    motd = next(f for f in findings if f.value == "motd")
    assert "/var/nfs/general" in motd.detail


def test_nmap_nfs_access_detects_writable() -> None:
    access = {
        f.value: f.detail for f in parse_nmap_nfs(_read("nmap-nfs.txt")) if f.kind == "access"
    }
    # each export's access line is attributed to its own volume, not the first one
    assert "writable" in access["/opt/backups"]  # 'Modify' present
    assert "read-only" in access["/var/nfs/general"]  # 'NoModify'


def test_nmap_nfs_multi_volume_attribution() -> None:
    # regression: a standalone `Volume /X` line (the 2nd+ export) must re-anchor attribution, else
    # every file/access after the first volume is credited to the wrong export.
    text = (
        "| nfs-ls: Volume /exportA\n"
        "|   access: Read Lookup NoModify NoExtend NoDelete NoExecute\n"
        "|   -rw-r--r--  0 0 10 2026-01-10T22:13:37 fileA\n"
        "|   Volume /exportB\n"
        "|   access: Read Lookup Modify Extend Delete NoExecute\n"
        "|_  -rw-------  0 0 20 2026-01-10T22:13:37 secret.key\n"
    )
    findings = parse_nmap_nfs(text)
    secret = next(f for f in findings if f.value == "secret.key")
    assert "/exportB" in secret.detail  # not mis-attributed to /exportA
    access = {f.value: f.detail for f in findings if f.kind == "access"}
    assert "writable" in access["/exportB"]
    assert "read-only" in access["/exportA"]


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
