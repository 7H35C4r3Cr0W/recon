import io
import tarfile
from pathlib import Path

import pytest

from oscprecon.models import Target
from oscprecon.profile import Profile
from oscprecon.workspace import portability
from oscprecon.workspace.portability import ProjectArchiveError


def _make_profile(workspace: Path, name: str, ip: str) -> Profile:
    prof = Profile.create(workspace, name, Target(ip=ip))
    (prof.directory / "notes.md").write_text("recon notes\n", encoding="utf-8")
    prof.save()
    return prof


def _write_tar(path: Path, build: object) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        build(tar)  # type: ignore[operator]
    return path


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes = b"x") -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


# ---- export / import round-trip -------------------------------------------------------------


def test_export_then_import_roundtrips(tmp_path: Path) -> None:
    ws1 = tmp_path / "ws1"
    prof = _make_profile(ws1, "htb-active", "10.10.10.100")
    archive = portability.export_project_archive(prof.directory, tmp_path)
    assert archive.name == "htb-active.tar.gz" and archive.is_file()

    ws2 = tmp_path / "ws2"
    dest = portability.import_project_archive(archive, ws2)
    assert dest == ws2 / "htb-active"
    reloaded = Profile.load(dest)
    assert reloaded.target.ip == "10.10.10.100"
    assert (dest / "notes.md").read_text(encoding="utf-8") == "recon notes\n"


# ---- delete_project (guarded, irreversible) --------------------------------------------------


def test_delete_project_removes_the_folder(tmp_path: Path) -> None:
    prof = _make_profile(tmp_path, "htb-active", "10.10.10.100")
    assert prof.directory.is_dir()
    portability.delete_project(prof.directory, tmp_path)
    assert not prof.directory.exists()


def test_delete_project_deletes_corrupt_profile(tmp_path: Path) -> None:
    # a folder with no profile.json (a broken project) must still be removable to clean up
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "notes.md").write_text("stub\n", encoding="utf-8")
    portability.delete_project(broken, tmp_path)
    assert not broken.exists()


def test_delete_project_refuses_the_workspace_root(tmp_path: Path) -> None:
    with pytest.raises(ProjectArchiveError):
        portability.delete_project(tmp_path, tmp_path)
    assert tmp_path.is_dir()  # the root is untouched


def test_delete_project_refuses_paths_outside_the_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "not-in-workspace"
    outside.mkdir()
    try:
        with pytest.raises(ProjectArchiveError):
            portability.delete_project(outside, tmp_path / "ws")
        assert outside.is_dir()  # nothing outside the workspace is ever removed
    finally:
        outside.rmdir()


def test_delete_project_refuses_nested_grandchild(tmp_path: Path) -> None:
    # only a DIRECT child of the workspace root is a project — a deeper path is refused
    nested = tmp_path / "htb-active" / "nmap"
    nested.mkdir(parents=True)
    with pytest.raises(ProjectArchiveError):
        portability.delete_project(nested, tmp_path)
    assert nested.is_dir()


def test_export_to_explicit_archive_path(tmp_path: Path) -> None:
    prof = _make_profile(tmp_path / "ws", "box", "10.0.0.1")
    out = tmp_path / "backups" / "custom.tar.gz"
    archive = portability.export_project_archive(prof.directory, out)
    assert archive == out and out.is_file()


def test_export_drops_transient_lock_and_tmp(tmp_path: Path) -> None:
    prof = _make_profile(tmp_path / "ws", "box", "10.0.0.1")
    (prof.directory / ".lock").write_text("pid\n", encoding="utf-8")
    (prof.directory / "profile.json.tmp").write_text("partial", encoding="utf-8")
    archive = portability.export_project_archive(prof.directory, tmp_path)
    with tarfile.open(archive) as tar:
        names = {Path(n).name for n in tar.getnames()}
    assert ".lock" not in names and "profile.json.tmp" not in names
    assert "profile.json" in names  # real data still travels


def test_export_rejects_non_profile_dir(tmp_path: Path) -> None:
    plain = tmp_path / "notaprofile"
    plain.mkdir()
    with pytest.raises(ProjectArchiveError, match="not a profile"):
        portability.export_project_archive(plain, tmp_path)


# ---- find by IP -----------------------------------------------------------------------------


def test_find_profiles_by_ip(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    _make_profile(ws, "a", "10.10.10.5")
    _make_profile(ws, "b", "10.10.10.5")
    _make_profile(ws, "c", "192.168.1.1")
    matches = {p.name for p in portability.find_profiles_by_ip(ws, "10.10.10.5")}
    assert matches == {"a", "b"}
    assert portability.find_profiles_by_ip(ws, "172.16.0.9") == []
    assert portability.find_profiles_by_ip(ws, "") == []


def test_find_profiles_by_ip_skips_corrupt(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    _make_profile(ws, "good", "10.10.10.5")
    broken = ws / "broken"
    broken.mkdir()
    (broken / "profile.json").write_text("{not json", encoding="utf-8")
    matches = [p.name for p in portability.find_profiles_by_ip(ws, "10.10.10.5")]
    assert matches == ["good"]  # corrupt profile skipped, not raised


# ---- collision handling ---------------------------------------------------------------------


def test_import_refuses_to_clobber_without_overwrite(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    prof = _make_profile(ws, "box", "10.0.0.1")
    archive = portability.export_project_archive(prof.directory, tmp_path)
    with pytest.raises(ProjectArchiveError, match="already exists"):
        portability.import_project_archive(archive, ws)  # same workspace → collision


def test_import_overwrite_replaces_cleanly(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    prof = _make_profile(ws, "box", "10.0.0.1")
    archive = portability.export_project_archive(prof.directory, tmp_path)
    # a stale file present only in the on-disk copy must be gone after an overwrite import
    (prof.directory / "stale.txt").write_text("old", encoding="utf-8")
    dest = portability.import_project_archive(archive, ws, overwrite=True)
    assert dest == ws / "box"
    assert not (dest / "stale.txt").exists()


# ---- malicious archive rejection ------------------------------------------------------------


def test_import_rejects_path_traversal(tmp_path: Path) -> None:
    bad = _write_tar(
        tmp_path / "bad.tar.gz",
        lambda t: (_add_bytes(t, "proj/profile.json", b"{}"), _add_bytes(t, "proj/../../pwned")),
    )
    with pytest.raises(ProjectArchiveError, match="traversal"):
        portability.import_project_archive(bad, tmp_path / "ws")
    assert not (tmp_path / "pwned").exists()  # nothing escaped


def test_import_rejects_absolute_path(tmp_path: Path) -> None:
    bad = _write_tar(tmp_path / "bad.tar.gz", lambda t: _add_bytes(t, "/etc/pwned"))
    with pytest.raises(ProjectArchiveError, match="unsafe path"):
        portability.import_project_archive(bad, tmp_path / "ws")


def test_import_rejects_symlink(tmp_path: Path) -> None:
    def build(tar: tarfile.TarFile) -> None:
        _add_bytes(tar, "proj/profile.json", b"{}")
        link = tarfile.TarInfo("proj/escape")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)

    bad = _write_tar(tmp_path / "bad.tar.gz", build)
    with pytest.raises(ProjectArchiveError, match="link"):
        portability.import_project_archive(bad, tmp_path / "ws")


def test_import_rejects_multiple_top_level_dirs(tmp_path: Path) -> None:
    bad = _write_tar(
        tmp_path / "bad.tar.gz",
        lambda t: (_add_bytes(t, "a/profile.json", b"{}"), _add_bytes(t, "b/profile.json", b"{}")),
    )
    with pytest.raises(ProjectArchiveError, match="one top-level"):
        portability.import_project_archive(bad, tmp_path / "ws")


def test_import_rejects_non_profile_archive_and_leaves_no_trace(tmp_path: Path) -> None:
    bad = _write_tar(tmp_path / "bad.tar.gz", lambda t: _add_bytes(t, "proj/notes.md", b"hi"))
    ws = tmp_path / "ws"
    with pytest.raises(ProjectArchiveError, match="not a profile"):
        portability.import_project_archive(bad, ws)
    assert not (ws / "proj").exists()  # staging cleaned up, nothing left behind


def test_import_rejects_backslash_names(tmp_path: Path) -> None:
    bad = _write_tar(tmp_path / "bad.tar.gz", lambda t: _add_bytes(t, "..\\..\\pwned"))
    with pytest.raises(ProjectArchiveError, match="unsafe path"):
        portability.import_project_archive(bad, tmp_path / "ws")


def test_import_rejects_decompression_bomb(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(portability, "_MAX_TOTAL_BYTES", 16)  # tiny cap for the test
    bad = _write_tar(
        tmp_path / "bomb.tar.gz",
        lambda t: (
            _add_bytes(t, "proj/profile.json", b"{}"),
            _add_bytes(t, "proj/big.bin", b"x" * 64),  # exceeds the 16-byte cap
        ),
    )
    with pytest.raises(ProjectArchiveError, match="too large"):
        portability.import_project_archive(bad, tmp_path / "ws")


def test_import_rejects_non_tar(tmp_path: Path) -> None:
    junk = tmp_path / "not.tar.gz"
    junk.write_bytes(b"this is not a tar archive at all")
    with pytest.raises(ProjectArchiveError, match="not a readable tar"):
        portability.import_project_archive(junk, tmp_path / "ws")


def test_import_missing_archive(tmp_path: Path) -> None:
    with pytest.raises(ProjectArchiveError, match="no such archive"):
        portability.import_project_archive(tmp_path / "nope.tar.gz", tmp_path / "ws")
