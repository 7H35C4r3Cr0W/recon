import io
import tarfile
from pathlib import Path

from typer.testing import CliRunner

from oscprecon.cli import app
from oscprecon.models import Target
from oscprecon.profile import Profile
from oscprecon.workspace import portability

runner = CliRunner()


def test_export_then_import_roundtrip(tmp_path: Path) -> None:
    ws1 = tmp_path / "ws1"
    Profile.create(ws1, "box", Target(ip="10.0.0.9"))
    r = runner.invoke(
        app, ["export-project", str(tmp_path), "--profile", "box", "--workspace", str(ws1)]
    )
    assert r.exit_code == 0
    assert "creds.json" in r.output  # the sensitivity warning is surfaced
    archive = tmp_path / "box.tar.gz"
    assert archive.is_file()

    ws2 = tmp_path / "ws2"
    r2 = runner.invoke(app, ["import-project", str(archive), "--workspace", str(ws2)])
    assert r2.exit_code == 0
    assert (ws2 / "box" / "profile.json").is_file()


def test_export_missing_profile_exits_2(tmp_path: Path) -> None:
    r = runner.invoke(
        app,
        ["export-project", str(tmp_path), "--profile", "nope", "--workspace", str(tmp_path / "ws")],
    )
    assert r.exit_code == 2
    assert "no profile" in r.output


def test_import_traversal_archive_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        info = tarfile.TarInfo("proj/../../pwned")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    r = runner.invoke(app, ["import-project", str(bad), "--workspace", str(tmp_path / "ws")])
    assert r.exit_code == 2
    assert not (tmp_path / "pwned").exists()


def test_import_collision_needs_overwrite(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    prof = Profile.create(ws, "box", Target(ip="10.0.0.9"))
    archive = portability.export_project_archive(prof.directory, tmp_path)
    r = runner.invoke(app, ["import-project", str(archive), "--workspace", str(ws)])
    assert r.exit_code == 2
    assert "overwrite" in r.output
    r2 = runner.invoke(app, ["import-project", str(archive), "--workspace", str(ws), "--overwrite"])
    assert r2.exit_code == 0
