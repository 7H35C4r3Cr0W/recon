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


def test_cli_creds_add_list_rm(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    Profile.create(ws, "box", Target(ip="10.0.0.9"))
    common = ["--profile", "box", "--workspace", str(ws)]
    assert runner.invoke(app, ["creds", "add", "-u", "admin", "-s", "pw", *common]).exit_code == 0
    assert (
        runner.invoke(
            app, ["creds", "add", "-u", "svc", "-s", "h", "--type", "hash", *common]
        ).exit_code
        == 0
    )
    listed = runner.invoke(app, ["creds", "list", *common])
    assert listed.exit_code == 0
    # secrets are shown IN FULL, exactly like the GUI vault — §6: never redact by default, your own
    # loot against your own authorized targets is the deliverable. (This test used to assert the
    # masked form, which contradicted both the policy and the GUI.)
    assert "admin" in listed.output and "pw" in listed.output
    assert "len=" not in listed.output
    assert runner.invoke(app, ["creds", "rm", "-u", "svc", *common]).exit_code == 0
    assert "svc" not in runner.invoke(app, ["creds", "list", *common]).output


def test_cli_list_and_delete_project(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    Profile.create(ws, "box", Target(ip="10.10.10.5"))
    listed = runner.invoke(app, ["list", "--workspace", str(ws)])
    assert listed.exit_code == 0 and "box" in listed.output and "10.10.10.5" in listed.output
    gone = runner.invoke(
        app, ["delete-project", "--profile", "box", "--yes", "--workspace", str(ws)]
    )
    assert gone.exit_code == 0
    assert not (ws / "box").exists()


def test_cli_config_toggle_and_spray_gate(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from oscprecon import config

    monkeypatch.setattr(config, "config_dir", lambda: tmp_path)  # isolate prefs.json
    ws = tmp_path / "ws"
    Profile.create(ws, "box", Target(ip="10.0.0.9"))
    # spray is refused while the gate is off (exam-legal default)
    off = runner.invoke(app, ["spray", "smb", "--profile", "box", "--workspace", str(ws)])
    assert off.exit_code == 2 and "Spray mode is OFF" in off.output
    shown = runner.invoke(app, ["config"])
    assert "spray_enabled   = False" in shown.output


# --- 2026-07-24 full-spectrum review regressions -------------------------------------------------
def _profile_with(tmp_path: Path, *services: object) -> Path:
    from oscprecon.models import DiscoveredService

    ws = tmp_path / "ws"
    prof = Profile.create(ws, "box", Target(ip="10.10.10.5"))
    if services:
        prof.set_services([s for s in services if isinstance(s, DiscoveredService)])
        prof.save()
    return ws


def test_enum_keeps_every_parsed_field_so_vhosts_stay_distinct(tmp_path: Path) -> None:
    # review finding (HIGH): the enum transform kept only kind/value, so three discovered vhosts
    # became three identical blank rows and the dedup collapsed them into one — names lost.
    from oscprecon import findings as findings_mod
    from oscprecon.modules.vhost import VhostModule

    ws = _profile_with(tmp_path)
    directory = ws / "box"
    parsed = VhostModule().parse(
        {
            "ffuf": (
                '{"results":[{"host":"admin.corp.htb","status":200,"length":100,'
                '"input":{"FUZZ":"admin"}},{"host":"dev.corp.htb","status":200,"length":120,'
                '"input":{"FUZZ":"dev"}}]}'
            )
        }
    )
    assert len(parsed) == 2
    findings_mod.add_findings(
        directory,
        [
            findings_mod.from_parsed(f.service, f.fields, f.detail, "2026-07-24T00:00:00Z")
            for f in parsed
        ],
    )
    rows = findings_mod.load_findings(directory)
    assert len(rows) == 2  # not collapsed
    assert {r["vhost"] for r in rows} == {"admin", "dev"}


def test_creds_list_shows_the_secret_in_full(tmp_path: Path) -> None:
    # review finding: the CLI masked secrets while the GUI vault shows them — §6 says NEVER redact
    # by default (your own loot is the deliverable).
    ws = tmp_path / "ws"
    Profile.create(ws, "box", Target(ip="10.10.10.5"))
    runner.invoke(
        app,
        [
            "creds",
            "add",
            "-p",
            "box",
            "-u",
            "svc_sql",
            "-s",
            "Sup3rS3cret!",
            "--workspace",
            str(ws),
        ],
    )
    r = runner.invoke(app, ["creds", "list", "-p", "box", "--workspace", str(ws)])
    assert r.exit_code == 0
    assert "Sup3rS3cret!" in r.output
    assert "len=" not in r.output


def test_scan_hostname_is_applied_to_an_existing_profile(tmp_path: Path) -> None:
    # review finding: you learn the vhost AFTER the first scan; --hostname on a re-run was dropped.
    ws = tmp_path / "ws"
    prof = Profile.create(ws, "box", Target(ip="127.0.0.1"))
    assert not prof.target.hostname
    r = runner.invoke(
        app,
        [
            "scan",
            "127.0.0.1",
            "-p",
            "box",
            "--workspace",
            str(ws),
            "--hostname",
            "corp.htb",
            "--scan-profile",
            "quick",
        ],
    )
    assert "hostname set to corp.htb" in r.output
    assert Profile.load(ws / "box").target.hostname == "corp.htb"


def test_enum_reports_when_nothing_could_run(tmp_path: Path) -> None:
    # review finding: vhost enum with no domain built zero commands but printed "0 finding(s)",
    # which reads as "nothing is there" instead of "this never ran".
    ws = _profile_with(tmp_path)
    r = runner.invoke(app, ["enum", "vhost", "-p", "box", "--workspace", str(ws)])
    assert r.exit_code == 2
    assert "nothing to run" in r.output
    assert "--hostname" in r.output


def test_exploit_url_uses_https_for_a_tls_service(tmp_path: Path) -> None:
    # review finding: {url} was always http://, so every copied command hit the wrong scheme on an
    # HTTPS-only host. The GUI already derived the scheme from the service.
    from oscprecon.models import DiscoveredService, Proto

    ws = _profile_with(
        tmp_path, DiscoveredService(443, Proto.TCP, "ssl/http", product="nginx", state="open")
    )
    r = runner.invoke(app, ["exploit", "gitlab", "-p", "box", "--workspace", str(ws)])
    assert r.exit_code == 0
    assert "https://10.10.10.5" in r.output
    assert "http://10.10.10.5" not in r.output.replace("https://10.10.10.5", "")
