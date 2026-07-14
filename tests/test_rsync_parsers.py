from oscprecon.models import Target
from oscprecon.modules.rsync import RsyncModule, parse_rsync_modules, parse_rsync_tool

_LIST = """@RSYNCD: 31.0
data            \tData directory
backup          \tBackups
files
@RSYNCD: EXIT
"""

_NMAP = "873/tcp open rsync\n| rsync-list-modules:\n|   data\n|_  backup\n"


def test_parses_modules_and_flags_unauth() -> None:
    values = {(f.kind, f.value) for f in parse_rsync_modules(_LIST)}
    assert ("access", "unauth") in values
    assert ("module", "data") in values
    assert ("module", "backup") in values
    assert ("module", "files") in values


def test_protocol_and_error_lines_skipped() -> None:
    names = {f.value for f in parse_rsync_modules(_LIST) if f.kind == "module"}
    assert "@RSYNCD" not in names and "EXIT" not in names


def test_nmap_nse_module_list_parses() -> None:
    names = {f.value for f in parse_rsync_modules(_NMAP) if f.kind == "module"}
    assert names == {"data", "backup"}


def test_module_dedupes_across_both_steps() -> None:
    module = RsyncModule()
    found = module.parse({"rsync-modules": _LIST, "rsync-nmap": _NMAP})
    mods = [f.fields["value"] for f in found if f.fields["kind"] == "module"]
    access = [f for f in found if f.fields["kind"] == "access"]
    assert sorted(mods) == ["backup", "data", "files"]  # data/backup not doubled
    assert len(access) == 1  # single access finding across both steps


def test_recon_steps_use_rsync_and_nmap() -> None:
    steps = RsyncModule().recon_steps(Target(ip="10.10.10.21"))
    lines = " ".join(s.command.shell_line for s in steps)
    assert "rsync://10.10.10.21" in lines
    assert "rsync-list-modules" in lines


def test_missing_sentinel_skipped() -> None:
    assert parse_rsync_modules("[missing] rsync — install with: apt install rsync\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_rsync_tool("nope", _LIST) == []
