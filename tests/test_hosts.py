from pathlib import Path

import pytest
from typer.testing import CliRunner

from oscprecon import hosts
from oscprecon.cli import app


def test_add_entry_appends_a_new_line(tmp_path: Path) -> None:
    hf = tmp_path / "hosts"
    hf.write_text("127.0.0.1\tlocalhost\n")
    result = hosts.add_entry("10.10.10.5", ["research.bedside.htb"], hf)
    assert result.changed
    assert result.added == ("research.bedside.htb",)
    text = hf.read_text()
    assert "127.0.0.1\tlocalhost" in text  # existing lines untouched
    assert "10.10.10.5\tresearch.bedside.htb" in text


def test_add_entry_merges_into_an_existing_ip_line(tmp_path: Path) -> None:
    hf = tmp_path / "hosts"
    hf.write_text("10.10.10.5\tbedside.htb\n")
    result = hosts.add_entry("10.10.10.5", ["research.bedside.htb", "bedside.htb"], hf)
    assert result.changed
    assert result.added == ("research.bedside.htb",)  # only the genuinely-new name
    line = hf.read_text().strip()
    # both names on the one line for that IP, no duplicate of bedside.htb
    assert line == "10.10.10.5\tbedside.htb research.bedside.htb"


def test_add_entry_is_idempotent(tmp_path: Path) -> None:
    hf = tmp_path / "hosts"
    hf.write_text("10.10.10.5\tresearch.bedside.htb\n")
    result = hosts.add_entry("10.10.10.5", ["research.bedside.htb"], hf)
    assert not result.changed
    assert "unchanged" in result.message


def test_add_entry_creates_the_file_when_absent(tmp_path: Path) -> None:
    hf = tmp_path / "hosts"  # does not exist yet
    hosts.add_entry("10.10.10.9", ["a.htb"], hf)
    assert hf.read_text() == "10.10.10.9\ta.htb\n"


def test_add_entry_flags_a_name_mapped_to_another_ip(tmp_path: Path) -> None:
    hf = tmp_path / "hosts"
    hf.write_text("10.10.10.1\tdup.htb\n")
    result = hosts.add_entry("10.10.10.5", ["dup.htb"], hf)
    assert result.changed  # still added to the new IP
    assert "already maps to another IP" in result.message


def test_add_entry_rejects_empty_input(tmp_path: Path) -> None:
    hf = tmp_path / "hosts"
    with pytest.raises(ValueError):
        hosts.add_entry("", ["x.htb"], hf)
    with pytest.raises(ValueError):
        hosts.add_entry("10.0.0.1", ["   "], hf)


def test_sudo_command_and_line_format() -> None:
    assert hosts.hosts_line("10.10.10.5", ["a.htb", "b.htb"]) == "10.10.10.5\ta.htb b.htb"
    assert (
        hosts.sudo_append_command("10.10.10.5", ["a.htb"])
        == "echo '10.10.10.5 a.htb' | sudo tee -a /etc/hosts"
    )


def test_cli_hosts_add(tmp_path: Path) -> None:
    hf = tmp_path / "hosts"
    hf.write_text("127.0.0.1\tlocalhost\n")
    res = CliRunner().invoke(
        app, ["hosts", "10.10.10.5", "research.bedside.htb", "--file", str(hf)]
    )
    assert res.exit_code == 0, res.output
    assert "Added" in res.output
    assert "10.10.10.5\tresearch.bedside.htb" in hf.read_text()


def test_cli_hosts_falls_back_to_sudo_when_unwritable(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    hf = tmp_path / "hosts"
    hf.write_text("127.0.0.1\tlocalhost\n")

    def _boom(*_a: object, **_k: object) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr(hosts, "add_entry", _boom)
    res = CliRunner().invoke(app, ["hosts", "10.10.10.5", "x.htb", "--file", str(hf)])
    assert res.exit_code == 1
    assert "sudo tee -a /etc/hosts" in res.output
