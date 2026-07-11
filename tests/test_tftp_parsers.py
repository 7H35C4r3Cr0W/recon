from pathlib import Path

from oscprecon.modules.tftp.parsers import parse_nmap_tftp, parse_tftp_tool

FIX = Path(__file__).parent / "fixtures" / "tftp"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_parse_nmap_tftp_files() -> None:
    files = {f.value for f in parse_nmap_tftp(_read("nmap-tftp.txt")) if f.kind == "file"}
    assert files == {"running-config", "startup-config"}


def test_section_ends_at_next_top_level_line() -> None:
    # a filename-looking token AFTER the script block (e.g. in Service Info) must not be captured
    text = "| tftp-enum:\n|_  bootrom.ld\nService Info: running-config\nNmap done: 1 IP address\n"
    files = {f.value for f in parse_nmap_tftp(text) if f.kind == "file"}
    assert files == {"bootrom.ld"}


def test_inline_filename_on_header() -> None:
    files = {f.value for f in parse_nmap_tftp("| tftp-enum: nvram.bin\n") if f.kind == "file"}
    assert files == {"nvram.bin"}


def test_status_prefixed_filenames_are_kept() -> None:
    # every in-section line is a reported filename — a name starting with info/error/date/started
    # (realistic via a custom tftp-enum.filelist or a device) must NOT be dropped
    text = "| tftp-enum:\n|   info.txt\n|   error.log\n|   date\n|_  startup-config\n"
    files = {f.value for f in parse_nmap_tftp(text) if f.kind == "file"}
    assert files == {"info.txt", "error.log", "date", "startup-config"}


def test_dispatch_and_garbage() -> None:
    assert parse_tftp_tool("unknown", "x") == []
    assert parse_tftp_tool("nmap-tftp", _read("nmap-tftp.txt"))
    assert parse_nmap_tftp("69/udp open tftp\nno script output here\n") == []
