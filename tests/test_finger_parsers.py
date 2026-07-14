from pathlib import Path

from oscprecon.models import Target
from oscprecon.modules.finger import FingerModule, parse_finger_tool, parse_finger_users

_FIX = Path(__file__).parent / "fixtures" / "finger" / "finger-at.txt"


def _query() -> str:
    return _FIX.read_text(encoding="utf-8")


def test_parses_usernames_and_skips_header() -> None:
    users = {f.value for f in parse_finger_users(_query())}
    assert users == {"root", "sunny", "admin"}  # header row "Login ..." excluded


def test_nmap_nse_prefixed_table_parses() -> None:
    text = (
        "79/tcp open finger\n| finger:\n"
        "|   Login  Name  Tty\n|   root   root  *:0\n|_  bob    Bob   pts/0\n"
    )
    users = {f.value for f in parse_finger_users(text)}
    assert "root" in users and "bob" in users


def test_no_one_logged_on_yields_no_users() -> None:
    assert parse_finger_users("No one logged on\n") == []


def test_module_dedupes_users_across_both_steps() -> None:
    module = FingerModule()
    raw = {
        "finger-query": _query(),
        "finger-nse": "| finger:\n|   Login Name Tty\n|   root root *:0\n|_  sunny s pts/0\n",
    }
    users = [f.fields["value"] for f in module.parse(raw) if f.fields["kind"] == "user"]
    assert sorted(users) == ["admin", "root", "sunny"]  # root/sunny not doubled


def test_suggest_builds_user_list() -> None:
    module = FingerModule()
    found = module.parse({"finger-query": _query()})
    tips = module.suggest(found)
    assert tips and "username" in tips[0].lower()


def test_recon_steps_use_finger_and_nmap() -> None:
    steps = FingerModule().recon_steps(Target(ip="10.10.10.7"))
    lines = [s.command.shell_line for s in steps]
    assert "finger @10.10.10.7" in lines
    assert any("--script finger" in line for line in lines)


def test_missing_sentinel_skipped() -> None:
    assert parse_finger_users("[missing] finger — install with: apt install finger\n") == []


def test_tool_dispatch_unknown_returns_empty() -> None:
    assert parse_finger_tool("nope", _query()) == []
