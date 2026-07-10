from pathlib import Path

from oscprecon import wordlists


def _make_tree(root: Path) -> None:
    (root / "Discovery" / "Web-Content").mkdir(parents=True)
    (root / "Discovery" / "DNS").mkdir(parents=True)
    (root / "Passwords" / "Common").mkdir(parents=True)
    (root / "Default-Passwords").mkdir(parents=True)
    (root / "Usernames").mkdir(parents=True)
    (root / "Discovery" / "Web-Content" / "common.txt").write_text("admin\nlogin\nindex\n")
    (root / "Discovery" / "DNS" / "subdomains.txt").write_text("www\nmail\n")
    (root / "Usernames" / "names.txt").write_text("root\nadmin\n")
    (root / "Passwords" / "Common" / "top.txt").write_text("123456\npassword\n")
    (root / "Default-Passwords" / "creds.txt").write_text(
        "admin:admin\n"
    )  # dir contains 'password'
    (root / "Discovery" / "Web-Content" / "sql-passwords.txt").write_text(
        "sa\n"
    )  # name has 'password'
    (root / "rockyou.txt").write_text("secret\n")
    (root / "binary.bin").write_bytes(b"\x00\x01\x02")


def test_indexes_text_and_filters_passwords(tmp_path: Path) -> None:
    _make_tree(tmp_path)
    names = {w.name for w in wordlists.index_wordlists([tmp_path])}
    assert {"common.txt", "subdomains.txt", "names.txt"} <= names
    assert "top.txt" not in names  # under Passwords/
    assert "creds.txt" not in names  # under Default-Passwords/ (dir contains 'password')
    assert "sql-passwords.txt" not in names  # filename contains 'password'
    assert "rockyou.txt" not in names  # excluded by name
    assert "binary.bin" not in names  # non-text suffix


def test_categories_inferred_from_path(tmp_path: Path) -> None:
    _make_tree(tmp_path)
    by_name = {w.name: w for w in wordlists.index_wordlists([tmp_path])}
    assert by_name["common.txt"].category == "web-content"
    assert by_name["subdomains.txt"].category == "dns"
    assert by_name["names.txt"].category == "usernames"


def test_line_and_size_counts(tmp_path: Path) -> None:
    _make_tree(tmp_path)
    by_name = {w.name: w for w in wordlists.index_wordlists([tmp_path])}
    assert by_name["common.txt"].line_count == 3
    assert by_name["common.txt"].size_bytes > 0


def test_missing_paths_are_skipped(tmp_path: Path) -> None:
    assert wordlists.index_wordlists([tmp_path / "does-not-exist"]) == []


def test_favorites_roundtrip() -> None:
    # the autouse config-isolation fixture points XDG_CONFIG_HOME at a tmp dir
    target = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    assert wordlists.favorites() == []
    wordlists.add_favorite(target)
    assert wordlists.is_favorite(target)
    wordlists.add_favorite(target)  # idempotent, no duplicate
    assert wordlists.favorites().count(target) == 1
    wordlists.remove_favorite(target)
    assert not wordlists.is_favorite(target)
