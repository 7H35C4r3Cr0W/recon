from pathlib import Path

from oscprecon import creds
from oscprecon.models import Credential, Target
from oscprecon.profile import Profile


def _mode(path: Path) -> str:
    return oct(path.stat().st_mode & 0o777)


def test_roundtrip_and_file_mode(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    cred = Credential(
        username="svc", secret="Sup3rSecret", domain="active.htb", source="smb-share-readme.txt"
    )
    creds.save_creds(path, [cred])
    assert _mode(path) == "0o600"
    loaded = creds.load_creds(path)
    assert len(loaded) == 1
    assert loaded[0].username == "svc"
    assert loaded[0].secret == "Sup3rSecret"
    assert loaded[0].domain == "active.htb"


def test_add_credential_dedups(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    cred = Credential(username="svc", secret="p", source="smb-anon-enum")
    creds.add_credential(path, cred)
    creds.add_credential(path, cred)
    assert len(creds.load_creds(path)) == 1
    creds.add_credential(path, Credential(username="svc", secret="p", source="ldap-anon-enum"))
    assert len(creds.load_creds(path)) == 2  # different source is a distinct entry


def test_redact_reveals_only_length() -> None:
    assert creds.redact("hunter2") == "<redacted len=7>"
    assert "hunter2" not in creds.redact("hunter2")


def test_load_missing_or_garbage(tmp_path: Path) -> None:
    assert creds.load_creds(tmp_path / "nope.json") == []
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    assert creds.load_creds(bad) == []


def test_profile_credentials_and_references(tmp_path: Path) -> None:
    prof = Profile.create(tmp_path, "htb-active", Target(ip="10.10.10.100"))
    prof.add_credential(Credential(username="svc", secret="x", source="smb-anon-enum"))
    assert _mode(prof.creds_path) == "0o600"
    assert prof.credentials()[0].username == "svc"

    url = "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smb/index.html"
    prof.add_reference_visited("smb", url)
    prof.add_reference_visited("smb", url)  # dedup by url
    prof.save()

    reloaded = Profile.load(prof.directory)
    assert len(reloaded.references_visited) == 1
    assert reloaded.references_visited[0]["service"] == "smb"
    assert reloaded.references_visited[0]["url"] == url


def test_save_forces_0600_even_with_stale_tmp(tmp_path: Path) -> None:
    import os

    path = tmp_path / "creds.json"
    stale = tmp_path / "creds.json.tmp"
    stale.write_text("stale", encoding="utf-8")
    os.chmod(stale, 0o666)  # simulate a leftover world-readable temp
    creds.save_creds(path, [Credential(username="u", secret="s")])
    assert _mode(path) == "0o600"
    assert not stale.exists()  # temp was atomically moved into place


def test_delete_credential_removes_the_matching_entry(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    keep = Credential(username="keep", secret="1")
    drop = Credential(username="drop", secret="2")
    creds.add_credential(path, keep)
    creds.add_credential(path, drop)
    remaining = creds.delete_credential(path, drop)
    assert [c.username for c in remaining] == ["keep"]
    assert [c.username for c in creds.load_creds(path)] == ["keep"]  # persisted


def test_profile_delete_credential_and_read_only_guard(tmp_path: Path) -> None:
    from oscprecon.profile import ReadOnlyError

    prof = Profile.create(tmp_path, "b", Target(ip="10.0.0.1"))
    cred = Credential(username="a", secret="1")
    prof.add_credential(cred)
    prof.delete_credential(cred)
    assert prof.credentials() == []
    prof.add_credential(cred)
    prof.read_only = True
    try:
        prof.delete_credential(cred)
        raise AssertionError("expected ReadOnlyError")
    except ReadOnlyError:
        pass
