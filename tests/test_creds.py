from pathlib import Path

import pytest

from oscprecon import creds
from oscprecon.models import Credential, Target
from oscprecon.profile import Profile


@pytest.fixture(autouse=True)
def _redaction_on(monkeypatch: pytest.MonkeyPatch) -> None:
    # These tests exercise the secret-MASKING capability. The shipping default is
    # shell.REDACT_SECRETS=False (owner policy 2026-07-22: never redact loot), so enable it
    # here to verify the masking logic still works when a build opts in.
    from oscprecon import shell

    monkeypatch.setattr(shell, "REDACT_SECRETS", True)


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


def test_save_forces_0600_and_leaves_no_secret_bearing_temp(tmp_path: Path) -> None:
    # save_creds writes a per-writer UNIQUE temp (mkstemp, 0600) then os.replace — so concurrent
    # writers never share a temp. The final file is 0600 and no leftover temp holds the secret.
    import os

    path = tmp_path / "creds.json"
    stale = tmp_path / "creds.json.tmp"
    stale.write_text("stale", encoding="utf-8")
    os.chmod(stale, 0o666)  # an unrelated leftover from an older fixed-name temp
    creds.save_creds(path, [Credential(username="u", secret="s")])
    assert _mode(path) == "0o600"
    # the unique temp was atomically moved into place — no creds.json.* temp lingers with the secret
    leftover = [p for p in tmp_path.glob("creds.json.*") if p.name.endswith(".tmp") and p != stale]
    assert not leftover


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


def test_manual_credentials_survive_reload_and_project_switch(tmp_path: Path) -> None:
    # "restart" / "switch project" == reopen the profile folder from disk. Manual creds must stay.
    a = Profile.create(tmp_path / "A", "a", Target(ip="10.0.0.1"))
    b = Profile.create(tmp_path / "B", "b", Target(ip="10.0.0.2"))
    a.add_credential(Credential(username="alice", secret="secretA", source="manual"))
    b.add_credential(Credential(username="bob", secret="secretB", source="manual"))
    # reopen both (fresh Profile objects reading the same dirs)
    a2 = Profile.load(a.directory)
    b2 = Profile.load(b.directory)
    assert [c.username for c in a2.credentials()] == ["alice"]
    assert [c.username for c in b2.credentials()] == ["bob"]  # isolated per project, no leak


def test_confirmation_records_add_only_and_never_removes(tmp_path: Path) -> None:
    # a confirmed spray appends to tested_against via set_credentials — the secret and the entry
    # itself must be preserved (a successful auth never removes a credential).
    prof = Profile.create(tmp_path, "c", Target(ip="10.0.0.1"))
    prof.add_credential(Credential(username="administrator", secret="Winter2024", source="manual"))
    prof.add_credential(Credential(username="svc", secret="Summer2024", source="manual"))
    creds_list = prof.credentials()
    creds_list[0].tested_against.append("spray-confirmed:smb")
    prof.set_credentials(creds_list)
    reloaded = prof.credentials()
    assert len(reloaded) == 2  # nothing removed
    admin = next(c for c in reloaded if c.username == "administrator")
    assert admin.secret == "Winter2024" and "spray-confirmed:smb" in admin.tested_against
    assert _mode(prof.creds_path) == "0o600"  # still restrictive after the update


def test_failed_save_preserves_the_previous_store(tmp_path, monkeypatch) -> None:
    path = tmp_path / "creds.json"
    creds.save_creds(path, [Credential(username="keep", secret="me")])

    def boom(fd: int, data: bytes) -> int:
        raise OSError("disk full")

    monkeypatch.setattr(creds.os, "write", boom)
    try:
        creds.save_creds(path, [Credential(username="new", secret="x")])
        raise AssertionError("expected OSError")
    except OSError:
        pass
    monkeypatch.undo()
    survivors = creds.load_creds(path)
    assert [c.username for c in survivors] == ["keep"]  # prior valid store intact
    assert not (tmp_path / "creds.json.tmp").exists()  # partial temp cleaned up
