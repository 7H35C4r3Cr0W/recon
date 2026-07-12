from pathlib import Path

from oscprecon import findings as findings_mod
from oscprecon import vault_export
from oscprecon.models import Credential, DiscoveredService, Proto, Target
from oscprecon.profile import Profile


def _seeded_profile(tmp_path: Path) -> Profile:
    prof = Profile.create(
        tmp_path / "ws", "htb-active", Target(ip="10.10.10.100", hostname="active.htb")
    )
    prof.set_services(
        [
            DiscoveredService(port=445, proto=Proto.TCP, service="microsoft-ds", discovered_at=""),
            DiscoveredService(port=88, proto=Proto.TCP, service="kerberos-sec", discovered_at=""),
        ]
    )
    prof.add_command(
        {"id": "cmd-001", "module": "nmap", "shell_line": "nmap -p- 10.10.10.100", "exit_code": 0}
    )
    findings_mod.add_findings(
        prof.directory,
        [{"module": "smb", "kind": "share", "value": "SYSVOL", "detail": "READ"}],
    )
    prof.add_credential(
        Credential(username="svc_sql", secret="Ticketmaster1968", domain="active.htb", source="smb")
    )
    prof.notes_path.write_text("# active\n\nfound GPP creds in SYSVOL\n", encoding="utf-8")
    return prof


def test_export_creates_full_structure(tmp_path: Path) -> None:
    prof = _seeded_profile(tmp_path)
    out = vault_export.export_vault(prof, tmp_path / "vault")

    assert out == tmp_path / "vault" / "htb-active"
    assert (out / "index.md").exists()
    assert (out / "target" / "10-10-10-100.md").exists()
    assert (out / "services" / "445-tcp-microsoft-ds.md").exists()
    assert (out / "services" / "88-tcp-kerberos-sec.md").exists()
    assert len(list((out / "findings").glob("*.md"))) == 1
    assert len(list((out / "credentials").glob("*.md"))) == 1
    assert len(list((out / "commands").glob("*.md"))) == 1
    assert len(list((out / "notes").glob("*.md"))) == 1


def test_export_redacts_credential_secret(tmp_path: Path) -> None:
    prof = _seeded_profile(tmp_path)
    out = vault_export.export_vault(prof, tmp_path / "vault")
    cred_md = next((out / "credentials").glob("*.md")).read_text(encoding="utf-8")
    assert "Ticketmaster1968" not in cred_md  # the plaintext secret never leaves the profile
    assert "<redacted len=16>" in cred_md
    assert "svc_sql" in cred_md


def test_export_links_service_to_target_and_hacktricks(tmp_path: Path) -> None:
    prof = _seeded_profile(tmp_path)
    out = vault_export.export_vault(prof, tmp_path / "vault")
    smb = (out / "services" / "445-tcp-microsoft-ds.md").read_text(encoding="utf-8")
    assert "[[10.10.10.100]]" in smb  # wikilink back to the target note
    assert "book.hacktricks.wiki" in smb
    index = (out / "index.md").read_text(encoding="utf-8")
    assert "[[445-tcp-microsoft-ds]]" in index  # index links to the service note
    assert "Snapshot export" in index


def test_export_notes_carry_user_content(tmp_path: Path) -> None:
    prof = _seeded_profile(tmp_path)
    out = vault_export.export_vault(prof, tmp_path / "vault")
    note_md = next((out / "notes").glob("*.md")).read_text(encoding="utf-8")
    assert "found GPP creds in SYSVOL" in note_md
