from pathlib import Path

from oscprecon.modules.kerberos.parsers import (
    parse_getadusers,
    parse_getnpusers,
    parse_getuserspns,
    parse_nmap_kerberos,
)

FIX = Path(__file__).parent / "fixtures" / "kerberos"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_parse_nmap_confirms_kdc_and_server_time() -> None:
    findings = parse_nmap_kerberos(_read("nmap-sv.txt"))
    by_kind = {f.kind: f for f in findings}
    assert by_kind["service"].value == "kerberos-sec"
    assert "Microsoft Windows Kerberos" in by_kind["service"].detail
    assert by_kind["server-time"].value == "2024-06-01 12:34:56Z"


def test_parse_getnpusers_extracts_principals_never_hashes() -> None:
    findings = parse_getnpusers(_read("getnpusers.txt"))
    principals = {f.value for f in findings}
    assert principals == {"svc-alfresco@HTB.LOCAL", "backup-svc@HTB.LOCAL"}
    assert all(f.kind == "user-no-preauth" for f in findings)
    # CRITICAL (§2): the AS-REP hash blob must NEVER be captured into a finding
    blob = " ".join(f"{f.value} {f.detail}" for f in findings)
    assert "FAKEHASHBLOB" not in blob and "$krb5asrep$" not in blob
    # accounts WITH pre-auth set are not roastable and must not be listed
    assert "administrator" not in {p.lower() for p in principals}


def test_parse_getuserspns_lists_spns_and_accounts() -> None:
    findings = parse_getuserspns(_read("getuserspns.txt"))
    spns = {f.value: f.detail for f in findings}
    assert "CIFS/dc.htb.local" in spns and "HTTP/web.htb.local" in spns
    assert "sql_svc" in spns["CIFS/dc.htb.local"]
    assert all(f.kind == "spn" for f in findings)
    assert "ServicePrincipalName" not in spns  # header row is not a finding


def test_parse_getadusers_lists_usernames() -> None:
    findings = parse_getadusers(_read("getadusers.txt"))
    names = {f.value for f in findings}
    assert {"Administrator", "Guest", "svc-alfresco", "backup-svc"} <= names
    assert all(f.kind == "user" for f in findings)
    assert "Name" not in names and "Impacket" not in names  # header/banner excluded
