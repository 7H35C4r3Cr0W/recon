from pathlib import Path

from oscprecon.modules.ldap.parsers import (
    parse_ldap_tool,
    parse_ldapsearch_entries,
    parse_ldapsearch_rootdse,
    parse_nmap_ldap,
)

FIX = Path(__file__).parent / "fixtures" / "ldap"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_parse_rootdse_naming_contexts() -> None:
    findings = parse_ldapsearch_rootdse(_read("rootdse.txt"))
    contexts = [f.value for f in findings if f.kind == "naming-context"]
    assert "DC=example,DC=htb" in contexts
    assert "CN=Configuration,DC=example,DC=htb" in contexts
    assert "CN=Schema,CN=Configuration,DC=example,DC=htb" in contexts
    # defaultNamingContext duplicates DC=example,DC=htb — it must appear once, not twice
    assert contexts.count("DC=example,DC=htb") == 1


def test_parse_rootdse_info_and_bind() -> None:
    findings = parse_ldapsearch_rootdse(_read("rootdse.txt"))
    info = {f.value for f in findings if f.kind == "info"}
    assert "dnsHostName: dc01.example.htb" in info
    assert "domainFunctionality: 7" in info
    # defaultNamingContext is surfaced only as a naming-context, never duplicated into info
    assert not any(v.startswith("defaultNamingContext") for v in info)
    assert any(f.kind == "bind" and f.value == "anonymous" for f in findings)


def test_rootdse_no_bind_when_empty() -> None:
    # no naming contexts came back (anonymous bind refused) -> no bind finding
    assert parse_ldapsearch_rootdse("dn:\nresult: 1 Operations error\n") == []


def test_parse_users() -> None:
    findings = parse_ldapsearch_entries(_read("users.txt"))
    users = [f.value for f in findings if f.kind == "user"]
    assert users == ["Administrator", "Guest", "jsmith", "svc_backup"]
    # a base64 cn (cn:: ...) must not corrupt the plain sAMAccountName extraction
    assert "c3ZjX2JhY2t1cA==" not in users


def test_parse_nmap_ldap() -> None:
    findings = parse_nmap_ldap(_read("nmap-ldap.txt"))
    contexts = [f.value for f in findings if f.kind == "naming-context"]
    assert "DC=example,DC=htb" in contexts
    assert contexts.count("DC=example,DC=htb") == 1  # deduped within the nmap block
    assert any(f.value == "dnsHostName: dc01.example.htb" for f in findings)


def test_ldif_line_folding() -> None:
    # a value folded across a continuation line (leading space) is rejoined before reading
    folded = "namingContexts: DC=very-long-example,\n DC=htb\ndefaultNamingContext: DC=x\n"
    contexts = [f.value for f in parse_ldapsearch_rootdse(folded) if f.kind == "naming-context"]
    assert "DC=very-long-example,DC=htb" in contexts


def test_dispatch_and_garbage() -> None:
    assert parse_ldap_tool("unknown", "x") == []
    assert parse_ldap_tool("ldapsearch-rootdse", _read("rootdse.txt"))
    assert parse_ldapsearch_entries("dn:\nno sam account here\n") == []
