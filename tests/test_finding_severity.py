from oscprecon import finding_severity as sev


def test_open_port_product_version_are_only_info() -> None:
    # the core security rule: presence facts are NEVER a weakness on their own
    for kind, value in [
        ("port", "22/tcp open"),
        ("service", "ssh"),
        ("product", "OpenSSH"),
        ("version", "8.4p1"),
        ("os", "Ubuntu"),
        ("banner", "220 vsFTPd 3.0.3"),
    ]:
        cat = sev.classify(kind, value)
        assert cat == sev.INFO
        assert not sev.is_notable(cat)


def test_generic_open_ssh_is_not_notable() -> None:
    cat = sev.classify("service", "ssh", "OpenSSH 8.4p1 Ubuntu")
    assert cat == sev.INFO
    assert not sev.is_notable(cat)


def test_exploitdb_hit_is_a_reference_not_a_vuln() -> None:
    for kind in ("edb", "searchsploit", "exploit", "reference"):
        cat = sev.classify(kind, "EDB-12345 OpenSSH 8.4 user enum")
        assert cat == sev.REFERENCE
        assert not sev.is_notable(cat)  # a reference is never a confirmed weakness


def test_anonymous_login_is_access_misconfig() -> None:
    cat = sev.classify("auth", "anonymous", "ftp anonymous login allowed")
    assert cat == sev.ACCESS
    assert sev.is_notable(cat)


def test_null_session_is_exposure() -> None:
    cat = sev.classify("access", "null session")
    assert cat == sev.EXPOSURE
    assert sev.is_notable(cat)
    # a share *name* stays info even if its detail mentions access — the exposure is a separate
    # finding kind, so a name never self-escalates
    assert sev.classify("share", "IT", "world-readable via null session") == sev.INFO


def test_smb_signing_disabled_is_relay_risk_but_enabled_is_info() -> None:
    disabled = sev.classify("signing", "disabled")
    enabled = sev.classify("signing", "required")
    assert disabled == sev.RELAY_RISK and sev.is_notable(disabled)
    assert enabled == sev.INFO and not sev.is_notable(enabled)


def test_world_readable_and_writable_are_exposure() -> None:
    assert sev.classify("world-readable", "SYSVOL") == sev.EXPOSURE
    assert sev.classify("nfs", "export", "no_root_squash") == sev.EXPOSURE


def test_username_and_share_name_are_info() -> None:
    assert sev.classify("user", "administrator") == sev.INFO
    assert sev.classify("share", "IT") == sev.INFO


def test_guest_writable_share_is_exposure_but_readable_is_info() -> None:
    # a guest/anon-WRITABLE share is a real exposure (upload / print-job / wide-link write vector),
    # while a merely readable or bare share stays info (HTB Abducted: guest-writable HP-Reception).
    writable = sev.classify("share", "HP-Reception", "WRITE")
    assert writable == sev.EXPOSURE and sev.is_notable(writable)
    assert sev.classify("share", "IT", "READ") == sev.INFO
    assert sev.classify("share", "projects", "") == sev.INFO
