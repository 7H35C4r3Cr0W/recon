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


# --- tool-confirmed vulnerabilities (NSE vuln scripts) ---------------------------------------


def test_a_confirmed_nse_verdict_is_the_vulnerable_category() -> None:
    assert sev.classify("vuln", "smb-vuln-ms17-010", "State: VULNERABLE") == sev.VULNERABLE
    assert sev.is_notable(sev.VULNERABLE)


def test_a_negative_verdict_is_never_a_vulnerability() -> None:
    assert sev.classify("vuln", "smb-vuln-ms08-067", "State: NOT VULNERABLE") != sev.VULNERABLE


def test_an_inconclusive_check_is_information_not_a_weakness() -> None:
    # "we could not establish this" must never be framed as a confirmed vulnerability
    assert sev.classify("vuln-check", "smb-vuln-ms10-061", "no verdict reached") == sev.INFO


def test_a_version_banner_is_still_never_called_a_vulnerability() -> None:
    # the conservative rule that predates this category: only a CHECK can assert one
    assert sev.classify("product", "vsftpd 2.3.4") == sev.INFO
    assert sev.classify("edb", "EDB-17491") == sev.REFERENCE


def test_vulnerable_outranks_every_other_category() -> None:
    ranks = [sev.rank(c) for c in sev.ALL_CATEGORIES]
    assert sev.rank(sev.VULNERABLE) == min(ranks)
