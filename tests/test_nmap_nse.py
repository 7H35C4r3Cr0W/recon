from pathlib import Path

from oscprecon.nmap_nse import list_scripts


def test_list_scripts_is_sorted_and_filters_brute() -> None:
    scripts = list_scripts()
    assert scripts == tuple(sorted(scripts))
    # the recon-brutes enumerate IDENTIFIERS, not passwords: SIDs and subdomains (§10)
    assert "oracle-sid-brute" in scripts and "dns-brute" in scripts
    # every password-iterating script is filtered out. Category SELECTORS are expressions and may
    # legitimately contain the word inside an exclusion — judge only the bare script names.
    names = [s for s in scripts if " " not in s]
    assert not any("brute" in n and n not in ("oracle-sid-brute", "dns-brute") for n in names)
    # the category selectors are offered in the form that actually passes the §2 gate
    assert "default" in scripts and "version" in scripts
    assert any(s.startswith("vuln and") for s in scripts)
    assert any(s.startswith("safe and") for s in scripts)
    assert any(s.startswith("discovery and") for s in scripts)
    assert "brute" not in scripts


def test_list_scripts_falls_back_when_dir_absent(tmp_path: Path) -> None:
    scripts = list_scripts(tmp_path / "does-not-exist")
    # curated offline fallback covers the OSCP staples across services
    for name in ("http-title", "smb-os-discovery", "ssh-hostkey", "ftp-anon", "ssl-enum-ciphers"):
        assert name in scripts
    names = [s for s in scripts if " " not in s]
    assert not any("brute" in n and n not in ("oracle-sid-brute", "dns-brute") for n in names)
