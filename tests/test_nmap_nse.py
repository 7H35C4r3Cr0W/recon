from pathlib import Path

from oscprecon.nmap_nse import list_scripts


def test_list_scripts_is_sorted_and_filters_brute() -> None:
    scripts = list_scripts()
    assert scripts == tuple(sorted(scripts))
    # oracle-sid-brute is the ONE allowed recon-brute (enumerates SIDs, not passwords)
    assert "oracle-sid-brute" in scripts
    # every other 'brute' script is filtered out (the shell policy blocks them at run time anyway)
    assert not any("brute" in s and s != "oracle-sid-brute" for s in scripts)
    # the common --script <category> selectors are always offered ('brute' category never is)
    for category in ("default", "discovery", "safe", "version", "vuln"):
        assert category in scripts
    assert "brute" not in scripts


def test_list_scripts_falls_back_when_dir_absent(tmp_path: Path) -> None:
    scripts = list_scripts(tmp_path / "does-not-exist")
    # curated offline fallback covers the OSCP staples across services
    for name in ("http-title", "smb-os-discovery", "ssh-hostkey", "ftp-anon", "ssl-enum-ciphers"):
        assert name in scripts
    assert not any("brute" in s and s != "oracle-sid-brute" for s in scripts)
