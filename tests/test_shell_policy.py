from pathlib import Path

from oscprecon import shell


def test_allows_recon_commands() -> None:
    assert shell.policy_violation(["nmap", "--top-ports", "1000", "10.10.10.5"]) is None
    assert shell.policy_violation(["nmap", "--script", "smb-os-discovery", "10.10.10.5"]) is None
    # RID cycling is recon (CLAUDE.md §11), not brute force — allowed despite the word "brute".
    assert (
        shell.policy_violation(
            ["netexec", "smb", "10.10.10.5", "-u", "", "-p", "", "--rid-brute", "10000"]
        )
        is None
    )


def test_blocks_forbidden_tools_and_flags() -> None:
    assert shell.policy_violation(["hydra", "-l", "a", "-P", "list", "10.10.10.5"]) is not None
    assert shell.policy_violation(["sqlmap", "-u", "http://x"]) is not None
    assert shell.policy_violation(["nmap", "--script", "ssh-brute", "10.10.10.5"]) is not None
    assert shell.policy_violation(["nmap", "--script=http-wordpress-brute", "x"]) is not None
    assert shell.policy_violation(["wpscan", "--url", "http://x", "--passwords", "l"]) is not None
    assert shell.policy_violation(["netexec", "smb", "x", "--continue-on-success"]) is not None


def test_run_refuses_forbidden_without_executing(tmp_path: Path) -> None:
    out = tmp_path / "o.txt"
    result = shell.run("hydra -l a -P list 10.10.10.5", out)
    assert result.blocked is not None
    assert result.exit_code == 126
    assert "[blocked]" in out.read_text(encoding="utf-8")


def test_blocks_searchsploit_non_display_flags() -> None:
    assert shell.policy_violation(["searchsploit", "--json", "-m", "47080"]) is not None
    assert shell.policy_violation(["searchsploit", "--json", "-u"]) is not None
    assert shell.policy_violation(["searchsploit", "--json", "-x", "47080"]) is not None
    # a plain display lookup is allowed
    assert shell.policy_violation(["searchsploit", "--json", "nginx", "1.18"]) is None


def test_blocks_wpscan_credential_brute() -> None:
    assert shell.policy_violation(["wpscan", "--url", "http://x/", "-P", "rockyou.txt"]) is not None
    assert shell.policy_violation(["wpscan", "--url", "http://x/", "--passwords", "l"]) is not None
    assert shell.policy_violation(["wpscan", "--url", "http://x/", "-U", "admin"]) is not None
    # enumeration is allowed
    assert shell.policy_violation(["wpscan", "--url", "http://x/", "--enumerate", "u"]) is None


def test_allows_ad_recon_pattern_commands() -> None:
    # the AD pattern-library suggestions (netexec null/single-cred enum, enum4linux) must run
    assert shell.policy_violation(["enum4linux", "-a", "10.0.0.1"]) is None
    assert (
        shell.policy_violation(["netexec", "smb", "10.0.0.1", "-u", "", "-p", "", "--groups"])
        is None
    )
    assert (
        shell.policy_violation(["netexec", "ldap", "10.0.0.1", "-u", "", "-p", "", "--get-sid"])
        is None
    )
    assert (
        shell.policy_violation(
            ["netexec", "ldap", "10.0.0.1", "-u", "u", "-p", "p", "--kerberoasting", "k.out"]
        )
        is None
    )


def test_blocks_ike_scan_pskcrack() -> None:
    # -P/--pskcrack writes the aggressive-mode PSK hash to disk for offline cracking (§12) — blocked
    assert shell.policy_violation(["ike-scan", "-A", "--pskcrack", "10.0.0.1"]) is not None
    assert shell.policy_violation(["ike-scan", "-A", "--pskcrack=out.txt", "10.0.0.1"]) is not None
    assert shell.policy_violation(["ike-scan", "-Pout.txt", "10.0.0.1"]) is not None  # -Pfile form
    # plain detection / aggressive-mode check are allowed
    assert shell.policy_violation(["ike-scan", "-M", "10.0.0.1"]) is None
    assert shell.policy_violation(["ike-scan", "-M", "-A", "10.0.0.1"]) is None


def test_blocks_ntpdate_without_q() -> None:
    # ntpdate WITHOUT -q sets the local clock (modifies state) -> blocked; -q query mode is allowed
    assert shell.policy_violation(["ntpdate", "10.0.0.1"]) is not None
    assert shell.policy_violation(["ntpdate", "-b", "-u", "10.0.0.1"]) is not None
    assert shell.policy_violation(["ntpdate", "-q", "10.0.0.1"]) is None
    assert shell.policy_violation(["ntpdate", "-q", "-u", "10.0.0.1"]) is None


def test_blocks_netexec_list_auth(tmp_path: object) -> None:
    from pathlib import Path

    wordlist = Path(str(tmp_path)) / "users.txt"
    wordlist.write_text("admin\nroot\n", encoding="utf-8")
    # a -u/-p value that is a FILE = a list = Tier-3 spray -> blocked
    assert shell.policy_violation(["netexec", "smb", "10.0.0.1", "-u", str(wordlist)]) is not None
    assert shell.policy_violation(["netexec", "smb", "10.0.0.1", "-p", str(wordlist)]) is not None
    # single literal creds (Tier-1/2) are allowed
    assert (
        shell.policy_violation(["netexec", "smb", "10.0.0.1", "-u", "administrator", "-p", ""])
        is None
    )
    assert (
        shell.policy_violation(["netexec", "smb", "10.0.0.1", "-u", "guest", "-p", "guest"]) is None
    )
    assert (
        shell.policy_violation(
            ["netexec", "smb", "10.0.0.1", "-u", "", "-p", "", "--rid-brute", "10000"]
        )
        is None
    )


def test_blocks_netexec_spray_bypasses(tmp_path: object) -> None:
    from pathlib import Path

    wl = Path(str(tmp_path)) / "rockyou.txt"
    wl.write_text("Summer2024\nWinter2024\n", encoding="utf-8")

    def blocked(argv: list[str]) -> bool:
        return shell.policy_violation(argv) is not None

    # nargs='+' spray: >1 inline password / >1 inline username (no file needed)
    assert blocked(["netexec", "smb", "10.0.0.1", "-u", "admin", "-p", "a", "b", "c"])
    assert blocked(["netexec", "smb", "10.0.0.1", "-u", "alice", "bob", "-p", "Password1"])
    # a wordlist file smuggled in 2nd position, or via '='/short '=' or concatenated syntax
    assert blocked(["netexec", "smb", "10.0.0.1", "-u", "admin", "-p", "decoy", str(wl)])
    assert blocked(["netexec", "smb", "10.0.0.1", f"--password={wl}"])
    assert blocked(["netexec", "smb", "10.0.0.1", f"-p={wl}"])
    assert blocked(["netexec", "smb", "10.0.0.1", f"-p{wl}"])
    assert blocked(["nxc", "smb", "10.0.0.1", "-u", "admin", "-p", "a", "b"])
    # single inline literals (Tier-1/2) still pass, including via '=' and empty secret
    assert not blocked(["netexec", "smb", "10.0.0.1", "-u", "administrator", "-p", ""])
    assert not blocked(["netexec", "smb", "10.0.0.1", "-u=guest", "-p=guest"])
    assert not blocked(["netexec", "smb", "10.0.0.1", "-u", "", "-p", "", "--shares"])
