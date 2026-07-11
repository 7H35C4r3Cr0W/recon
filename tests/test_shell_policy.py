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
