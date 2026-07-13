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


def test_allows_newly_wired_readonly_enum_tools() -> None:
    def ok(argv: list[str]) -> bool:
        return shell.policy_violation(argv) is None

    # read-only impacket enum + service enum tools are now on the allow-list
    assert ok(["impacket-samrdump", "corp.local/:@10.0.0.1"])
    assert ok(["impacket-lookupsid", ":@10.0.0.1"])
    assert ok(["impacket-rpcdump", "10.0.0.1"])
    assert ok(["ssh-audit", "10.0.0.1"])
    assert ok(["snmp-check", "-c", "public", "10.0.0.1"])
    assert ok(["snmpbulkwalk", "-v2c", "-c", "public", "10.0.0.1"])
    assert ok(["windapsearch", "--dc-ip", "10.0.0.1", "-u", "", "-U"])
    assert ok(["ldapdomaindump", "ldap://10.0.0.1"])
    assert ok(["svn", "ls", "svn://10.0.0.1/"])
    assert ok(["iscsiadm", "-m", "discovery", "-t", "st", "-p", "10.0.0.1"])
    # DB clients — single default-cred (Tier-2) read-only enum
    assert ok(["mysql", "-h", "10.0.0.1", "-u", "root"])
    assert ok(["psql", "-h", "10.0.0.1", "-U", "postgres"])
    assert ok(["redis-cli", "-h", "10.0.0.1", "INFO"])
    assert ok(["mongosh", "--host", "10.0.0.1", "--quiet"])
    assert ok(["impacket-mssqlclient", "sa:@10.0.0.1"])
    # the blanket brute/spray flag guard still applies to the new tools
    assert shell.policy_violation(["mysql", "-h", "10.0.0.1", "--passwords", "x"]) is not None


def test_blocks_db_client_file_and_os_primitives() -> None:
    def blocked(argv: list[str]) -> bool:
        return shell.policy_violation(argv) is not None

    # a hand-typed DB-client query that writes/reads files or runs OS commands is not recon (§2)
    outfile = "SELECT 1 INTO OUTFILE '/var/www/x.php'"
    assert blocked(["mysql", "-h", "x", "-u", "root", "-e", outfile])
    assert blocked(["mysql", "-h", "x", "-u", "root", "-e", "SELECT LOAD_FILE('/etc/passwd')"])
    assert blocked(["mysql", "-h", "x", "-u", "root", "-e", "SELECT sys_exec('id')"])
    assert blocked(["psql", "-h", "x", "-c", "SELECT pg_read_file('/etc/passwd')"])
    assert blocked(["psql", "-h", "x", "-c", "SELECT lo_export(1, '/tmp/x')"])
    assert blocked(["mysql", "-h", "x", "-u", "root", "-e", "\\! id"])  # client shell escape
    # read-only enum queries stay allowed
    assert not blocked(["mysql", "-h", "x", "-u", "root", "-e", "SHOW DATABASES;"])
    assert not blocked(["psql", "-h", "x", "-U", "postgres", "-c", "SELECT version();"])
    assert not blocked(["redis-cli", "-h", "x", "INFO"])


def test_blocks_postgresql_server_modifying_primitives() -> None:
    def blocked(sql: str) -> bool:
        return shell.policy_violation(["psql", "svc", "-c", sql]) is not None

    # server-write / file / OS / role-DDL primitives are blocked (case + whitespace insensitive)
    assert blocked("COPY t TO '/tmp/x'")
    assert blocked("COPY t FROM PROGRAM 'id'")
    assert blocked("copy  t  to  '/tmp/x'")  # extra whitespace
    assert blocked("CREATE FUNCTION f() RETURNS int AS $$ x $$ LANGUAGE sql")
    assert blocked("create  or  replace  function f()")  # whitespace variant
    assert blocked("CREATE EXTENSION plpython3u")
    assert blocked("DO $$ BEGIN PERFORM 1; END $$")
    assert blocked("ALTER ROLE postgres SUPERUSER")
    assert blocked("create role hax with superuser")
    assert blocked("DROP DATABASE prod")
    assert blocked("SELECT pg_read_file('/etc/passwd')")
    assert blocked("SELECT pg_ls_dir('/')")
    assert blocked("SELECT lo_export(1, '/tmp/x')")
    # review-hardening: variants + evasions that earlier slipped through
    assert blocked("DO $body$ BEGIN PERFORM 1; END $body$")  # tagged dollar-quote (not just $$)
    assert blocked("DO $$ BEGIN PERFORM 1; END $$")
    assert blocked("CREATE/**/EXTENSION plpython3u")  # block-comment splits keyword
    assert blocked("CREATE/**/FUNCTION f() RETURNS int AS $x$ x $x$ LANGUAGE sql")
    assert blocked("ALTER/**/ROLE postgres SUPERUSER")
    assert blocked("ALTER USER postgres WITH SUPERUSER")  # USER is an alias of ROLE
    assert blocked("DROP USER victim")
    assert blocked("SELECT pg_read_binary_file('/etc/shadow')")  # binary_ infix variant
    assert blocked("SELECT pg_ls_waldir()")
    assert blocked("SELECT pg_ls_logdir()")
    assert blocked("SELECT pg_stat_file('/etc/passwd')")
    assert blocked("GRANT pg_read_server_files TO app")
    assert blocked("COPY (SELECT 1) TO PROGRAM 'id'")
    # read-only enumeration must NOT be blocked (no simplistic substring false positives)
    assert not blocked("SELECT version()")
    assert not blocked("SELECT datname FROM pg_database")
    assert not blocked("SELECT rolname FROM pg_roles")
    assert not blocked("SELECT rolcanlogin FROM pg_roles")
    assert not blocked("SELECT current_user, version()")
    assert not blocked("SELECT schema_name FROM information_schema.schemata")
    assert not blocked("SELECT copy FROM audit_log")  # a column named 'copy' is not the COPY stmt
    assert not blocked("SELECT datname FROM pg_database WHERE datname = 'copydb'")
