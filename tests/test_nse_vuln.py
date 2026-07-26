from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from oscprecon import nse_vuln, shell
from oscprecon.models import Proto

FIXTURES = Path(__file__).parent / "fixtures" / "nse"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# --- selector construction ------------------------------------------------------------------------


def test_every_generated_command_passes_the_recon_policy() -> None:
    # the whole feature runs through shell.run — a selector the policy refuses is a dead button
    for profile in (*nse_vuln.PROFILES, nse_vuln.GENERIC):
        for mode in nse_vuln.MODES:
            command = nse_vuln.build_command("10.10.10.100", [445], mode=mode, profile=profile)
            assert shell.policy_violation(shlex.split(command)) is None, command


def test_no_selector_can_reach_a_brute_script() -> None:
    # §2: a glob is judged by what it EXPANDS to. `smb-*` would match smb-brute; the families must
    # be narrow enough that no mode of any profile can run a credential attack.
    for profile in (*nse_vuln.PROFILES, nse_vuln.GENERIC):
        for mode in nse_vuln.MODES:
            selector = nse_vuln.selector(mode, profile)
            assert "brute" not in selector
            command = shlex.split(
                nse_vuln.build_command("10.10.10.100", [445], mode=mode, profile=profile)
            )
            assert shell.policy_violation(command) is None


def test_vulners_is_excluded_from_every_selector() -> None:
    # vulners.nse queries vulners.com with the target's product/version at scan time — §2 forbids
    # runtime internet and transmitting target data.
    for profile in (*nse_vuln.PROFILES, nse_vuln.GENERIC):
        for mode in nse_vuln.MODES:
            assert nse_vuln.VULNERS_EXCLUDE in nse_vuln.selector(mode, profile)


def test_command_shape() -> None:
    smb = nse_vuln.profile_for("microsoft-ds", 445)
    command = nse_vuln.build_command("10.10.10.100", [139, 445], profile=smb)
    assert command.startswith("nmap -Pn -sV -p 139,445 ")
    assert '--script "vuln and not *vulners*"' in command
    assert "--script-args vulns.showall" in command  # negative verdicts must be visible
    assert command.endswith(" 10.10.10.100")
    # no -oN: shell.run owns stdout -> the output file, a second writer would fight it
    assert "-oN" not in command


def test_udp_service_gets_su() -> None:
    snmp = nse_vuln.profile_for("snmp", 161)
    command = nse_vuln.build_command("10.10.10.100", [161], profile=snmp, proto=Proto.UDP)
    assert " -sU " in command


def test_targeted_mode_uses_the_family_operators_type() -> None:
    smb = nse_vuln.profile_for("microsoft-ds", 445)
    selector = nse_vuln.selector(nse_vuln.MODE_TARGETED, smb)
    assert "smb-vuln-*" in selector


def test_targeted_falls_back_to_the_category_without_a_family() -> None:
    assert nse_vuln.selector(nse_vuln.MODE_TARGETED, nse_vuln.GENERIC).startswith("vuln ")


def test_safe_mode_excludes_dos_scripts() -> None:
    smb = nse_vuln.profile_for("microsoft-ds", 445)
    assert "safe" in nse_vuln.selector(nse_vuln.MODE_SAFE, smb)


# --- service matching -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "port", "expected"),
    [
        ("microsoft-ds", 445, "smb"),
        ("netbios-ssn", 139, "smb"),
        ("http", 80, "http"),
        ("ssl/http", 443, "http"),
        ("ms-wbt-server", 3389, "rdp"),
        ("domain", 53, "dns"),
        ("ftp", 21, "ftp"),
        ("msrpc", 135, "generic"),  # unmatched -> still a complete, portrule-driven scan
        ("", 3306, "mysql"),  # no name: fall back to the port
    ],
)
def test_profile_for(name: str, port: int, expected: str) -> None:
    assert nse_vuln.profile_for(name, port).key == expected


def test_plan_scans_groups_a_service_family_into_one_pass() -> None:
    # 139 and 445 are both SMB: scanning per-port would run the identical command twice and record
    # every verdict twice.
    services = [
        (139, Proto.TCP, "netbios-ssn", ""),
        (445, Proto.TCP, "microsoft-ds", ""),
        (3389, Proto.TCP, "ms-wbt-server", ""),
    ]
    plan = nse_vuln.plan_scans(services)
    keys = {t.profile.key: t for t in plan}
    assert set(keys) == {"smb", "rdp"}
    assert keys["smb"].ports == (139, 445)
    assert keys["rdp"].ports == (3389,)


def test_plan_scans_keeps_tcp_and_udp_apart() -> None:
    plan = nse_vuln.plan_scans([(53, Proto.TCP, "domain", ""), (53, Proto.UDP, "domain", "")])
    assert len(plan) == 2
    assert {t.proto for t in plan} == {Proto.TCP, Proto.UDP}


# --- parsing --------------------------------------------------------------------------------------


def test_parses_a_confirmed_verdict_from_real_output() -> None:
    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-showall.txt"), default_port=445)
    hits = [r for r in results if r.vulnerable]
    assert [r.script for r in hits] == ["smb-vuln-ms17-010"]
    hit = hits[0]
    assert hit.state == "VULNERABLE"
    assert "CVE-2017-0143" in hit.ids
    assert "MS17-010" in hit.ids
    assert hit.risk == "HIGH"
    assert hit.port == 445


def test_not_vulnerable_is_never_a_hit() -> None:
    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-showall.txt"), default_port=445)
    cleared = {r.script for r in results if r.state.startswith("NOT VULNERABLE")}
    # the very check the operator was hunting for — it RAN, and it came back clean
    assert "smb-vuln-cve2009-3103" in cleared
    assert "smb-vuln-ms08-067" in cleared
    for script in cleared:
        assert not any(r.vulnerable for r in results if r.script == script)


def test_an_error_verdict_is_inconclusive_not_clean() -> None:
    # the operator's own lesson: "do not treat a timeout as a negative vulnerability result"
    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-showall.txt"), default_port=445)
    unknown = {r.script for r in results if r.inconclusive}
    assert "smb-vuln-ms10-061" in unknown  # NT_STATUS_ACCESS_DENIED
    ms10_061 = next(r for r in results if r.script == "smb-vuln-ms10-061")
    assert ms10_061.vulnerable is False
    assert ms10_061.state.startswith("NOT VULNERABLE") is False


def test_port_scripts_are_attributed_to_their_own_port() -> None:
    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-showall.txt"), default_port=445)
    webexec = [r for r in results if r.script == "smb-vuln-webexec"]
    assert {r.port for r in webexec} == {139, 445}  # ran on both ports, recorded on both


def test_findings_carry_the_vulnerable_severity() -> None:
    from oscprecon import finding_severity

    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-showall.txt"), default_port=445)
    found = nse_vuln.to_findings(results, "smb")
    confirmed = [f for f in found if f.fields.get("kind") == "vuln"]
    assert len(confirmed) == 1
    assert finding_severity.category_of(confirmed[0].fields) == finding_severity.VULNERABLE
    assert finding_severity.is_notable(finding_severity.VULNERABLE)


def test_findings_record_inconclusive_checks_as_info_not_as_a_weakness() -> None:
    from oscprecon import finding_severity

    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-showall.txt"), default_port=445)
    found = nse_vuln.to_findings(results, "smb")
    unknown = [f for f in found if f.fields.get("kind") == "vuln-check"]
    assert unknown, "an unreached verdict must be recorded, not dropped"
    for finding in unknown:
        assert finding_severity.category_of(finding.fields) == finding_severity.INFO


def test_clean_checks_are_not_recorded_as_findings() -> None:
    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-showall.txt"), default_port=445)
    scripts = {f.fields.get("value") for f in nse_vuln.to_findings(results, "smb")}
    assert "smb-vuln-ms08-067" not in scripts  # clean -> the transcript's job, not findings.json


def test_summary_counts_what_actually_ran() -> None:
    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-showall.txt"), default_port=445)
    lines = nse_vuln.summary_lines(results)
    assert any("VULNERABLE: smb-vuln-ms17-010" in line for line in lines)
    assert any("could not check" in line for line in lines)
    assert any("clean" in line for line in lines)


def test_summary_of_an_empty_scan_says_so() -> None:
    assert "No NSE script output" in nse_vuln.summary_lines([])[0]


def test_parser_survives_junk() -> None:
    for junk in ("", "not nmap output at all", "|\n|_\n| :\n", "445/tcp open\n| x"):
        assert isinstance(nse_vuln.parse_vuln_output(junk), list)


def test_category_run_finds_the_same_hit_as_the_targeted_family() -> None:
    # both selectors were run live against the same host; they must agree on the verdict
    showall = nse_vuln.parse_vuln_output(_fixture("smb-vuln-showall.txt"), default_port=445)
    category = nse_vuln.parse_vuln_output(_fixture("smb-vuln-category.txt"), default_port=445)
    assert {r.script for r in showall if r.vulnerable} == {
        r.script for r in category if r.vulnerable
    }


def test_output_name_is_distinct_per_mode_and_ports() -> None:
    smb = nse_vuln.profile_for("microsoft-ds", 445)
    names = {nse_vuln.output_name(smb, [139, 445], mode) for mode in nse_vuln.MODES}
    assert len(names) == len(nse_vuln.MODES)  # a mode switch must not overwrite the last run
    assert nse_vuln.output_name(smb, [139, 445], "all") != nse_vuln.output_name(smb, [445], "all")


def test_an_informational_script_is_not_reported_as_a_failed_check() -> None:
    # live-observed noise: several vuln-category scripts state a negative in prose or just print a
    # value. Calling those "could not check" buries the one that really did fail.
    text = """\
PORT     STATE SERVICE
5357/tcp open  http
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_ssl-ccs-injection: No reply from server (TIMEOUT)
"""
    results = nse_vuln.parse_vuln_output(text, default_port=5357)
    unknown = {r.script for r in results if r.inconclusive}
    assert unknown == {"ssl-ccs-injection"}  # only the real failure
    findings = {f.fields.get("value") for f in nse_vuln.to_findings(results, "http")}
    assert findings == {"ssl-ccs-injection"}


def test_the_clean_count_only_counts_explicit_negatives() -> None:
    # "nothing found, N checks clean" must be backed by N real NOT VULNERABLE verdicts
    text = """\
PORT     STATE SERVICE
80/tcp   open  http
|_http-server-header: nginx
| http-vuln-cve2017-5638:
|   NOT VULNERABLE:
|     State: NOT VULNERABLE
"""
    lines = nse_vuln.summary_lines(nse_vuln.parse_vuln_output(text, default_port=80))
    assert "1 check(s) came back clean" in " ".join(lines)


def test_sV_fingerprint_output_is_not_mistaken_for_a_check() -> None:
    text = """\
PORT     STATE SERVICE
8080/tcp open  http-alt
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 400 Bad Request
|_    Connection: close
"""
    assert nse_vuln.parse_vuln_output(text, default_port=8080) == []


# --- the exact miss this feature exists to prevent (PG "Internal", MS09-050) --------------------


def test_the_ms09_050_verdict_that_was_missed_is_caught() -> None:
    # The operator's own scan of PG Internal. A default -sC -sV sweep reported this box as clean;
    # only `--script smb-vuln-*` produced the verdict below, and it was the way in.
    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-cve2009-3103.txt"), default_port=445)
    hits = [r for r in results if r.vulnerable]
    assert [r.script for r in hits] == ["smb-vuln-cve2009-3103"]
    assert hits[0].state == "VULNERABLE"
    assert "CVE-2009-3103" in hits[0].ids
    assert "SMBv2" in hits[0].title


def test_the_ms09_050_verdict_becomes_a_vulnerable_finding() -> None:
    from oscprecon import finding_severity

    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-cve2009-3103.txt"), default_port=445)
    found = [f for f in nse_vuln.to_findings(results, "smb") if f.fields.get("kind") == "vuln"]
    assert len(found) == 1
    assert finding_severity.category_of(found[0].fields) == finding_severity.VULNERABLE
    assert "CVE-2009-3103" in found[0].detail


def test_the_ms10_061_timeout_is_not_reported_as_safe() -> None:
    # lesson 7 of the writeup: "Do not treat a timeout as a negative vulnerability result."
    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-cve2009-3103.txt"), default_port=445)
    ms10_061 = next(r for r in results if r.script == "smb-vuln-ms10-061")
    assert ms10_061.inconclusive is True
    assert ms10_061.vulnerable is False
    lines = " ".join(nse_vuln.summary_lines(results))
    assert "could not check: smb-vuln-ms10-061" in lines


def test_the_ms10_054_false_is_a_clean_verdict_not_a_hit() -> None:
    results = nse_vuln.parse_vuln_output(_fixture("smb-vuln-cve2009-3103.txt"), default_port=445)
    ms10_054 = next(r for r in results if r.script == "smb-vuln-ms10-054")
    assert ms10_054.vulnerable is False
    assert ms10_054.inconclusive is False


def test_every_service_family_has_a_vuln_surface() -> None:
    # "all services — ftp vuln or other stuff vuln needs to be part of the roster". Any discovered
    # service resolves to a runnable vuln scan: a named family where one exists, the portrule-driven
    # vuln category otherwise. There is no service for which the button does nothing.
    for name, port in [
        ("ftp", 21),
        ("ssh", 22),
        ("smtp", 25),
        ("domain", 53),
        ("http", 80),
        ("netbios-ssn", 139),
        ("microsoft-ds", 445),
        ("ms-wbt-server", 3389),
        ("mysql", 3306),
        ("ms-sql-s", 1433),
        ("vnc", 5900),
        ("irc", 6667),
        ("java-rmi", 1099),
        ("snmp", 161),
        ("nfs", 2049),
        ("ldap", 389),
        ("imap", 143),
        ("afp", 548),
        ("oracle-tns", 1521),
        ("msrpc", 135),  # no specific family -> still a complete, portrule-driven scan
        ("whatever-unknown", 61234),
    ]:
        spec = nse_vuln.profile_for(name, port)
        command = nse_vuln.build_command("10.10.10.100", [port], profile=spec)
        assert "--script" in command and str(port) in command, name
        assert shell.policy_violation(shlex.split(command)) is None, name


def test_the_named_families_cover_the_classic_oscp_checks() -> None:
    # the forms an operator types by hand must actually be what "targeted" runs
    families = {p.key: " ".join(p.family) for p in nse_vuln.PROFILES}
    assert "smb-vuln-*" in families["smb"]
    assert "ftp-vuln-*" in families["ftp"] and "ftp-vsftpd-backdoor" in families["ftp"]
    assert "http-vuln-*" in families["http"]
    assert "smtp-vuln-*" in families["smtp"]
    assert "rdp-vuln-*" in families["rdp"]
    assert "mysql-vuln-*" in families["mysql"]


# --- roster width: a vuln script with no family never runs in targeted mode ----------------------


def test_the_samba_prefixed_check_is_reachable_from_the_smb_family() -> None:
    # samba-vuln-cve-2012-1182 is a DIFFERENT PREFIX — smb-vuln-* does not match it. Samba on Linux
    # answers 139/445 as often as Windows does, so a targeted SMB run that cannot reach the Samba
    # pre-auth heap overflow is the same silent miss this whole feature exists to prevent.
    smb = nse_vuln.profile_for("microsoft-ds", 445)
    selector = nse_vuln.selector(nse_vuln.MODE_TARGETED, smb)
    assert "samba-vuln-*" in selector
    assert "smb-vuln-*" in selector  # and the Windows prefix is still there


@pytest.mark.parametrize(
    ("key", "check"),
    [
        ("clamav", "clamav-exec"),
        ("distcc", "distcc-cve2004-2687"),
        ("ipmi", "ipmi-cipher-zero"),
        ("ipmi", "supermicro-ipmi-conf"),
        ("netbus", "netbus-auth-bypass"),
        ("puppet", "puppet-naivesigning"),
        ("qconn", "qconn-exec"),
        ("wdb", "wdb-version"),
        ("dns", "dns-update"),
        ("http", "tls-ticketbleed"),
        ("http", "rsa-vuln-roca"),
        ("mail-tls", "tls-ticketbleed"),
        ("ssh", "rsa-vuln-roca"),
    ],
)
def test_each_family_carries_its_signature_check(key: str, check: str) -> None:
    profile = next(p for p in nse_vuln.PROFILES if p.key == key)
    assert check in nse_vuln.selector(nse_vuln.MODE_TARGETED, profile)


@pytest.mark.parametrize(
    ("name", "port", "expected"),
    [
        ("clam", 3310, "clamav"),
        ("distccd", 3632, "distcc"),
        ("asf-rmcp", 623, "ipmi"),
        ("netbus", 12345, "netbus"),
        ("puppet", 8140, "puppet"),
        ("qconn", 8000, "qconn"),
        ("wdbrpc", 17185, "wdb"),
        ("", 3632, "distcc"),  # no name: the port still finds the family
    ],
)
def test_profile_for_resolves_the_new_service_names(name: str, port: int, expected: str) -> None:
    assert nse_vuln.profile_for(name, port).key == expected


def test_a_tls_fronted_app_beats_the_generic_web_name() -> None:
    # nmap reports the Puppet CA as "8140/tcp open ssl/http Puppet". Matching "ssl/http" first would
    # hand it the web family and never run puppet-naivesigning.
    assert nse_vuln.profile_for("ssl/http", 8140, "Puppet").key == "puppet"


def test_a_bmc_web_page_stays_on_the_web_family() -> None:
    # the mirror case: "IPMI" is in the product string of a BMC's *web* UI, and port 80 wants the
    # http checks, not the 623/udp IPMI ones.
    assert nse_vuln.profile_for("http", 80, "Supermicro IPMI web interface").key == "http"


def test_every_new_family_produces_a_runnable_targeted_scan() -> None:
    for key in ("clamav", "distcc", "ipmi", "netbus", "puppet", "qconn", "wdb"):
        profile = next(p for p in nse_vuln.PROFILES if p.key == key)
        command = nse_vuln.build_command(
            "10.10.10.100", list(profile.ports), mode=nse_vuln.MODE_TARGETED, profile=profile
        )
        assert shell.policy_violation(shlex.split(command)) is None, key
        assert profile.why, key


def test_no_family_uses_a_bare_service_glob() -> None:
    # §2: a glob is judged by what it EXPANDS to, and `smb-*` matches smb-brute. Every selector is
    # either an explicit script name or a *-vuln-* glob, which cannot reach a credential script.
    for profile in nse_vuln.PROFILES:
        for entry in profile.family:
            if "*" in entry:
                assert "-vuln-" in entry, entry
