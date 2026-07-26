"""Recon can run as a credential you already hold, not just anonymously.

The vault existed but only the Exploitation tab read it, so every service panel was stuck on null
session / guest / anonymous. Finding a password in an http config and then having no way to point
the SMB or LDAP enumeration at it is the gap these tests pin shut.

This is authenticated enumeration, NOT a credential attack: one credential the operator already has,
never a list. `shell.policy_violation` agrees — see the bottom of this file.
"""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from oscprecon import shell
from oscprecon.models import Credential, Target
from oscprecon.modules.ftp import FtpModule
from oscprecon.modules.ldap import LdapModule
from oscprecon.modules.smb import SmbModule
from oscprecon.recon_auth import ReconAuth, from_method


def _target() -> Target:
    return Target(ip="10.10.10.5", hostname="active.htb")


def _cred(**kw: str) -> Credential:
    base = {"username": "svc_account", "secret": "Ticketmaster1968", "domain": "active.htb"}
    base.update(kw)
    return Credential(**base)  # type: ignore[arg-type]


# --- the identity value object -------------------------------------------------------------------


def test_the_three_identities() -> None:
    assert ReconAuth.null().anonymous and ReconAuth.guest().anonymous
    who = ReconAuth.from_credential(_cred())
    assert not who.anonymous
    assert who.username == "svc_account" and who.secret == "Ticketmaster1968"


def test_from_method_bridges_the_old_string_form() -> None:
    assert from_method("guest").kind == "guest"
    assert from_method("null").kind == "null"
    assert from_method("anything else").kind == "null"


def test_each_identity_writes_to_its_own_output_folder() -> None:
    # two users' share lists must never overwrite each other's snapshot on disk
    a = ReconAuth.from_credential(_cred(username="alice"))
    b = ReconAuth.from_credential(_cred(username="bob"))
    assert a.output_slug != b.output_slug
    assert ReconAuth.null().output_slug == "null-session"
    assert ReconAuth.guest().output_slug == "guest"


def test_a_hostile_username_cannot_escape_the_output_folder(tmp_path: Path) -> None:
    # the username reaches a path, and a credential can be pasted in from anywhere
    evil = ReconAuth.from_credential(_cred(username="../../etc/passwd"))
    slug = evil.output_slug
    assert "/" not in slug and "\\" not in slug
    assert (tmp_path / "smb" / slug).resolve().is_relative_to(tmp_path.resolve())


def test_a_hash_uses_the_pass_the_hash_flag_not_the_password_flag() -> None:
    who = ReconAuth(username="admin", secret="a" * 32, secret_type="hash", kind="cred")
    assert who.netexec_args() == "-u 'admin' -H '" + "a" * 32 + "'"
    assert "--pw-nt-hash" in who.smbclient_auth()


def test_the_recorded_domain_is_passed_explicitly() -> None:
    # without -d, netexec authenticates against the domain it found on the TARGET — usually right,
    # silently wrong when the credential belongs to another domain
    assert " -d 'active.htb'" in ReconAuth.from_credential(_cred()).netexec_args()
    assert "-d" not in ReconAuth.from_credential(_cred(domain="")).netexec_args()
    assert "-d" not in ReconAuth.guest().netexec_args()  # guest is the target's own account


def test_an_empty_secret_is_not_treated_as_a_hash() -> None:
    who = ReconAuth(username="admin", secret="", secret_type="hash", kind="cred")
    assert not who.is_hash
    assert "-p ''" in who.netexec_args()


def test_anonymous_curl_stays_flagless() -> None:
    # curl already logs into FTP anonymously; adding -u would change every existing command
    assert ReconAuth.null().curl_userpass() == ""
    assert ReconAuth.from_credential(_cred()).curl_userpass() == "-u 'svc_account:Ticketmaster1968'"


# --- the modules build the right commands ---------------------------------------------------------


def test_smb_credentialed_steps_authenticate() -> None:
    steps = SmbModule().credentialed_steps(_target(), ReconAuth.from_credential(_cred()))
    lines = [s.command.shell_line for s in steps]
    assert any(
        "-u 'svc_account' -p 'Ticketmaster1968' -d 'active.htb' --shares" in line for line in lines
    )
    assert any("smbclient -L //10.10.10.5/ -U 'active.htb/svc_account%" in line for line in lines)
    assert all("as-svc_account" in s.command.output_file for s in steps)


def test_smb_followups_unlock_more_as_a_real_user() -> None:
    module = SmbModule()
    anon = [s.command.shell_line for s in module.followup_steps(_target(), ReconAuth.null())]
    cred = [
        s.command.shell_line
        for s in module.followup_steps(_target(), ReconAuth.from_credential(_cred()))
    ]
    assert len(cred) > len(anon)
    assert any("--groups" in line for line in cred)
    assert not any("--groups" in line for line in anon)


def test_credentialed_smb_never_reads_a_list_file() -> None:
    # the Tier-3 line: one credential is enumeration, a list is spraying (§11)
    steps = SmbModule().credentialed_steps(_target(), ReconAuth.from_credential(_cred()))
    steps += SmbModule().followup_steps(_target(), ReconAuth.from_credential(_cred()))
    joined = " ".join(s.command.shell_line for s in steps)
    assert ".txt" not in joined
    assert "--continue-on-success" not in joined


def test_smb_share_access_uses_the_chosen_identity() -> None:
    module = SmbModule()
    who = ReconAuth.from_credential(_cred())
    ls = module.share_steps(_target(), "Replication", who)[0].command.shell_line
    assert "-U 'active.htb/svc_account%Ticketmaster1968'" in ls
    peek = module.share_peek_step(_target(), "Replication", "web.config", who).command.shell_line
    assert "-U 'active.htb/svc_account%Ticketmaster1968'" in peek


def test_ldap_binds_with_the_credential() -> None:
    steps = LdapModule().rootdse_steps(_target(), 389, ReconAuth.from_credential(_cred()))
    line = steps[0].command.shell_line
    assert "-D 'svc_account@active.htb'" in line and "-w 'Ticketmaster1968'" in line
    assert "as-svc_account" in steps[0].command.output_file


def test_ldap_anonymous_command_is_unchanged() -> None:
    # the default path must stay byte-identical — this feature adds a mode, it does not alter one
    anon = LdapModule().rootdse_steps(_target(), 389)[0].command
    assert anon.shell_line.startswith("ldapsearch -x -H ldap://10.10.10.5:389")
    assert anon.output_file == "ldap/rootdse.txt"


def test_ftp_anonymous_command_is_unchanged() -> None:
    anon = FtpModule().list_step(_target(), "/pub", 21).command
    assert " -u " not in anon.shell_line
    assert anon.output_file.startswith("ftp/dirs/")


def test_ftp_authenticates_when_given_a_credential() -> None:
    step = FtpModule().list_step(_target(), "/pub", 21, ReconAuth.from_credential(_cred()))
    assert "-u 'svc_account:Ticketmaster1968'" in step.command.shell_line
    assert step.command.output_file.startswith("ftp/as-svc_account/")


# --- the policy already allows this ---------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "netexec smb 10.10.10.5 -u 'svc' -p 'pass' --shares",
        "netexec smb 10.10.10.5 -u 'svc' -H 'aad3b435b51404eeaad3b435b51404ee' --shares",
        "smbclient -L //10.10.10.5/ -U 'dom/svc%pass'",
        "ldapsearch -x -D 'svc@dom' -w 'pass' -H ldap://10.10.10.5:389 -b '' -s base",
        "smbmap -H 10.10.10.5 -u 'svc' -d 'dom' -p 'pass'",
    ],
)
def test_one_known_credential_is_recon_not_a_credential_attack(command: str) -> None:
    assert shell.policy_violation(shlex.split(command)) is None, command


@pytest.mark.parametrize(
    "command",
    [
        "netexec smb 10.10.10.5 -u users.txt -p passwords.txt",
        "netexec smb 10.10.10.5 -u 'svc' -p passwords.txt --continue-on-success",
        "hydra -L users.txt -P rockyou.txt smb://10.10.10.5",
    ],
)
def test_iterating_a_list_is_still_blocked_by_default(command: str) -> None:
    assert shell.policy_violation(shlex.split(command)) is not None, command


# --- what the authenticated-only tools return -----------------------------------------------------


def _fixture(name: str) -> str:
    return (Path(__file__).parent / "fixtures" / "smb" / name).read_text(encoding="utf-8")


def test_smbmap_permissions_are_parsed() -> None:
    from oscprecon.modules.smb.parsers import parse_smbmap

    found = {f.value: f.detail for f in parse_smbmap(_fixture("smbmap.txt"))}
    assert found["Replication"] == "READ"
    assert found["Team Share"] == "READ,WRITE"  # a multi-word share name survives
    assert found["ADMIN$"] == ""  # NO ACCESS is not a permission


def test_netexec_groups_are_parsed() -> None:
    from oscprecon.modules.smb.parsers import parse_netexec_groups

    found = parse_netexec_groups(_fixture("netexec-groups.txt"))
    names = [f.value for f in found]
    assert "Domain Admins" in names
    assert all(f.kind == "group" for f in found)
    assert "-Group Name-" not in names and "Windows Server 2016 Standard 14393 x64" not in names


def test_netexec_loggedon_sessions_drop_the_domain_prefix() -> None:
    from oscprecon.modules.smb.parsers import parse_netexec_loggedon

    found = parse_netexec_loggedon(_fixture("netexec-loggedon.txt"))
    assert {f.value for f in found} == {"Administrator", "svc_tgs"}
    assert all(f.kind == "session" for f in found)


def test_spider_indexes_files_without_downloading_them() -> None:
    from oscprecon.modules.smb.parsers import parse_netexec_spider

    found = parse_netexec_spider(_fixture("netexec-spider.txt"))
    assert "Team Share/passwords.xlsx" in {f.value for f in found}
    assert all(f.kind == "file" for f in found)


def test_a_group_name_is_never_escalated_to_a_weakness() -> None:
    # Windows ships built-ins called "ANONYMOUS LOGON" / "Guests"; the text fallback would have
    # flagged them as anonymous access and put a red ring on the graph node
    from oscprecon.finding_severity import INFO, classify

    assert classify("group", "ANONYMOUS LOGON") == INFO
    assert classify("session", "Guest") == INFO


def test_a_credentialed_share_walk_does_not_overwrite_the_anonymous_snapshot() -> None:
    module = SmbModule()
    who = ReconAuth.from_credential(_cred())
    anon_ls = module.share_steps(_target(), "IT", ReconAuth.null())[0].command.output_file
    cred_ls = module.share_steps(_target(), "IT", who)[0].command.output_file
    assert anon_ls != cred_ls
    assert anon_ls.startswith("smb/shares/")  # the default path is unchanged
    assert cred_ls.startswith("smb/as-svc_account/shares/")

    anon_peek = module.share_peek_step(_target(), "IT", "web.config", ReconAuth.null())
    cred_peek = module.share_peek_step(_target(), "IT", "web.config", who)
    assert anon_peek.command.output_file.startswith("smb/peek/")
    assert cred_peek.command.output_file.startswith("smb/as-svc_account/peek/")
