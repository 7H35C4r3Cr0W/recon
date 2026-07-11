import shlex

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.ldap import (
    LdapModule,
    domain_to_basedn,
    ldap_uri,
    sanitize_basedn,
)


def _target() -> Target:
    return Target(ip="10.10.10.5", hostname="example.htb")


def test_triggers() -> None:
    module = LdapModule()
    for port in (389, 636, 3268, 3269):
        svc = ScanResults(target=_target(), services=[DiscoveredService(port, Proto.TCP, "ldap")])
        assert module.triggers(svc) is True
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_rootdse_steps() -> None:
    steps = LdapModule().rootdse_steps(_target())
    assert [s.tool for s in steps] == ["ldapsearch-rootdse", "nmap-ldap"]
    rootdse = steps[0].command.shell_line
    assert rootdse == 'ldapsearch -x -H ldap://10.10.10.5:389 -s base -b "" "(objectClass=*)" +'
    # the empty base and filter survive shlex as clean tokens (no injection, no split surprises)
    assert shlex.split(rootdse)[0] == "ldapsearch"
    assert len(LdapModule().commands(_target(), [])) == 2


def test_user_search_step_needs_valid_basedn() -> None:
    module = LdapModule()
    step = module.user_search_step(_target(), "DC=example,DC=htb")
    assert step is not None
    assert step.tool == "ldapsearch-users"
    assert step.command.shell_line == (
        'ldapsearch -x -H ldap://10.10.10.5:389 -b "DC=example,DC=htb" '
        '"(objectClass=person)" sAMAccountName cn -z 200'
    )
    # a hostile base DN yields no command at all
    assert module.user_search_step(_target(), '" ; rm -rf /') is None
    assert module.user_search_step(_target(), "") is None


def test_sanitize_basedn() -> None:
    assert sanitize_basedn("DC=example,DC=htb") == "DC=example,DC=htb"
    assert (
        sanitize_basedn("CN=Domain Admins,DC=example,DC=htb")
        == "CN=Domain Admins,DC=example,DC=htb"
    )
    assert sanitize_basedn('DC=x" evil') is None  # quote break-out blocked
    assert sanitize_basedn("-b evil") is None  # leading-dash flag blocked
    assert sanitize_basedn("DC=x;whoami") is None
    assert sanitize_basedn("DC=x$(id)") is None
    assert sanitize_basedn("") is None
    assert sanitize_basedn(None) is None


def test_domain_to_basedn() -> None:
    assert domain_to_basedn("example.htb") == "DC=example,DC=htb"
    assert domain_to_basedn("a.b.c") == "DC=a,DC=b,DC=c"
    assert domain_to_basedn("") == ""
    assert domain_to_basedn("bad domain") == ""  # space -> not a clean domain


def test_ldap_uri_scheme() -> None:
    assert ldap_uri("10.10.10.5", 389) == "ldap://10.10.10.5:389"
    assert ldap_uri("10.10.10.5", 3268) == "ldap://10.10.10.5:3268"
    assert ldap_uri("10.10.10.5", 636) == "ldaps://10.10.10.5:636"
    assert ldap_uri("10.10.10.5", 3269) == "ldaps://10.10.10.5:3269"


def test_non_default_port() -> None:
    step = LdapModule().rootdse_steps(_target(), port=3268)[1]  # nmap step
    assert "-p 3268 10.10.10.5" in step.command.shell_line


def test_parse_and_suggest() -> None:
    module = LdapModule()
    findings = module.parse(
        {
            "ldapsearch-rootdse": "namingContexts: DC=example,DC=htb\n",
            "ldapsearch-users": "sAMAccountName: jsmith\nsAMAccountName: svc_sql\n",
        }
    )
    kinds = {f.fields["kind"] for f in findings}
    assert {"naming-context", "bind", "user"} <= kinds
    joined = " ".join(module.suggest(findings)).lower()
    assert "anonymous ldap read allowed" in joined
    assert "base dn dc=example,dc=htb" in joined
    assert "2 users" in joined
