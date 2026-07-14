import shlex
from pathlib import Path

import pytest
import yaml

from oscprecon import shell
from oscprecon.gui.simple_recon import SIMPLE_SPECS
from oscprecon.models import Target
from oscprecon.modules import base

# The read-only service modules added in the specialist batch. Their Tier-1 commands must actually
# pass the shell policy (else the tool would silently [blocked] them), and their Tier-2 manual
# follow-ups must be runnable too — every command's binary has to be on the OSCP allow-list.
_NEW_MODULES = [
    "rdp",
    "vnc",
    "finger",
    "x11",
    "ajp",
    "ipmi",
    "sip",
    "oracle",
    "elasticsearch",
    "couchdb",
    "docker",
    "kubernetes",
    "memcached",
    "winrm",
    "rsync",
    "msrpc",
    "imap",
    "pop3",
    "telnet",
    "ipp",
    "iscsi",
    "svn",
    "ident",
    "mdns",
    "upnp",
    "rmi",
    "openvpn",
    "rpcbind",
    "etcd",
    "jetdirect",
]


@pytest.mark.parametrize("module", _NEW_MODULES)
def test_tier1_commands_pass_the_shell_policy(module: str) -> None:
    target = Target(ip="10.10.10.5")
    for command, _tool in SIMPLE_SPECS[module].steps_fn(target, 0):
        argv = shlex.split(command.shell_line)
        violation = shell.policy_violation(argv)
        assert violation is None, f"{module} Tier-1 blocked: {command.shell_line} -> {violation}"


@pytest.mark.parametrize("module", _NEW_MODULES)
def test_manual_commands_use_allowed_tools(module: str) -> None:
    path = Path(base.__file__).parent / module / "manual_commands.yaml"
    entries = yaml.safe_load(path.read_text(encoding="utf-8"))
    for entry in entries:
        # placeholders like {target}/{module} would break shlex — neutralise them to a bare token
        neutral = entry["command"].replace("{", "X").replace("}", "X")
        tool = shlex.split(neutral)[0]
        assert tool in shell.ALLOWED_TOOLS, f"{module} manual command uses non-allowed tool: {tool}"


@pytest.mark.parametrize("module", _NEW_MODULES)
def test_module_findings_service_matches_module_name(module: str) -> None:
    # the graph parents a finding to its service via the finding's `module` == service name, so the
    # module's parse() must stamp Finding(service=<module>) or the BloodHound edge is lost
    factory = SIMPLE_SPECS[module].factory
    assert factory().name == module
