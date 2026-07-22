import shlex

from oscprecon.models import DiscoveredService, Proto, ScanResults, Target
from oscprecon.modules.ftp import (
    FtpModule,
    anon_credential,
    ftp_base_url,
    ftp_dir_url,
)


def _target() -> Target:
    return Target(ip="10.10.10.5", hostname="box.htb")


def test_triggers() -> None:
    module = FtpModule()
    ftp = ScanResults(target=_target(), services=[DiscoveredService(21, Proto.TCP, "ftp")])
    assert module.triggers(ftp) is True
    alt = ScanResults(target=_target(), services=[DiscoveredService(2121, Proto.TCP, "ftp")])
    assert module.triggers(alt) is True  # matched by service name, not just port
    other = ScanResults(target=_target(), services=[DiscoveredService(80, Proto.TCP, "http")])
    assert module.triggers(other) is False


def test_banner_and_anon_steps() -> None:
    module = FtpModule()
    banner = [s.command.shell_line for s in module.banner_steps(_target())]
    assert "nmap -sV --script ftp-anon,ftp-syst,ftp-bounce -p 21 10.10.10.5" in banner
    anon = [s.command.shell_line for s in module.anon_steps(_target())]
    assert len(anon) == 1 and shlex.split(anon[0])[-1] == "ftp://10.10.10.5/"


def test_commands_batch() -> None:
    assert len(FtpModule().commands(_target(), [])) == 2  # 1 banner + 1 anon


def test_non_default_port() -> None:
    assert ftp_base_url("10.10.10.5", 2121) == "ftp://10.10.10.5:2121"
    step = FtpModule().anon_steps(_target(), port=2121)[0]
    assert shlex.split(step.command.shell_line)[-1] == "ftp://10.10.10.5:2121/"


def test_list_step_encodes_untrusted_path() -> None:
    module = FtpModule()
    # a directory name with a space is percent-encoded, so it stays one argv token
    spaced = module.list_step(_target(), "/New Folder", port=21).command.shell_line
    assert shlex.split(spaced)[-1] == "ftp://10.10.10.5/New%20Folder/"
    # a hostile dir name cannot inject a flag or a second URL: the space (token break) and colon
    # (scheme) are percent-encoded, so the URL is a single trailing token and no second URL forms
    hostile = module.list_step(_target(), "/-x http://evil/", port=21).command.shell_line
    tokens = shlex.split(hostile)
    assert tokens[0] == "curl"
    assert tokens[-1].startswith("ftp://10.10.10.5/")
    assert sum(t.startswith("ftp://") for t in tokens) == 1  # exactly one URL token
    assert "http://evil" not in hostile  # the ':' is encoded, so no second URL forms


def test_list_step_output_files_are_injective() -> None:
    module = FtpModule()
    t = _target()
    # '/' and '/root' both slug to "root" — the path hash keeps their snapshot files distinct
    root = module.list_step(t, "/").command.output_file
    root_dir = module.list_step(t, "/root").command.output_file
    assert root != root_dir
    assert module.list_step(t, "/a/b").command.output_file != (
        module.list_step(t, "/a-b").command.output_file
    )


def test_dir_url_always_lists_never_downloads() -> None:
    # every walked URL ends in '/', so curl issues LIST, never a file download
    assert ftp_dir_url("10.10.10.5", 21, "/pub").endswith("/")
    assert ftp_dir_url("10.10.10.5", 21, "pub/sub").endswith("/")


def test_anon_credential() -> None:
    cred = anon_credential(_target())
    assert cred.username == "anonymous"
    assert cred.secret == ""
    assert cred.source == "ftp-anon-enum"
    assert cred.domain == "box.htb"


def test_parse_and_suggest() -> None:
    module = FtpModule()
    findings = module.parse(
        {
            "nmap-ftp": "21/tcp open  ftp     vsftpd 3.0.3\n"
            "| ftp-anon: Anonymous FTP login allowed (FTP code 230)\n"
        }
    )
    kinds = {f.fields["kind"] for f in findings}
    assert "auth" in kinds
    assert "banner" in kinds
    suggestions = module.suggest(findings)
    assert suggestions and "anonymous ftp allowed" in suggestions[0].lower()


def test_suggest_active_mode_when_pasv_unreachable() -> None:
    # HTB Ethereal: PASV advertises a NAT-internal IP → passive listing fails; suggest active mode.
    module = FtpModule()
    findings = module.parse(
        {
            "nmap-ftp": "| ftp-anon: Anonymous FTP login allowed (FTP code 230)\n"
            "|_Can't get directory listing: PASV IP 172.16.249.135 is not the same as 10.10.10.6\n"
        }
    )
    hits = [s for s in module.suggest(findings) if "ACTIVE mode" in s]
    assert hits and "--no-passive-ftp" in hits[0]
