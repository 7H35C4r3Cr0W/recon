from pathlib import Path

from oscprecon import manual_commands
from oscprecon.modules import ftp as ftp_pkg
from oscprecon.modules import http as http_pkg
from oscprecon.modules import smb as smb_pkg
from oscprecon.modules import vhost as vhost_pkg

HTTP_YAML = Path(http_pkg.__file__).parent / "manual_commands.yaml"
VHOST_YAML = Path(vhost_pkg.__file__).parent / "manual_commands.yaml"
SMB_YAML = Path(smb_pkg.__file__).parent / "manual_commands.yaml"
FTP_YAML = Path(ftp_pkg.__file__).parent / "manual_commands.yaml"


def test_http_manual_commands_load() -> None:
    commands = manual_commands.load_manual_commands(HTTP_YAML)
    assert len(commands) >= 12
    assert all(c.description and c.command for c in commands)


def test_http_manual_commands_are_exam_legal() -> None:
    joined = " ".join(c.command for c in manual_commands.load_manual_commands(HTTP_YAML))
    assert "--enumerate" in joined  # wpscan enumerate present
    assert "--passwords" not in joined  # never a password brute
    # no shell chaining — each entry must run as a single command through shell.run
    assert ";" not in joined and "&&" not in joined


def test_expand() -> None:
    assert manual_commands.expand("curl {url}x", url="http://h/") == "curl http://h/x"
    assert manual_commands.expand("{target}:{port}", target="10.0.0.1", port=8080) == (
        "10.0.0.1:8080"
    )


def test_vhost_manual_commands_are_active_and_legal() -> None:
    commands = manual_commands.load_manual_commands(VHOST_YAML)
    assert len(commands) >= 5
    joined = " ".join(c.command for c in commands)
    # no passive OSINT — §2 forbids internet at runtime beyond probing the target
    for passive in ("subfinder", "amass", "assetfinder"):
        assert passive not in joined
    assert "--passwords" not in joined
    assert ";" not in joined and "&&" not in joined


def test_smb_manual_commands_are_tier2_legal() -> None:
    commands = manual_commands.load_manual_commands(SMB_YAML)
    assert len(commands) >= 5
    joined = " ".join(c.command for c in commands)
    # Tier-2 single default creds present
    assert "'administrator'" in joined
    assert "'sa' -p 'sa'" in joined
    # never Tier-3: no list files, no spraying, no credential dumping
    assert "--passwords" not in joined
    assert "--continue-on-success" not in joined
    assert "secretsdump" not in joined
    assert ".txt" not in joined  # no wordlist files


def test_ftp_manual_commands_are_tier2_legal() -> None:
    commands = manual_commands.load_manual_commands(FTP_YAML)
    assert len(commands) >= 5
    joined = " ".join(c.command for c in commands)
    # single default-cred checks are single literals in the URL, never lists/spray
    assert "ftp:ftp@" in joined
    assert "--passwords" not in joined
    assert ".txt" not in joined  # no wordlist-driven auth
    # each entry runs as one command through shell.run (no shell chaining)
    assert ";" not in joined and "&&" not in joined
    # only §2-allowed clients
    for tool in ("hydra", "medusa", "ncrack"):
        assert tool not in joined


def test_load_missing(tmp_path: Path) -> None:
    assert manual_commands.load_manual_commands(tmp_path / "nope.yaml") == []
