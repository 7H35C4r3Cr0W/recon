import shlex
from pathlib import Path

import pytest

from oscprecon import shell
from oscprecon.models import Target, is_cidr_range, validate_host_or_range
from oscprecon.nmap_scan import network_scan_command
from oscprecon.profile import Profile

# --- CIDR range target model ----------------------------------------------------------------------


def test_is_cidr_range() -> None:
    assert is_cidr_range("10.10.5.0/24") is True
    assert is_cidr_range("10.10.0.0/16") is True
    assert is_cidr_range("10.10.5.5/32") is False  # single host written as CIDR
    assert is_cidr_range("10.10.5.5") is False
    assert is_cidr_range("box.htb") is False
    assert is_cidr_range("") is False


def test_validate_host_or_range_normalizes_network() -> None:
    assert validate_host_or_range("10.10.5.7/24") == "10.10.5.0/24"  # normalized to network addr
    assert validate_host_or_range("10.10.10.5") == "10.10.10.5"
    assert validate_host_or_range("box.htb") == "box.htb"


@pytest.mark.parametrize(
    "bad", ["10.10.5.0/33", "-oX x", "10.10.5.0/24 --script x", "$(id)/24", ""]
)
def test_validate_host_or_range_rejects_junk(bad: str) -> None:
    with pytest.raises(ValueError):
        validate_host_or_range(bad)


def test_target_range_flag() -> None:
    net = Target(ip="10.10.5.0/24")
    assert net.is_range is True
    assert net.ip == "10.10.5.0/24"
    host = Target(ip="10.10.10.5")
    assert host.is_range is False


def test_target_range_never_keeps_a_hostname() -> None:
    # a /24 network has no single vhost — every construction path (New Project builds Target
    # directly) must agree with Profile.set_target and drop the hostname.
    net = Target(ip="10.10.5.0/24", hostname="foo.htb")
    assert net.hostname is None
    assert net.host == "10.10.5.0/24"


# --- network scan command (a whole /24 Run Recon) -------------------------------------------------


def test_network_scan_command_is_versioned_and_policy_clean() -> None:
    for profile in ("quick", "default", "full", "exam"):
        cmd = network_scan_command("10.10.5.0/24", profile)
        argv = shlex.split(cmd)
        assert argv[0] == "nmap"
        assert "-sV" in argv  # each host lands with product/version
        assert "10.10.5.0/24" in cmd
        assert shell.policy_violation(argv) is None


# --- project rename + retarget --------------------------------------------------------------------


def test_profile_rename_moves_the_whole_folder(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "old-name", Target(ip="10.10.10.5"))
    (profile.directory / "notes.md").write_text("keep me", encoding="utf-8")
    new_dir = profile.rename("new-name")
    assert new_dir == tmp_path / "new-name"
    assert new_dir.is_dir()
    assert not (tmp_path / "old-name").exists()
    assert profile.profile_name == "new-name"
    assert profile.directory == new_dir
    assert (new_dir / "notes.md").read_text(encoding="utf-8") == "keep me"
    reloaded = Profile.load(new_dir)  # the moved profile still loads
    assert reloaded.profile_name == "new-name"
    assert reloaded.target.ip == "10.10.10.5"


def test_profile_rename_rejects_existing_name(tmp_path: Path) -> None:
    Profile.create(tmp_path, "taken", Target(ip="10.10.10.6"))
    profile = Profile.create(tmp_path, "src", Target(ip="10.10.10.7"))
    with pytest.raises(FileExistsError):
        profile.rename("taken")
    assert profile.directory == tmp_path / "src"  # unchanged on failure


@pytest.mark.parametrize("bad", ["", "a/b", "../evil", ".hidden"])
def test_profile_rename_rejects_bad_names(tmp_path: Path, bad: str) -> None:
    profile = Profile.create(tmp_path, "src", Target(ip="10.10.10.8"))
    with pytest.raises(ValueError):
        profile.rename(bad)


def test_profile_set_target_updates_ip_and_hostname(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    profile.set_target("10.10.10.9", "box.htb")
    assert profile.target.ip == "10.10.10.9"
    assert profile.target.hostname == "box.htb"
    reloaded = Profile.load(profile.directory)
    assert reloaded.target.ip == "10.10.10.9"
    assert reloaded.target.hostname == "box.htb"


def test_profile_set_target_to_range_drops_hostname(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "b", Target(ip="10.10.10.5", hostname="box.htb"))
    profile.set_target("10.10.5.0/24", "box.htb")
    assert profile.target.ip == "10.10.5.0/24"
    assert profile.target.hostname is None  # a /24 network has no single vhost
    assert profile.target.is_range is True


def test_profile_set_target_rejects_injection(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "b", Target(ip="10.10.10.5"))
    with pytest.raises(ValueError):
        profile.set_target("10.10.10.5;whoami")
    assert profile.target.ip == "10.10.10.5"  # unchanged
