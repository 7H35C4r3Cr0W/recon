from pathlib import Path

import pytest

from oscprecon.models import Port, Proto, Target
from oscprecon.modules.http import HttpModule
from oscprecon.profile import Profile


def test_target_host_prefers_hostname_over_ip() -> None:
    assert Target(ip="10.10.10.5").host == "10.10.10.5"  # no hostname -> IP
    assert Target(ip="10.10.10.5", hostname="box.htb").host == "box.htb"  # vhost wins


def test_http_probes_use_the_hostname_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    # commands() now falls back to the IP when the vhost name does NOT resolve (the unresolvable-
    # hostname fix); force it resolvable so this test deterministically exercises the hostname path
    # (a real DNS lookup of thetoppers.htb is non-deterministic across environments).
    import oscprecon.modules.http as httpmod

    monkeypatch.setattr(httpmod, "host_resolves", lambda _n: True)
    module = HttpModule()
    target = Target(ip="10.129.227.248", hostname="thetoppers.htb")
    lines = [c.shell_line for c in module.commands(target, [Port(80, Proto.TCP, "http")])]
    assert any("http://thetoppers.htb/" in line for line in lines)
    assert not any("10.129.227.248" in line for line in lines)  # IP not used for host-based probes


def test_set_hostname_persists_and_normalizes(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "three", Target(ip="10.129.227.248"))
    profile.set_hostname(" thetoppers.htb ")
    assert Profile.load(profile.directory).target.hostname == "thetoppers.htb"  # trimmed + saved
    profile.set_hostname("")  # blank clears it
    assert Profile.load(profile.directory).target.hostname is None


def test_set_hostname_rejects_a_hostile_value(tmp_path: Path) -> None:
    profile = Profile.create(tmp_path, "three", Target(ip="10.129.227.248"))
    with pytest.raises(ValueError):
        profile.set_hostname("bad host; rm -rf")  # validate_host guards argv-injection
    assert profile.target.hostname is None  # unchanged on rejection
