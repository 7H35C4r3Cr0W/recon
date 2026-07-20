from pathlib import Path

import pytest

from oscprecon import doctor


def test_scan_resources_reports_present_and_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    present = tmp_path / "here"
    present.mkdir()
    monkeypatch.setattr(
        doctor,
        "_RESOURCE_PATHS",
        (
            ("Present thing", str(present), "apt install x"),
            ("Missing thing", str(tmp_path / "nope"), "apt install y"),
        ),
    )
    checks = {c.name: c for c in doctor.scan_resources()}
    assert checks["Present thing"].ok is True
    assert checks["Missing thing"].ok is False
    assert checks["Missing thing"].detail == "apt install y"


def test_scan_system_flags_low_disk_and_missing_vpn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor, "_free_gb", lambda _p: 0.3)
    monkeypatch.setattr(doctor, "_vpn_up", lambda **_k: False)
    monkeypatch.setattr(doctor, "_nmap_can_raw", lambda: True)
    checks = {c.name: c for c in doctor.scan_system("/whatever")}
    assert checks["Workspace disk space"].ok is False
    assert "0.3 GB" in checks["Workspace disk space"].detail
    assert checks["VPN tunnel up (tun/tap)"].ok is False
    assert checks["Raw-socket scans (nmap -sS/-sU/-O)"].ok is True


def test_scan_system_unknown_disk_does_not_alarm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor, "_free_gb", lambda _p: -1.0)  # couldn't read the fs
    checks = {c.name: c for c in doctor.scan_system("/x")}
    assert checks["Workspace disk space"].ok is True  # unknown != a failure


def test_tool_version_only_probes_curated_present_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: "/usr/bin/nmap" if t == "nmap" else None)
    calls: list[list[str]] = []

    class _R:
        stdout = "Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64"
        stderr = ""

    def _fake_run(argv: list[str], **_kw: object) -> _R:
        calls.append(argv)
        return _R()

    monkeypatch.setattr(doctor.subprocess, "run", _fake_run)
    assert doctor.tool_version("nmap") == "Nmap version 7.94 ( https://nmap.org )"
    assert doctor.tool_version("gobuster") is None  # curated but not present (which -> None)
    assert doctor.tool_version("smbclient") is None  # present-agnostic: no curated probe -> skipped
    assert calls == [["nmap", "--version"]]  # only the present, curated tool was actually run


def test_versions_maps_present_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: "/x" if t == "nmap" else None)
    monkeypatch.setattr(doctor, "tool_version", lambda n: "7.94" if n == "nmap" else None)
    assert doctor.versions(doctor.scan()) == {"nmap": "7.94"}


def test_scan_marks_present_and_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: "/usr/bin/nmap" if t == "nmap" else None)
    report = doctor.scan()
    assert {t.name for t in report.found} == {"nmap"}
    assert report.missing and all(t.hint for t in report.missing)


def test_exploit_tools_reported_but_never_auto_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # §2b exploit-tab tools (evil-winrm/certipy/impacket-secretsdump/…) run in exploit mode, which
    # bypasses the recon allow-list, so the doctor must still report them — but as an informational
    # 'exploit' category that NEVER enters the apt auto-install plan (they span apt/pipx/gem).
    monkeypatch.setattr(doctor.shutil, "which", lambda t: None)  # everything missing
    report = doctor.scan()
    exploit = {t.name for t in report.exploit}
    assert {"evil-winrm", "certipy", "impacket-secretsdump", "responder"} <= exploit
    assert all(t.optional and t.category == "exploit" for t in report.exploit)
    # they must not inflate the "required" (recon) count or the auto-install package list
    assert exploit.isdisjoint({t.name for t in report.required})
    plan = doctor.install_plan(report)
    assert not any(
        n in p
        for n in ("evil-winrm", "certipy", "impacket-secretsdump", "responder")
        for p in plan.packages
    )


def test_install_plan_is_alternative_aware_and_separates_manual(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: None)  # all missing
    plan = doctor.install_plan(doctor.scan())
    assert len(plan.packages) == len(set(plan.packages))  # deduped
    assert "impacket-scripts" in plan.packages  # impacket-GetX.py collapse to one package
    assert "nmap" in plan.packages
    # a wholly-missing alternative group installs ONLY its preferred package — never the deprecated
    # or redundant alternatives (don't pull crackmapexec/python3-impacket when netexec/
    # impacket-scripts already cover them).
    assert "netexec" in plan.packages
    assert "crackmapexec" not in plan.packages
    assert "python3-impacket" not in plan.packages
    # a pipx/git tool is MANUAL, never in the apt package list
    assert "windapsearch" in {name for name, _ in plan.manual}
    assert not any("windapsearch" in p for p in plan.packages)


def test_effective_missing_skips_tools_covered_by_a_present_alternative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        doctor.shutil, "which", lambda t: "/usr/bin/netexec" if t == "netexec" else None
    )
    report = doctor.scan()
    names = {t.name for t in doctor.effective_missing(report)}
    assert not ({"nxc", "crackmapexec", "netexec"} & names)  # netexec present covers the group
    plan = doctor.install_plan(report)
    assert "crackmapexec" not in plan.packages and "netexec" not in plan.packages


def test_effective_missing_collapses_a_fully_missing_group_to_preferred(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: None)  # all missing
    names = {t.name for t in doctor.effective_missing(doctor.scan())}
    assert "netexec" in names  # the preferred member represents the group
    assert "nxc" not in names and "crackmapexec" not in names


def test_apt_package_extracts_only_a_safe_package_token() -> None:
    assert doctor._apt_package("apt install nmap") == "nmap"
    assert doctor._apt_package("apt install crackmapexec  (or use netexec)") == "crackmapexec"
    # non-apt hints are not auto-installable
    assert doctor._apt_package("pipx install windapsearch-py (or git clone ...)") is None
    assert doctor._apt_package("echo pwned") is None
    # SAFETY: even a hostile hint yields ONLY the package token — no shell metacharacters ride along
    assert doctor._apt_package("apt install nmap; rm -rf /") == "nmap"
    assert doctor._apt_package("apt install $(evil)") is None


def test_install_requires_confirmation() -> None:
    ran: list[list[str]] = []
    lines: list[str] = []
    code = doctor.install(
        doctor.InstallPlan(("nmap",), ()),
        confirm=lambda command: False,  # user declines
        runner=lambda argv: ran.append(argv) or 0,
        echo=lines.append,
    )
    assert code == 1 and ran == []  # nothing ran
    assert any("cancelled" in line for line in lines)


def test_install_runs_each_package_independently_on_confirm() -> None:
    ran: list[list[str]] = []
    code = doctor.install(
        doctor.InstallPlan(("nmap", "ffuf"), ()),
        confirm=lambda command: True,
        runner=lambda argv: ran.append(argv) or 0,
        echo=lambda _msg: None,
    )
    # one apt-get per package — a single batched call aborts entirely if one package is unavailable
    assert code == 0 and len(ran) == 2
    assert [argv[-3:] for argv in ran] == [["install", "-y", "nmap"], ["install", "-y", "ffuf"]]


def test_install_continues_past_an_unavailable_package() -> None:
    ran: list[str] = []
    lines: list[str] = []

    def _runner(argv: list[str]) -> int:
        pkg = argv[-1]
        ran.append(pkg)
        return 100 if pkg == "crackmapexec" else 0  # apt "unable to locate package"

    code = doctor.install(
        doctor.InstallPlan(("crackmapexec", "nmap"), ()),
        assume_yes=True,
        runner=_runner,
        echo=lines.append,
    )
    # the unavailable package does NOT abort the run — nmap is still attempted and installed
    assert ran == ["crackmapexec", "nmap"]
    assert code == 1  # non-zero because one failed
    assert any("nmap" in line and "installed" in line for line in lines)


def test_install_empty_plan_is_a_noop() -> None:
    def _boom(argv: list[str]) -> int:
        raise AssertionError("runner must not be called for an empty plan")

    assert doctor.install(doctor.InstallPlan((), ()), runner=_boom, echo=lambda _m: None) == 0


def test_install_handles_missing_apt_binary() -> None:
    # non-Kali host: the runner raises FileNotFoundError — install must NOT crash, and must tell the
    # user the command to run themselves.
    def _no_apt(argv: list[str]) -> int:
        raise FileNotFoundError("apt-get")

    lines: list[str] = []
    code = doctor.install(
        doctor.InstallPlan(("nmap",), ()),
        assume_yes=True,
        runner=_no_apt,
        echo=lines.append,
    )
    assert code == 1
    assert any("run it yourself" in line for line in lines)


def test_assume_yes_skips_confirmation() -> None:
    ran: list[list[str]] = []
    code = doctor.install(
        doctor.InstallPlan(("nmap",), ()),
        assume_yes=True,
        confirm=None,  # no prompt provided; --yes must not require one
        runner=lambda argv: ran.append(argv) or 0,
        echo=lambda _m: None,
    )
    assert code == 0 and len(ran) == 1


def test_scan_includes_spray_tools_as_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: None)  # all missing
    report = doctor.scan()
    optional = {t.name for t in report.optional}
    assert "hydra" in optional and "medusa" in optional
    assert all(t.optional for t in report.optional)
    assert "hydra" not in {t.name for t in report.required}  # not counted among required tools


def test_install_plan_excludes_optional_spray_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: None)  # all missing
    plan = doctor.install_plan(doctor.scan())
    # a recon-only user must never be auto-pushed hydra/medusa (Spray mode is opt-in / off default)
    assert "hydra" not in plan.packages and "medusa" not in plan.packages
    assert "hydra" not in {name for name, _ in plan.manual}
