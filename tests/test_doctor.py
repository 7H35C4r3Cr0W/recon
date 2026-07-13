import pytest

from oscprecon import doctor


def test_scan_marks_present_and_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor.shutil, "which", lambda t: "/usr/bin/nmap" if t == "nmap" else None)
    report = doctor.scan()
    assert {t.name for t in report.found} == {"nmap"}
    assert report.missing and all(t.hint for t in report.missing)


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
