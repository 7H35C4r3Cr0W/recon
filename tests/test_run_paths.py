from __future__ import annotations

from pathlib import Path

from oscprecon import run_paths


def test_distinct_commands_get_distinct_scan_files(tmp_path: Path) -> None:
    # the bug this exists to stop: a preset scan and the versioned battery scan both wrote
    # nmap/tcp-versioned.txt, so with scans running in parallel each parsed the other's output.
    full = run_paths.scan_output(tmp_path, "nmap -sT -p- 10.10.10.100", "10.10.10.100")
    vuln = run_paths.scan_output(
        tmp_path, 'nmap -Pn -sV -p 445 --script "vuln" 10.10.10.100', "10.10.10.100"
    )
    assert full != vuln


def test_the_same_command_keeps_the_same_file(tmp_path: Path) -> None:
    # stable per command, so a re-run overwrites its own output and --resume/history stay meaningful
    command = "nmap -sT -p- 10.10.10.100"
    assert run_paths.scan_output(tmp_path, command, "10.10.10.100") == run_paths.scan_output(
        tmp_path, command, "10.10.10.100"
    )


def test_claim_refuses_a_second_owner(tmp_path: Path) -> None:
    path = tmp_path / "http" / "80" / "feroxbuster-big.txt"
    assert run_paths.claim(path, "http:80 #1") is None
    assert run_paths.claim(path, "http:80 #2") == "http:80 #1"
    run_paths.release(path)
    assert run_paths.claim(path, "http:80 #2") is None
    run_paths.release(path)


def test_claim_is_idempotent_for_its_own_owner(tmp_path: Path) -> None:
    path = tmp_path / "a.txt"
    assert run_paths.claim(path, "tag") is None
    assert run_paths.claim(path, "tag") is None  # re-claiming your own path is not a conflict
    run_paths.release(path)


def test_claims_compare_on_the_resolved_path(tmp_path: Path) -> None:
    path = tmp_path / "nmap" / "out.txt"
    path.parent.mkdir(parents=True)
    assert run_paths.claim(path, "one") is None
    assert run_paths.claim(tmp_path / "nmap" / "." / "out.txt", "two") == "one"
    run_paths.release_tag("one")


def test_release_tag_frees_every_path_a_run_held(tmp_path: Path) -> None:
    run_paths.claim(tmp_path / "a.txt", "run #1")
    run_paths.claim(tmp_path / "b.json", "run #1")
    run_paths.claim(tmp_path / "c.txt", "run #2")
    run_paths.release_tag("run #1")
    assert run_paths.owner_of(tmp_path / "a.txt") is None
    assert run_paths.owner_of(tmp_path / "b.json") is None
    assert run_paths.owner_of(tmp_path / "c.txt") == "run #2"
    run_paths.release_tag("run #2")


def test_disambiguate_only_fires_on_non_default_settings() -> None:
    assert (
        run_paths.disambiguate("http/80/feroxbuster-big.txt", "") == "http/80/feroxbuster-big.txt"
    )
    a = run_paths.disambiguate("http/80/feroxbuster-big.txt", "ext=php,asp")
    b = run_paths.disambiguate("http/80/feroxbuster-big.txt", "ext=txt")
    assert a != b != "http/80/feroxbuster-big.txt"
    assert a.startswith("http/80/feroxbuster-big-") and a.endswith(".txt")


def test_for_port_nests_and_is_idempotent() -> None:
    assert run_paths.for_port("snmp/onesixtyone.txt", 161) == "snmp/161/onesixtyone.txt"
    assert run_paths.for_port("snmp/161/onesixtyone.txt", 161) == "snmp/161/onesixtyone.txt"
    assert run_paths.for_port("snmp/onesixtyone.txt", 0) == "snmp/onesixtyone.txt"
    assert run_paths.for_port("report.md", 80) == "report.md"
