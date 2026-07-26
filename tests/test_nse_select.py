"""The §2 gate judges an `--script` selector by what it SELECTS, not by how it is spelled.

`smb-* and vuln` selects zero credential-brute scripts precisely because of the conjunction, and it
is the form that catches vulnerability scripts whose filename has no "vuln" in it. A lexical check
could not tell it apart from bare `smb-*` (which does select smb-brute), so it refused both — and
the operator lost checks they should have had. These tests pin the evaluator to nmap's own answer.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from oscprecon import nmap_nse, nse_select, shell

_SCRIPT_DB = Path("/usr/share/nmap/scripts/script.db")
_needs_nmap_db = pytest.mark.skipif(not _SCRIPT_DB.exists(), reason="nmap script.db not installed")


# --- the evaluator matches nmap ------------------------------------------------------------------


def _nmap_selection(selector: str) -> set[str]:
    out = subprocess.run(  # noqa: S603 - fixed verb, selector from the test table
        ["nmap", "--script-help", selector],
        capture_output=True,
        text=True,
        check=False,
    )
    names: set[str] = set()
    for line in out.stdout.splitlines():
        stripped = line.strip()
        if stripped and not line.startswith((" ", "\t")) and " " not in stripped:
            head = stripped.startswith(("http", "Starting", "Categories"))
            if not head or "-" in stripped:
                names.add(stripped)
    return {n for n in names if not n.startswith("https")}


@_needs_nmap_db
@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed")
@pytest.mark.parametrize(
    "selector",
    [
        "smb-* and vuln",
        "(smb-* or smb2-*) and vuln",
        "ftp-* and (safe or discovery)",
        "vuln and not *vulners*",
        "http-* and auth",
        "mysql-* and (safe or discovery or auth or vuln) and not brute",
    ],
)
def test_the_evaluator_agrees_with_nmap(selector: str) -> None:
    # the whole gate rests on this: if our idea of "what this selects" drifts from nmap's, the
    # policy is either blocking legitimate recon or waving through a credential attack.
    assert set(nse_select.selected(selector)) == _nmap_selection(selector)


# --- grammar -------------------------------------------------------------------------------------


@_needs_nmap_db
def test_a_conjunction_narrows_a_glob() -> None:
    broad = set(nse_select.selected("smb-*"))
    narrowed = set(nse_select.selected("smb-* and vuln"))
    assert narrowed < broad
    assert "smb-brute" in broad and "smb-brute" not in narrowed


@_needs_nmap_db
def test_a_comma_is_a_union_not_part_of_the_boolean() -> None:
    both = set(nse_select.selected("smb-os-discovery,ftp-anon"))
    assert both == {"smb-os-discovery", "ftp-anon"}


@_needs_nmap_db
def test_not_and_parentheses() -> None:
    assert "smb-brute" not in nse_select.selected("smb-* and not brute")
    assert set(nse_select.selected("(ftp-anon or ftp-syst)")) == {"ftp-anon", "ftp-syst"}


def test_a_malformed_expression_is_reported_not_guessed() -> None:
    for bad in ("smb-* and", "(vuln", "vuln)", "and vuln"):
        with pytest.raises(nse_select.SelectorError):
            nse_select.selected(bad)


def test_a_directory_selector_is_refused_rather_than_modelled() -> None:
    with pytest.raises(nse_select.SelectorError):
        nse_select.selected("/usr/share/nmap/scripts/")


def test_it_works_without_a_script_db(tmp_path: Path) -> None:
    # a dev/CI box with no nmap must still evaluate deterministically, not crash
    missing = tmp_path / "nope.db"
    assert nse_select.selected("smb-* and vuln", missing)


# --- the policy the evaluator backs ---------------------------------------------------------------


def _violation(selector: str) -> str | None:
    return shell.policy_violation(shlex.split(f'nmap -p 445 --script "{selector}" 10.10.10.5'))


@_needs_nmap_db
@pytest.mark.parametrize(
    "selector",
    [
        "smb-* and vuln",
        "(smb-* or smb2-*) and vuln",
        "ftp-* and (default or safe or discovery or version) "
        "and not (brute or dos or exploit or intrusive or fuzzer)",
        "http-* and auth",
        "mysql-* and (safe or discovery or auth or vuln) and not brute",
        "vuln and not *vulners*",
        "smb-vuln-*",
        "default",
    ],
)
def test_the_forms_an_operator_types_are_allowed(selector: str) -> None:
    assert _violation(selector) is None, selector


@_needs_nmap_db
@pytest.mark.parametrize(
    "selector",
    [
        "smb-*",  # selects smb-brute
        "all",
        "brute",
        "intrusive",
        "ssh-* and brute",
        "vuln",  # selects vulners, which queries vulners.com with the target's version
        "shodan-api",
    ],
)
def test_a_selection_containing_a_credential_attack_or_a_third_party_lookup_is_refused(
    selector: str,
) -> None:
    assert _violation(selector) is not None, selector


@_needs_nmap_db
def test_the_refusal_names_the_script_and_how_to_fix_it() -> None:
    # §24: never refuse silently, and never refuse without saying what to do instead
    message = _violation("vuln")
    assert message is not None
    assert "vulners" in message
    assert "not (" in message  # it shows the exclusion to add


@_needs_nmap_db
def test_the_single_dash_form_is_gated_too() -> None:
    assert shell.policy_violation(shlex.split("nmap -p 22 -script smb-* 10.10.10.5")) is not None


@_needs_nmap_db
def test_dns_subdomain_brute_is_recon_not_a_credential_attack() -> None:
    # §10 lists DNS subdomain brute-forcing (dnsrecon -t brt, gobuster dns) as allowed recon —
    # refusing nmap's equivalent was inconsistent. A PASSWORD iterator stays blocked.
    assert "dns-brute" not in nmap_nse.brute_script_names()
    assert _violation("dns-brute") is None
    assert _violation("ssh-brute") is not None


@_needs_nmap_db
def test_every_category_the_picker_offers_actually_runs() -> None:
    # a picker entry that the policy then refuses is a dead control — the operator picks it, presses
    # Run, and gets a refusal for something the app itself suggested.
    offered = [c for c in nmap_nse.list_scripts() if " " in c or c in ("default", "version")]
    assert offered
    for selector in offered:
        assert _violation(selector) is None, selector
