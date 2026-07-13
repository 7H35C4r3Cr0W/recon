"""Multi-version + partial-extraction resilience.

Goal beyond "does not crash": when a tool's output drifts across versions (or a row is truncated /
malformed), the parser must still extract every row it CAN recognise and silently drop only the
unknown part. Every input form below is a real tool-output shape (documented format variants), not
fabricated. Control characters must never leak; auth-tool secrets must never reach findings.
"""

from oscprecon.models import Proto
from oscprecon.modules.http.parsers import (
    parse_feroxbuster,
    parse_ffuf,
    parse_gobuster,
    parse_whatweb,
)
from oscprecon.modules.nmap import NmapModule
from oscprecon.modules.smb.parsers import netexec_auth_ok, parse_netexec_users

_CTRL = "".join(chr(c) for c in (0, 1, 7, 27))


# ---- whatweb: single-array vs NDJSON (the drift that returned zero findings) -------------------


def test_whatweb_ndjson_and_array_variants_both_parse() -> None:
    ndjson = (
        '{"target":"http://t/","http_status":200,"plugins":{"nginx":[],"PHP":[]}}\n'
        '{"target":"http://t/admin","http_status":403,"plugins":{"Apache":[]}}\n'
    )
    array = '[{"target":"http://t/","http_status":200,"plugins":{"nginx":[]}}]'
    assert [f.status for f in parse_whatweb(ndjson, 80)] == [200, 403]  # NDJSON variant
    assert len(parse_whatweb(array, 80)) == 1  # single-array variant


def test_whatweb_skips_a_malformed_ndjson_row_between_valid_ones() -> None:
    text = (
        '{"target":"http://t/","http_status":200,"plugins":{"nginx":[]}}\n'
        "GARBAGE not-json line from a truncated write\n"
        '{"target":"http://t/api","http_status":500,"plugins":{}}\n'
    )
    findings = parse_whatweb(text, 80)
    assert [f.status for f in findings] == [200, 500]  # bad row dropped, the two valid kept


# ---- ffuf: JSON type drift + malformed rows ---------------------------------------------------


def test_ffuf_tolerates_changed_types_and_bad_rows() -> None:
    text = (
        '{"results":['
        '{"url":"http://t/a","status":"200","length":"1234"},'  # status/length as STRINGS (drift)
        '"a-bare-string-not-an-object",'  # malformed row
        '{"url":"http://t/b","status":301,"length":0}'  # valid
        "]}"
    )
    findings = parse_ffuf(text, 80)
    paths = {f.path for f in findings}
    assert "/a" in paths and "/b" in paths  # both real rows extracted
    a = next(f for f in findings if f.path == "/a")
    assert a.status == 200 and a.size == 1234  # string ints coerced, not crashed


def test_ffuf_corrupt_json_degrades_to_empty() -> None:
    assert parse_ffuf('{"results":[', 80) == []  # truncated doc -> no crash, no findings


# ---- feroxbuster: NDJSON mixed with non-response rows + garbage --------------------------------


def test_feroxbuster_mixed_ndjson_extracts_only_responses() -> None:
    text = (
        '{"type":"response","url":"http://t/x","status":200,"content_length":10}\n'
        '{"type":"statistics","requests":500}\n'  # a non-response record (drift/noise)
        "not json at all\n"
        '{"type":"response","url":"http://t/y","status":301,"content_length":0,'
        '"headers":{"location":"/z"}}\n'
    )
    findings = parse_feroxbuster(text, 80)
    assert {f.path for f in findings} == {"/x", "/y"}
    assert next(f for f in findings if f.path == "/y").redirect_to == "/z"


# ---- gobuster: banner/blank/garbage lines between valid rows -----------------------------------


def test_gobuster_keeps_valid_rows_amongst_noise() -> None:
    text = (
        "===============================================================\n"
        "Gobuster v3.6\n"  # banner noise
        "/admin                (Status: 301) [Size: 312] [--> /admin/]\n"
        "\x1b[2Kprogress junk line\n"
        "/config.php           (Status: 200) [Size: 1024]\n"
    )
    findings = parse_gobuster(text, 80)
    assert {f.path for f in findings} == {"/admin", "/config.php"}


# ---- nmap: garbage / truncated lines interspersed with a real port table ----------------------


def test_nmap_extracts_valid_ports_around_truncated_lines() -> None:
    text = (
        "Starting Nmap 7.94 ( https://nmap.org )\n"
        "PORT     STATE SERVICE VERSION\n"
        "22/tcp   open  ssh     OpenSSH 8.4p1\n"
        "80/tcp   ope\n"  # truncated line mid-write
        "445/tcp  open  microsoft-ds Samba smbd 4.13\n"
        "garbage line that is not a port\n"
    )
    services = {(s.port, s.proto): s for s in NmapModule().discovered_services({"scan.txt": text})}
    assert (22, Proto.TCP) in services and (445, Proto.TCP) in services  # valid ports survive
    assert "OpenSSH" in services[(22, Proto.TCP)].product


# ---- netexec / crackmapexec: --users with and without a domain prefix (version drift) ----------


def test_netexec_users_parse_across_prefix_variants() -> None:
    with_domain = (
        "SMB 10.0.0.1 445 DC [*] Enumerated domain user(s)\n"
        "SMB 10.0.0.1 445 DC CORP\\administrator                 badpwdcount: 0\n"
        "SMB 10.0.0.1 445 DC CORP\\svc_sql                       badpwdcount: 0\n"
    )
    users = {f.value for f in parse_netexec_users(with_domain)}
    assert "administrator" in users and "svc_sql" in users


def test_netexec_output_never_leaks_a_secret_into_findings() -> None:
    # a valid-login line carries the password; the parser must confirm auth WITHOUT surfacing it
    line = "SMB 10.0.0.1 445 DC [+] CORP\\administrator:Sup3rSecret! (Pwn3d!)"
    assert netexec_auth_ok(line) is True
    findings = parse_netexec_users(line)
    assert all("Sup3rSecret!" not in f.value and "Sup3rSecret!" not in f.detail for f in findings)


# ---- control characters must not leak from any of the line parsers -----------------------------


def test_control_chars_do_not_leak_from_parsers() -> None:
    noisy = f"/admin{_CTRL}                (Status: 200) [Size: 5]\n"
    findings = parse_gobuster(noisy, 80)
    assert findings and all(not any(ch in f.path for ch in _CTRL) for f in findings)
    assert findings[0].path == "/admin"  # control bytes stripped from the path
    # feroxbuster NDJSON followed by a control-byte garbage line must not crash, still one finding
    ferox = '{"type":"response","url":"http://t/ok","status":200,"content_length":1}\n'
    assert len(parse_feroxbuster(ferox + _CTRL + "\n", 80)) == 1
