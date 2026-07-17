from oscprecon.modules.zookeeper import parse_nmap_zookeeper, parse_zk_4lw


def test_parse_nmap_sv_with_version() -> None:
    out = parse_nmap_zookeeper("2181/tcp open  zookeeper  Zookeeper 3.4.6\n")
    kinds = {f.kind: f.value for f in out}
    assert kinds.get("access") == "reachable"
    assert kinds.get("version") == "3.4.6"


def test_parse_nmap_sv_no_version() -> None:
    out = parse_nmap_zookeeper("2181/tcp open  zookeeper\n")
    assert [f.kind for f in out] == ["access"]


def test_parse_nmap_ignores_unrelated_lines() -> None:
    assert parse_nmap_zookeeper("22/tcp open ssh OpenSSH 8.4\n") == []


def test_parse_mntr() -> None:
    text = "zk_version\t3.4.6-1569965\nzk_server_state\tleader\nzk_znode_count\t127\n"
    kinds = {f.kind: f.value for f in parse_zk_4lw(text)}
    assert kinds["access"] == "unauth"
    assert kinds["version"] == "3.4.6"
    assert kinds["mode"] == "leader"
    assert kinds["znodes"] == "127"


def test_parse_stat() -> None:
    text = "Zookeeper version: 3.5.7\nClients:\n /10.0.0.5:527[0]\nMode: standalone\n"
    kinds = {f.kind: f.value for f in parse_zk_4lw(text)}
    assert kinds["version"] == "3.5.7"
    assert kinds["mode"] == "standalone"
    assert kinds["access"] == "unauth"


def test_parse_4lw_no_signal() -> None:
    assert parse_zk_4lw("some unrelated garbage\n") == []
