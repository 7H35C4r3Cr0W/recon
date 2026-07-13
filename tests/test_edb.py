from pathlib import Path

from oscprecon import edb
from oscprecon.references import ExploitHit


def _hit(edb_id: str, title: str = "example", path: str = "linux/remote/x.py") -> ExploitHit:
    return ExploitHit(
        edb_id=edb_id,
        title=title,
        url=f"https://www.exploit-db.com/exploits/{edb_id}",
        path=path,
    )


def test_add_and_load_roundtrip(tmp_path: Path) -> None:
    edb.add_edb(
        tmp_path,
        service="22/tcp ssh",
        product="OpenSSH",
        version="7.2",
        hits=[_hit("40136", "OpenSSH user enum")],
    )
    rows = edb.load_edb(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["edb_id"] == "40136"
    assert (
        row["service"] == "22/tcp ssh" and row["product"] == "OpenSSH" and row["version"] == "7.2"
    )
    assert row["url"].endswith("/40136")
    assert "path" not in row  # lookup-only: the local PoC path is NEVER persisted


def test_dedup_on_reselect(tmp_path: Path) -> None:
    hits = [_hit("40136")]
    edb.add_edb(tmp_path, service="s", product="OpenSSH", version="7.2", hits=hits)
    edb.add_edb(tmp_path, service="s", product="OpenSSH", version="7.2", hits=hits)  # same query
    assert len(edb.load_edb(tmp_path)) == 1


def test_distinct_versions_kept(tmp_path: Path) -> None:
    edb.add_edb(tmp_path, service="s", product="OpenSSH", version="7.2", hits=[_hit("1")])
    edb.add_edb(tmp_path, service="s", product="OpenSSH", version="8.0", hits=[_hit("1")])
    assert len(edb.load_edb(tmp_path)) == 2  # same EDB-ID, different version query → distinct


def test_empty_hits_writes_no_file(tmp_path: Path) -> None:
    edb.add_edb(tmp_path, service="s", product="x", version="", hits=[])
    assert not edb.edb_path(tmp_path).exists()


def test_corrupt_edb_json_degrades(tmp_path: Path) -> None:
    edb.edb_path(tmp_path).write_text("{not json", encoding="utf-8")
    assert edb.load_edb(tmp_path) == []
