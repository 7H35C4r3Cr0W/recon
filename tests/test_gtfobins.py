from oscprecon.references import gtfobins


def test_gtfobins_dataset_loads() -> None:
    bins = gtfobins.load_gtfobins()
    assert len(bins) > 40
    names = {b.name for b in bins}
    for essential in ("find", "vim", "tar", "python", "bash"):
        assert essential in names


def test_get_returns_binary_with_techniques() -> None:
    f = gtfobins.get("find")
    assert f is not None
    assert "sudo" in f.functions and "suid" in f.functions
    assert f.url == "https://gtfobins.github.io/gtfobins/find/"
    assert any("find" in t.code for t in f.techniques)


def test_search_matches_name_function_and_code() -> None:
    # exact-name match is first
    assert gtfobins.search("tar")[0].name == "tar"
    # by function
    sudoable = {b.name for b in gtfobins.search("sudo")}
    assert "find" in sudoable and "vim" in sudoable
    caps = {b.name for b in gtfobins.search("capabilities")}
    assert {"python", "perl", "gdb"} <= caps
    # empty query returns all, sorted
    everything = gtfobins.search("")
    assert len(everything) == len(gtfobins.load_gtfobins())
    assert [b.name for b in everything] == sorted(b.name for b in everything)


def test_no_match_returns_empty() -> None:
    assert gtfobins.search("definitely-not-a-real-binary-xyz") == []
