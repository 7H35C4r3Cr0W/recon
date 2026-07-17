import pytest

from oscprecon import guide


def test_every_topic_has_a_loadable_nontrivial_page() -> None:
    topics = guide.topics()
    assert len(topics) >= 6
    ids = [t.id for t in topics]
    assert len(ids) == len(set(ids)), "topic ids must be unique"
    for topic in topics:
        assert topic.title and topic.summary
        md = guide.load(topic.id)
        assert md.lstrip().startswith("#"), f"{topic.id} should open with a heading"
        assert len(md) > 200, f"{topic.id} looks too thin to be useful"


def test_first_topic_is_overview() -> None:
    assert guide.topics()[0].id == "overview"


def test_load_unknown_topic_raises() -> None:
    with pytest.raises(KeyError):
        guide.load("does-not-exist")


def test_resolve_by_id_title_and_prefix() -> None:
    assert guide.resolve("overview") is guide.get("overview")
    assert guide.resolve("Overview").id == "overview"  # case-insensitive
    assert guide.resolve("getting").id == "getting-started"  # id prefix
    assert guide.resolve("Keyboard").id == "shortcuts"  # title prefix
    assert guide.resolve("nope-nope") is None
