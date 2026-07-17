from typer.testing import CliRunner

from oscprecon import guide
from oscprecon.cli import app

runner = CliRunner()


def test_docs_with_no_topic_lists_every_topic() -> None:
    result = runner.invoke(app, ["docs"])
    assert result.exit_code == 0
    for topic in guide.topics():
        assert topic.id in result.output


def test_docs_prints_a_topic_as_markdown() -> None:
    # CliRunner is non-tty, so the command prints the raw markdown (clean for scripts)
    result = runner.invoke(app, ["docs", "graph"])
    assert result.exit_code == 0
    assert "attack-surface graph" in result.output.lower()


def test_docs_resolves_a_title_or_id_prefix() -> None:
    result = runner.invoke(app, ["docs", "getting"])
    assert result.exit_code == 0
    assert "Getting started" in result.output


def test_docs_unknown_topic_exits_nonzero() -> None:
    result = runner.invoke(app, ["docs", "nonsense-xyz"])
    assert result.exit_code == 1
