from oscprecon.references import hashcat as hc


def test_modes_load_across_categories() -> None:
    modes = hc.load_modes()
    assert len(modes) >= 100
    assert len({m.category for m in modes}) >= 10
    # every mode number is a positive int; names non-empty
    for m in modes:
        assert m.mode >= 0 and m.name


def test_search_finds_by_name_number_category() -> None:
    assert any(m.mode == 1600 for m in hc.search("apr1"))  # Apache/htpasswd
    assert any(m.mode == 1800 for m in hc.search("shadow"))  # sha512crypt
    assert any(m.mode == 13100 for m in hc.search("kerberos"))  # Kerberoast
    assert any(m.mode == 1000 for m in hc.search("1000"))  # by number
    assert hc.search("") == hc.load_modes()  # empty = all
    assert hc.search("zzzznope") == []


def test_build_command_per_attack_mode() -> None:
    assert (
        hc.build_command(1600, attack="0", hashfile="h", wordlist="rock")
        == "hashcat -m 1600 -a 0 h rock"
    )
    assert hc.build_command(0, attack="3", hashfile="h", mask="?a?a") == "hashcat -m 0 -a 3 h ?a?a"
    assert "-r best64" in hc.build_command(
        1000, attack="0", hashfile="h", wordlist="w", rules="best64"
    )


def test_gui_dialog_smoke() -> None:
    import pytest

    qtw = pytest.importorskip("PySide6.QtWidgets")
    app = qtw.QApplication.instance() or qtw.QApplication([])
    from oscprecon.gui.dialogs.hashcat_helper import HashcatHelperDialog

    d = HashcatHelperDialog(initial="apr1")
    d._rebuild()
    assert "-m 1600" in d._command.toPlainText()
    app.processEvents()
