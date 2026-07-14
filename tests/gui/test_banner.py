from pytestqt.qtbot import QtBot

from oscprecon.gui.theme import tokens
from oscprecon.gui.widgets.banner import Banner
from oscprecon.gui.widgets.tool_panel import ToolPanel


def test_banner_shows_kind_and_clears(qtbot: QtBot) -> None:
    banner = Banner("dark")
    qtbot.addWidget(banner)
    assert banner.isHidden()  # hidden until there's something to say
    banner.show_message("error", "[blocked] hydra is spray-only")
    assert not banner.isHidden()
    assert tokens.DARK.error in banner._msg.styleSheet()  # error-coloured
    assert banner._mark.text() == "✕"
    banner.clear()
    assert banner.isHidden() and banner._msg.text() == ""


def test_tool_panel_surfaces_tagged_lines_only(qtbot: QtBot) -> None:
    tp = ToolPanel()
    qtbot.addWidget(tp)
    tp.set_theme("dark")
    assert tp._banner.isHidden()

    tp.append_output("nmap scan report for 10.10.10.5")  # raw tool output -> no banner
    assert tp._banner.isHidden()

    tp.append_output("[blocked] credential brute is Spray-mode only (§2a)")
    assert not tp._banner.isHidden()
    assert tokens.DARK.error in tp._banner._msg.styleSheet()

    tp.append_output("[done] SMB recon complete")  # a later outcome updates the banner
    assert tokens.DARK.success in tp._banner._msg.styleSheet()

    tp.append_output("22/tcp open ssh")  # untagged again -> banner unchanged (still success)
    assert not tp._banner.isHidden()
