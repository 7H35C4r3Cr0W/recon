from pytestqt.qtbot import QtBot

from oscprecon.gui.widgets.reference_pane import ReferencePane
from oscprecon.models import DiscoveredService, Proto
from oscprecon.references import ServiceRef

_SMB_URL = "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smb/index.html"


def _ref(module: str, url: str) -> ServiceRef:
    return ServiceRef(label=module.upper(), hacktricks=url, module=module, tools=[])


def test_offline_hacktricks_renders_for_vendored_service(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "microsoft-ds"), _ref("smb", _SMB_URL))
    text = pane.offline_text()
    assert "445" in text and "SMB" in text  # rendered offline content
    assert "{{#include" not in text  # banner directives already stripped at vendor time
    assert pane._tabs.currentIndex() == pane._offline_index  # offline-first default
    assert "book.hacktricks.wiki" in pane._link.text()  # live link still shown to view yourself


def test_no_offline_page_falls_back_to_live_tab(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    # vhost has no vendored HackTricks page
    pane.show_service(DiscoveredService(80, Proto.TCP, "http"), _ref("vhost", _SMB_URL))
    assert pane._tabs.currentIndex() == pane._live_index
    assert "No offline HackTricks page" in pane.offline_text()


def test_clear_on_no_service(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL))
    pane.show_service(None, None)  # deselect
    assert pane.offline_text() == ""
