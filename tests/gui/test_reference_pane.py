from pytestqt.qtbot import QtBot

from oscprecon import hacktricks
from oscprecon.gui.widgets.reference_pane import _FINDING_SECTIONS, ReferencePane
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


def test_finding_aware_jump_sets_hint(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    findings = [{"module": "smb", "kind": "auth", "value": "null session"}]
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL), findings)
    assert "Server Enumeration" in pane._jump_hint.text()  # jumped to the matching section
    assert pane._offline.textCursor().hasSelection()  # the section is selected/scrolled to


def test_no_findings_no_jump_hint(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL), [])
    assert pane._jump_hint.text() == ""


def test_section_for_findings_maps_kind() -> None:
    assert (
        ReferencePane._section_for_findings("smb", [{"kind": "share"}])
        == "Shared Folders Enumeration"
    )
    assert ReferencePane._section_for_findings("ftp", [{"kind": "auth"}]) == "Anonymous login"
    assert ReferencePane._section_for_findings("smb", [{"kind": "unknown"}]) == ""


def test_find_box_jumps_to_text(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL))
    pane._find.setText("Shared Folders")
    pane._find_next()
    assert pane._offline.textCursor().hasSelection()


def test_finding_sections_keywords_exist_in_cleaned_pages() -> None:
    # guard: every section-map keyword must exist in its module's (cleaned) vendored page, so the
    # finding-aware jump lands somewhere real — catches a keyword drifting out on a future refresh.
    for module, kinds in _FINDING_SECTIONS.items():
        page = hacktricks.page_for_module(module)
        assert page is not None, f"{module} has a section map but no vendored page"
        text = hacktricks.clean_markdown(page.markdown).lower()
        for kind, keyword in kinds.items():
            assert keyword.lower() in text, f"{module}/{kind}: '{keyword}' not found in page"


def test_offline_render_strips_mdbook_callouts(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL))
    text = pane.offline_text()
    assert "[!TIP]" not in text  # GitHub callout normalized, not shown raw
    assert "<summary>" not in text and "<details>" not in text
