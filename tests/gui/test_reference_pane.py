from pytestqt.qtbot import QtBot

from oscprecon import hacktricks
from oscprecon.gui.widgets.reference_pane import _FINDING_SECTIONS, ReferencePane
from oscprecon.models import DiscoveredService, Proto
from oscprecon.references import ServiceRef
from oscprecon.references.live_hacktricks import LiveResult

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


# ---- live HackTricks states --------------------------------------------------------------------


def test_live_disabled_by_default_refresh_button_off(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL))
    assert pane._refresh_btn.isEnabled() is False  # live fetching off by default
    pane.set_live_enabled(True)
    assert pane._refresh_btn.isEnabled() is True
    assert pane.current_ref_url() == _SMB_URL


def test_apply_live_result_renders_then_reverts(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL))
    result = LiveResult(
        "live-refreshed", "# Live SMB\n\nfresh live body", ["Live SMB"], 1.0e9, _SMB_URL
    )
    pane.apply_live_result(result)
    assert "fresh live body" in pane.offline_text()
    # isHidden (not isVisible) — the top-level window isn't shown in an offscreen test
    assert not pane._use_offline_btn.isHidden()
    assert pane._source_badge.text().strip() == "LIVE"  # colour-coded source tier
    assert not pane._source_badge.isHidden()
    pane._restore_offline()
    assert "fresh live body" not in pane.offline_text() and "445" in pane.offline_text()
    assert pane._use_offline_btn.isHidden()
    assert pane._source_badge.text().strip() == "OFFLINE"  # reverted to the reliable default


def test_apply_live_result_for_other_page_is_ignored(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL))
    other = "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ftp/index.html"
    stale = LiveResult("live-refreshed", "WRONG PAGE CONTENT", [], 1.0e9, other)
    pane.apply_live_result(stale)
    assert "WRONG PAGE CONTENT" not in pane.offline_text()  # url mismatch -> not applied


def test_live_fetch_error_keeps_offline_content(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL))
    pane.apply_live_result(LiveResult("error", "", [], 0.0, _SMB_URL, "refresh failed: down"))
    assert "445" in pane.offline_text()  # offline content intact after a failure
    assert "failed" in pane._source_state.text().lower()


def test_refresh_button_emits_signal(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL))
    pane.set_live_enabled(True)
    with qtbot.waitSignal(pane.refresh_requested, timeout=1000):
        pane._refresh_btn.click()


def test_live_content_applies_finding_aware_jump(qtbot: QtBot) -> None:
    pane = ReferencePane()
    qtbot.addWidget(pane)
    findings = [{"module": "smb", "kind": "auth", "value": "null session"}]
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL), findings)
    # live content that contains the finding's mapped section (smb auth -> Server Enumeration)
    md = "# SMB\n\n## Basic Info\n\nintro\n\n## Server Enumeration\n\nenumerate the server here\n"
    pane.apply_live_result(LiveResult("live-refreshed", md, [], 1.0e9, _SMB_URL))
    assert "Server Enumeration" in pane._jump_hint.text()  # jumped into the live content, not top
    assert pane._offline.textCursor().hasSelection()


def test_live_content_renders_no_dangerous_links(qtbot: QtBot) -> None:
    from oscprecon.references import live_hacktricks

    pane = ReferencePane()
    qtbot.addWidget(pane)
    pane.show_service(DiscoveredService(445, Proto.TCP, "smb"), _ref("smb", _SMB_URL))
    # a hostile page's literal link text, extracted and rendered exactly as the live path does
    md, _ = live_hacktricks.html_to_markdown(
        "<main><p>see [x](file:///etc/passwd) and [y](javascript:alert(1))</p></main>"
    )
    pane.apply_live_result(LiveResult("live-refreshed", md, [], 1.0e9, _SMB_URL))
    html = pane._offline.toHtml().lower()
    assert 'href="file:' not in html and 'href="javascript:' not in html  # no clickable link
    assert "file:///etc/passwd" in pane.offline_text()  # still shown as readable text
