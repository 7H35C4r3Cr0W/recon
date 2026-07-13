from oscprecon import hacktricks


def test_index_loads_offline_with_expected_modules() -> None:
    index = hacktricks.load_index()
    assert len(index) >= 18  # the vendored bounded snapshot
    assert {"smb", "ssh", "ftp", "http", "kerberos", "redis", "ldap"} <= set(index)
    for entry in index.values():
        assert entry["url"].startswith("https://book.hacktricks.wiki/")  # live link to view


def test_page_for_module_returns_content_and_link() -> None:
    page = hacktricks.page_for_module("smb")
    assert page is not None
    assert page.title and page.markdown
    assert page.url.startswith("https://book.hacktricks.wiki/")
    assert "445" in page.markdown  # real SMB content, not a mismatched page


def test_unknown_module_is_none() -> None:
    assert hacktricks.page_for_module("does-not-exist") is None


def test_clean_markdown_normalizes_mdbook_syntax() -> None:
    src = (
        "> [!TIP]\n> use a null session\n\n"
        "<details>\n<summary>Cypher query</summary>\nMATCH (n) RETURN n\n</details>\n\n"
        "<figure><img src='https://x/y.png'></figure>\n"
        "plain body text\n"
    )
    out = hacktricks.clean_markdown(src)
    assert "[!TIP]" not in out and "**Tip**" in out  # callout -> bold label
    assert "<summary>" not in out and "**Cypher query**" in out  # summary -> bold heading
    assert "<details>" not in out and "</details>" not in out  # collapsible tags dropped
    assert "MATCH (n) RETURN n" in out  # ...but the details content is kept
    assert "<figure" not in out and "<img" not in out  # offline images removed
    assert "plain body text" in out  # ordinary content untouched


def test_clean_markdown_strips_raw_tokens_from_real_pages() -> None:
    for module in ("smb", "http"):
        page = hacktricks.page_for_module(module)
        assert page is not None
        out = hacktricks.clean_markdown(page.markdown)
        assert "[!TIP]" not in out and "[!WARNING]" not in out and "[!CAUTION]" not in out
        assert "<details>" not in out and "<summary>" not in out


def test_vendored_pages_are_clean_and_accurate() -> None:
    # every vendored page: non-empty, mdBook include/banner directives stripped, and — the accuracy
    # check — actually about its service (guards against a wrong module->file mapping).
    markers = {
        "smb": ("445", "SMB"),
        "ssh": ("SSH",),
        "ftp": ("FTP",),
        "kerberos": ("Kerberos",),
        "redis": ("Redis",),
        "mysql": ("MySQL",),
        "snmp": ("SNMP",),
    }
    for module in hacktricks.available_modules():
        page = hacktricks.page_for_module(module)
        assert page is not None and page.markdown.strip()
        assert "{{#include" not in page.markdown  # banner directives stripped
        for needle in markers.get(module, ()):
            assert needle in page.markdown, f"{module} page missing {needle!r}"
