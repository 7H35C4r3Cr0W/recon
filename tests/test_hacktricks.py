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
