from oscprecon import hacktricks


def test_page_and_clean_markdown_are_cached() -> None:
    # static vendored data -> repeated lookups reuse the cached result (reference-pane hot path)
    first = hacktricks.page_for_module("smb")
    second = hacktricks.page_for_module("smb")
    assert first is not None and first is second  # same object, no re-read

    cleaned_a = hacktricks.clean_markdown(first.markdown)
    cleaned_b = hacktricks.clean_markdown(first.markdown)
    assert cleaned_a is cleaned_b  # cached, no re-run of the regex passes

    # the index is loaded once and shared
    assert hacktricks.load_index() is hacktricks.load_index()


def test_cache_still_returns_correct_content() -> None:
    # caching must not change WHAT is returned
    page = hacktricks.page_for_module("smb")
    assert page is not None and page.module == "smb"
    assert "[!TIP]" not in hacktricks.clean_markdown(page.markdown)  # still cleaned
