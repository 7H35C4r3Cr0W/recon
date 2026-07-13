from oscprecon.references import sections

_MD = """intro preamble text

## Basic Information
general service info

## Server Enumeration
enumerate the server here

```bash
smbclient -L //t/
## not a real heading inside a code fence
echo done
```

## Apache Tricks
apache-specific content, version 2.4.49 mentioned here

## Shared Folders Enumeration
list the shares
"""


def test_split_sections_is_fence_aware_and_keeps_code_whole():
    secs = sections.split_sections(_MD)
    headings = [s.heading for s in secs]
    assert "Basic Information" in headings and "Server Enumeration" in headings
    # a heading-looking line INSIDE the code fence must NOT become a section
    assert "not a real heading inside a code fence" not in headings
    server = next(s for s in secs if s.heading == "Server Enumeration")
    assert "smbclient -L //t/" in server.body and server.body.count("```") == 2  # fences balanced


def test_relevant_prioritizes_finding_then_product():
    secs = sections.relevant_sections(_MD, keywords=["Server Enumeration"], product="Apache")
    assert secs[0].heading == "Server Enumeration"  # finding-kind heading wins
    assert any(s.heading == "Apache Tricks" for s in secs)  # product section next


def test_relevant_version_match():
    secs = sections.relevant_sections(_MD, keywords=["nope"], product="", version="2.4.49")
    assert any(s.heading == "Apache Tricks" for s in secs)  # version text lives in that section


def test_relevant_falls_back_to_general_sections():
    secs = sections.relevant_sections(_MD, keywords=["nonexistent"], product="")
    headings = [s.heading for s in secs]
    # Enumeration / Basic Information are the service-general fallback tier
    assert "Basic Information" in headings and "Server Enumeration" in headings


def test_relevant_empty_and_unknown():
    assert sections.relevant_sections("", keywords=["x"]) == []
    only = sections.relevant_sections("## Only\nbody\n", keywords=["zzz"], product="")
    assert only and only[0].heading == "Only"  # falls back to the first section


def test_relevant_never_cuts_a_code_block():
    for section in sections.relevant_sections(
        _MD, keywords=["Server Enumeration"], product="Apache"
    ):
        assert section.body.count("```") % 2 == 0  # every returned section has balanced fences


def test_relevant_is_deterministic():
    a = sections.relevant_sections(_MD, keywords=["Enumeration"], product="Apache")
    b = sections.relevant_sections(_MD, keywords=["Enumeration"], product="Apache")
    assert [s.heading for s in a] == [s.heading for s in b]
