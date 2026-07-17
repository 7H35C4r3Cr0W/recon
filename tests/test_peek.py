from oscprecon.modules.peek import (
    PEEK_MAX_BYTES,
    extension,
    is_data_bearing,
    is_peekable,
    is_sensitive,
    peek_snippet,
)


def test_extension_handles_dotfiles_and_compound_names() -> None:
    assert extension("prod.dtsConfig") == "dtsconfig"  # case-folded
    assert extension("archive.tar.gz") == "gz"  # last segment only
    assert extension("README") == ""  # no extension
    assert extension(".bashrc") == ""  # dotfile is not an extension


def test_is_data_bearing_peeks_anything_not_binary_or_secret() -> None:
    # the directive: peek anything with data inside, not a fixed text-extension allowlist
    assert is_data_bearing("prod.dtsConfig") is True  # unusual config extension
    assert is_data_bearing("notes") is True  # no extension
    assert is_data_bearing("service.mystery") is True  # totally unknown extension
    assert is_data_bearing("app.log") is True
    assert is_data_bearing("settings.ini") is True
    # known-binary / media / archive types are the only extension-based skips
    assert is_data_bearing("photo.JPG") is False  # case-insensitive
    assert is_data_bearing("dump.zip") is False
    assert is_data_bearing("slides.pptx") is False
    assert is_data_bearing("agent.exe") is False
    # secret material is never data-bearing for peek purposes
    assert is_data_bearing("id_rsa") is False
    assert is_data_bearing("cert.pem") is False


def test_is_sensitive_covers_key_and_hash_material() -> None:
    assert is_sensitive("server.key") is True
    assert is_sensitive("backup.pfx") is True
    assert is_sensitive("shadow") is True
    assert is_sensitive(".htpasswd") is True
    assert is_sensitive("prod.dtsConfig") is False


def test_is_peekable_bounds_on_size_and_type() -> None:
    assert is_peekable("prod.dtsConfig", False, 609) is True
    assert is_peekable("prod.dtsConfig", True, 609) is False  # directory
    assert is_peekable("prod.dtsConfig", False, 0) is False  # zero/unknown size
    assert is_peekable("prod.dtsConfig", False, PEEK_MAX_BYTES + 1) is False  # too big
    assert is_peekable("keepass.kdbx", False, 500) is False  # secret store


def test_peek_snippet_never_leaks_beyond_the_bound() -> None:
    # a config whose head is XML but whose secret sits deeper never reaches the bounded snippet
    xml = '<?xml version="1.0"?><DTSConfiguration><Heading/>' + "x" * 200 + "Password=SECRET;"
    snip = peek_snippet(xml, limit=60)
    assert "SECRET" not in snip
    assert len(snip) <= 61  # 60 chars + the ellipsis
    assert peek_snippet("\x00\x01\x02\xff\xfe binary \x00\x00") == "(binary or non-text content)"
    assert peek_snippet("   ") == "(empty)"
