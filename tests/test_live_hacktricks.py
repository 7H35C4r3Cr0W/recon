import json
import urllib.error

import pytest

from oscprecon.references import live_hacktricks as lh

_MAPPED = "https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-smb/index.html"


@pytest.fixture(autouse=True)
def _cache_env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    lh._LAST_FETCH.clear()
    lh._URL_LOCKS.clear()


class _Resp:
    def __init__(self, body=b"", headers=None, status=200, url=_MAPPED):
        self._body = body
        self.headers = headers or {}
        self.status = status
        self._url = url

    def read(self, n=-1):
        return self._body[:n] if n and n >= 0 else self._body

    def geturl(self):
        return self._url


class _Opener:
    def __init__(self, response=None, error=None):
        self._response = response
        self._error = error
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if self._error is not None:
            raise self._error
        return self._response


def _html(body="<h2>Server Enumeration</h2><p>enumerate</p>"):
    return f"<html><body><main>{body}</main></body></html>".encode()


# ---- URL trust ---------------------------------------------------------------------------------


def test_mapped_url_is_fetchable():
    assert _MAPPED in lh.mapped_urls()
    assert lh.is_fetchable(_MAPPED) is True


def test_arbitrary_and_unsafe_urls_rejected():
    assert lh.is_fetchable("https://evil.example.com/x") is False
    assert lh.is_fetchable("https://book.hacktricks.wiki/not-in-map") is False
    assert lh.is_fetchable("http://book.hacktricks.wiki/en/x") is False  # not HTTPS + not mapped
    assert lh.is_fetchable("javascript:alert(1)") is False
    assert lh.is_fetchable("file:///etc/passwd") is False


def test_cross_host_redirect_refused():
    handler = lh._NoCrossHostRedirect()
    import urllib.request as ur

    req = ur.Request(_MAPPED)
    assert handler.redirect_request(req, None, 302, "", {}, "https://evil.com/x") is None
    assert handler.redirect_request(req, None, 302, "", {}, "http://book.hacktricks.wiki/x") is None
    ok = handler.redirect_request(req, None, 302, "", {}, "https://book.hacktricks.wiki/other")
    assert ok is not None


# ---- fetch boundaries --------------------------------------------------------------------------


def test_fetch_rejects_oversized_response(monkeypatch):
    monkeypatch.setattr(lh, "_MAX_BYTES", 50)
    opener = _Opener(_Resp(body=b"x" * 100, headers={"Content-Type": "text/html"}))
    result = lh.get_page(_MAPPED, force=True, opener=opener)
    assert result.state == "error" and "size cap" in result.error


def test_fetch_rejects_bad_content_type():
    opener = _Opener(_Resp(body=b"MZ...", headers={"Content-Type": "application/octet-stream"}))
    result = lh.get_page(_MAPPED, force=True, opener=opener)
    assert result.state == "error" and "content type" in result.error


def test_fetch_handles_timeout_as_error():
    opener = _Opener(error=urllib.error.URLError("timed out"))
    result = lh.get_page(_MAPPED, force=True, opener=opener)
    assert result.state == "error"


def test_request_carries_no_project_data():
    opener = _Opener(_Resp(body=_html(), headers={"Content-Type": "text/html"}))
    lh.get_page(_MAPPED, force=True, opener=opener)
    request = opener.requests[0]
    assert request.full_url == _MAPPED  # no query string appended
    assert request.data is None  # no request body
    # only fixed headers; nothing that could carry a target IP/hostname/product/finding
    header_values = " ".join(str(v) for v in request.headers.values()).lower()
    assert "10." not in header_values and "target" not in header_values


# ---- extraction / sanitization -----------------------------------------------------------------


def test_html_to_markdown_strips_scripts_and_keeps_content():
    html = (
        b"<html><head><script>alert('x')</script></head>"
        b"<body><nav>sidebar junk</nav>"
        b"<main><h2>Server Enumeration</h2><p>use a null session</p>"
        b"<pre>smbclient -L //t/</pre></main></body></html>"
    )
    md, headings = lh.html_to_markdown(html.decode())
    assert "alert(" not in md and "sidebar junk" not in md  # script + nav removed
    assert "## Server Enumeration" in md and "use a null session" in md
    assert "smbclient -L //t/" in md and "```" in md  # code fenced, preserved
    assert headings == ["Server Enumeration"]


# ---- cache -------------------------------------------------------------------------------------


def test_refresh_success_writes_cache_then_serves_fresh():
    opener = _Opener(_Resp(body=_html(), headers={"Content-Type": "text/html", "ETag": '"v1"'}))
    first = lh.get_page(_MAPPED, force=True, opener=opener)
    assert first.state == "live-refreshed" and "Server Enumeration" in first.markdown
    # a fresh cache short-circuits — the opener is not hit again
    opener2 = _Opener(error=urllib.error.URLError("should not be called"))
    second = lh.get_page(_MAPPED, opener=opener2)
    assert second.state == "live-cached" and opener2.requests == []


def test_corrupt_cache_degrades_and_rebuilds():
    path = lh._cache_path(_MAPPED)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    assert lh.read_cache(_MAPPED) is None  # corrupt -> None, no raise
    opener = _Opener(_Resp(body=_html(), headers={"Content-Type": "text/html"}))
    result = lh.get_page(_MAPPED, force=True, opener=opener)
    assert result.state == "live-refreshed"  # rebuilt cleanly


def test_refresh_failure_retains_previous_cache():
    good = _Opener(_Resp(body=_html(), headers={"Content-Type": "text/html"}))
    lh.get_page(_MAPPED, force=True, opener=good)  # seed a valid cache
    broken = _Opener(error=urllib.error.URLError("down"))
    result = lh.get_page(_MAPPED, force=True, opener=broken)
    assert result.state == "live-cached"  # kept the prior valid copy
    assert "refresh failed" in result.error and "Server Enumeration" in result.markdown


def test_conditional_304_keeps_content_and_sends_etag():
    seed = _Opener(_Resp(body=_html(), headers={"Content-Type": "text/html", "ETag": '"v1"'}))
    lh.get_page(_MAPPED, force=True, opener=seed)
    not_modified = _Opener(error=urllib.error.HTTPError(_MAPPED, 304, "Not Modified", {}, None))
    result = lh.get_page(_MAPPED, force=True, opener=not_modified)
    assert result.state == "live-cached" and "Server Enumeration" in result.markdown
    assert not_modified.requests[0].get_header("If-none-match") == '"v1"'


def test_manual_refresh_bypasses_freshness():
    v1 = _Opener(_Resp(body=_html("<h2>Old</h2>"), headers={"Content-Type": "text/html"}))
    lh.get_page(_MAPPED, force=True, opener=v1)
    v2 = _Opener(_Resp(body=_html("<h2>New</h2>"), headers={"Content-Type": "text/html"}))
    result = lh.get_page(_MAPPED, force=True, opener=v2)  # force -> re-fetch despite fresh cache
    assert result.state == "live-refreshed" and "New" in result.markdown


# ---- disabled / clear --------------------------------------------------------------------------


def test_disabled_makes_no_request_and_falls_back():
    opener = _Opener(error=urllib.error.URLError("must not fetch"))
    result = lh.get_page(_MAPPED, enabled=False, opener=opener)
    assert result.state == "error" and "disabled" in result.error
    assert opener.requests == []


def test_disabled_still_serves_existing_cache():
    seed = _Opener(_Resp(body=_html(), headers={"Content-Type": "text/html"}))
    lh.get_page(_MAPPED, force=True, opener=seed)
    result = lh.get_page(_MAPPED, enabled=False)
    assert result.state == "live-cached" and "Server Enumeration" in result.markdown


def test_clear_cache_removes_cache_but_not_project_files(tmp_path):
    seed = _Opener(_Resp(body=_html(), headers={"Content-Type": "text/html"}))
    lh.get_page(_MAPPED, force=True, opener=seed)
    project_creds = tmp_path / "creds.json"
    project_creds.write_text(json.dumps({"entries": []}), encoding="utf-8")
    removed = lh.clear_cache()
    assert removed >= 1 and lh.read_cache(_MAPPED) is None
    assert project_creds.exists()  # clearing the cache never touches project data
