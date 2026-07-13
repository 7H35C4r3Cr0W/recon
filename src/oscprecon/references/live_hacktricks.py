from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field, replace
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from oscprecon import __version__, config
from oscprecon.references import HACKTRICKS_BASE, load_rules

# Owner-approved live HackTricks fetch/cache (CLAUDE.md §14a). Boundaries live HERE, not in the GUI:
# only a canonical mapped page URL may be fetched; HTTPS + allow-listed host only; NO project data
# ever transmitted; bounded size/time; cross-host redirects refused; response sanitized to markdown.

_ALLOWED_HOSTS = frozenset({"book.hacktricks.wiki"})
_ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/markdown", "text/plain")
_MAX_BYTES = 3 * 1024 * 1024  # hard response cap
_TIMEOUT = 12.0  # connect + read, seconds
_MIN_INTERVAL = 2.0  # seconds; a same-URL re-fetch inside this window returns the cache instead
_USER_AGENT = f"oscp-recon/{__version__} (offline recon tool; local reference viewer)"

_FETCH_LOCK = threading.Lock()
_URL_LOCKS: dict[str, threading.Lock] = {}
_LAST_FETCH: dict[str, float] = {}


class LiveFetchError(Exception):
    """Any refusal or failure of a live fetch — always caught at the boundary, never crashes UI."""


# ---- URL trust ---------------------------------------------------------------------------------


def mapped_urls() -> frozenset[str]:
    urls = {rule.hacktricks for rule in load_rules() if rule.hacktricks}
    urls.add(HACKTRICKS_BASE)
    return frozenset(urls)


def is_fetchable(url: str) -> bool:
    # ONLY a canonical page already in the local services.yaml map; HTTPS; allow-listed host.
    if url not in mapped_urls():
        return False
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in _ALLOWED_HOSTS


# ---- HTML -> safe markdown ---------------------------------------------------------------------

_SKIP_TAGS = {
    "script",
    "style",
    "nav",
    "head",
    "svg",
    "footer",
    "header",
    "form",
    "button",
    "noscript",
    "aside",
    "iframe",
    "link",
    "meta",
    "select",
    "input",
    "textarea",
}
_HEADING_LEVEL = {"h1": 1, "h2": 2, "h3": 3, "h4": 4, "h5": 5, "h6": 6}
_BLOCK_TAGS = {"p", "div", "section", "article", "tr", "table", "ul", "ol", "blockquote"}
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _escape_links(text: str) -> str:
    # Neutralize markdown link/image syntax in page TEXT so a literal "[x](file://...)" in the page
    # can't render as a clickable link with an arbitrary scheme. Defense-in-depth: the host is
    # TLS-pinned, and real <a> hrefs are already dropped (we emit link text only). `\[`/`\]` render
    # as literal brackets, so the content stays readable.
    return text.replace("[", "\\[").replace("]", "\\]")


def _article_html(html: str) -> str:
    # mdBook wraps the page body in <main>; isolate it so the sidebar/nav/chrome never leak.
    low = html.lower()
    start = low.find("<main")
    if start == -1:
        return html
    end = low.rfind("</main>")
    return html[start:end] if end > start else html[start:]


class _MarkdownExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._out: list[str] = []
        self.headings: list[str] = []
        self._skip = 0
        self._heading = 0
        self._hbuf: list[str] = []
        self._pre = 0
        self._buf: list[str] = []

    def _flush(self) -> None:
        text = re.sub(r"\s+", " ", "".join(self._buf)).strip()
        self._buf = []
        if text:
            self._out.append(_escape_links(text))
            self._out.append("")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_TAGS:
            self._skip += 1
            return
        if self._skip:
            return
        if tag in _HEADING_LEVEL:
            self._flush()
            self._heading = _HEADING_LEVEL[tag]
            self._hbuf = []
        elif tag == "pre":
            self._flush()
            self._pre += 1
            self._out.append("```")
        elif tag == "li":
            self._flush()
            self._buf.append("- ")
        elif tag == "br":
            self._buf.append(" ")
        elif tag in _BLOCK_TAGS:
            self._flush()

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
            return
        if self._skip:
            return
        if tag in _HEADING_LEVEL and self._heading:
            title = re.sub(r"\s+", " ", "".join(self._hbuf)).strip()
            if title:
                self._out.append(f"{'#' * self._heading} {_escape_links(title)}")
                self._out.append("")
                self.headings.append(title)  # raw title for the (plain-text) navigation index
            self._heading = 0
            self._hbuf = []
        elif tag == "pre" and self._pre:
            self._flush()
            self._out.append("```")
            self._out.append("")
            self._pre = max(0, self._pre - 1)
        elif tag in _BLOCK_TAGS or tag == "li":
            self._flush()

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._pre:
            self._out.append(data.rstrip("\n"))
        elif self._heading:
            self._hbuf.append(data)
        else:
            self._buf.append(data)

    def markdown(self) -> str:
        self._flush()
        text = _CONTROL_RE.sub("", "\n".join(self._out))
        return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"


def html_to_markdown(html: str) -> tuple[str, list[str]]:
    # Produce our OWN markdown from parsed text tokens — no raw remote HTML/JS is ever passed on.
    parser = _MarkdownExtractor()
    parser.feed(_article_html(html))
    parser.close()
    return parser.markdown(), parser.headings


# ---- cache -------------------------------------------------------------------------------------


@dataclass
class CacheEntry:
    url: str
    fetched_at: float
    content_hash: str
    content_type: str
    etag: str
    last_modified: str
    markdown: str
    headings: list[str] = field(default_factory=list)
    status: str = "ok"  # "ok" | "error"
    source_host: str = ""


def cache_root() -> Path:
    directory = config.cache_dir() / "hacktricks"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _cache_path(url: str) -> Path:
    return cache_root() / f"{hashlib.sha256(url.encode('utf-8')).hexdigest()[:16]}.json"


def read_cache(url: str) -> CacheEntry | None:
    path = _cache_path(url)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None  # missing OR corrupt -> degrade to "no cache", never raise
    if not isinstance(data, dict) or data.get("url") != url:
        return None
    try:
        return CacheEntry(
            url=str(data["url"]),
            fetched_at=float(data.get("fetched_at", 0.0)),
            content_hash=str(data.get("content_hash", "")),
            content_type=str(data.get("content_type", "")),
            etag=str(data.get("etag", "")),
            last_modified=str(data.get("last_modified", "")),
            markdown=str(data.get("markdown", "")),
            headings=[str(h) for h in data.get("headings", []) if isinstance(h, str)],
            status=str(data.get("status", "ok")),
            source_host=str(data.get("source_host", "")),
        )
    except (TypeError, ValueError):
        return None


def _write_cache(entry: CacheEntry) -> None:
    path = _cache_path(entry.url)
    tmp = path.with_suffix(".json.tmp")
    try:
        tmp.write_text(json.dumps(asdict(entry), indent=2), encoding="utf-8")
        tmp.replace(path)  # atomic
    except OSError:
        tmp.unlink(missing_ok=True)  # a failed cache write is non-fatal; never touches project data


def clear_cache() -> int:
    # Rebuildable; clearing it NEVER touches project data. Returns how many entries were removed.
    removed = 0
    try:
        for path in cache_root().glob("*.json"):
            path.unlink(missing_ok=True)
            removed += 1
    except OSError:
        pass
    return removed


def _is_fresh(entry: CacheEntry, max_age_days: int) -> bool:
    return (time.time() - entry.fetched_at) < max_age_days * 86400


# ---- network -----------------------------------------------------------------------------------


class _NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        parsed = urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_HOSTS:
            return None  # refuse a redirect that would leave the allow-listed host / drop HTTPS
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoCrossHostRedirect())


@dataclass(frozen=True)
class _Raw:
    status: int
    body: bytes
    content_type: str
    etag: str
    last_modified: str


def _http_get(
    url: str,
    *,
    etag: str = "",
    last_modified: str = "",
    opener: urllib.request.OpenerDirector | None = None,
) -> _Raw:
    # URL is taken verbatim from the map — NO query params/body/headers carry any project data.
    request = urllib.request.Request(url, method="GET")
    request.add_header("User-Agent", _USER_AGENT)
    request.add_header("Accept", "text/html, text/markdown, text/plain")
    if etag:
        request.add_header("If-None-Match", etag)
    if last_modified:
        request.add_header("If-Modified-Since", last_modified)
    driver = opener or _build_opener()
    try:
        response: Any = driver.open(request, timeout=_TIMEOUT)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return _Raw(304, b"", "", etag, last_modified)
        raise LiveFetchError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise LiveFetchError(str(exc)) from exc
    final_host = urlparse(str(response.geturl())).hostname
    if final_host not in _ALLOWED_HOSTS:
        raise LiveFetchError("redirected off the allow-listed host")
    content_type = str(response.headers.get("Content-Type", "")).split(";")[0].strip().lower()
    if not content_type:
        raise LiveFetchError(
            "response had no Content-Type header"
        )  # explicit: don't parse unlabeled
    if not any(content_type.startswith(t) for t in _ALLOWED_CONTENT_TYPES):
        raise LiveFetchError(f"unexpected content type: {content_type}")
    body = response.read(_MAX_BYTES + 1)
    if len(body) > _MAX_BYTES:
        raise LiveFetchError("response exceeded the size cap")
    return _Raw(
        status=int(getattr(response, "status", 200) or 200),
        body=body,
        content_type=content_type,
        etag=str(response.headers.get("ETag", "")),
        last_modified=str(response.headers.get("Last-Modified", "")),
    )


# ---- orchestrator ------------------------------------------------------------------------------


@dataclass(frozen=True)
class LiveResult:
    state: str  # "live-refreshed" | "live-cached" | "error"
    markdown: str
    headings: list[str]
    fetched_at: float
    url: str
    error: str = ""


def _cached_result(entry: CacheEntry, error: str = "") -> LiveResult:
    return LiveResult(
        "live-cached", entry.markdown, entry.headings, entry.fetched_at, entry.url, error
    )


def _fresh_hit(cached: CacheEntry | None, force: bool, max_age_days: int) -> LiveResult | None:
    if cached is None or cached.status != "ok" or force:
        return None
    return _cached_result(cached) if _is_fresh(cached, max_age_days) else None


def _url_lock(url: str) -> threading.Lock:
    with _FETCH_LOCK:
        lock = _URL_LOCKS.get(url)
        if lock is None:
            lock = threading.Lock()
            _URL_LOCKS[url] = lock
        return lock


def get_page(
    url: str,
    *,
    enabled: bool = True,
    force: bool = False,
    max_age_days: int = config.DEFAULT_HACKTRICKS_CACHE_DAYS,
    opener: urllib.request.OpenerDirector | None = None,
) -> LiveResult:
    if not is_fetchable(url):
        return LiveResult("error", "", [], 0.0, url, "URL is not an allow-listed HackTricks page")

    cached = read_cache(url)
    if not enabled and not force:
        if cached is not None and cached.status == "ok":
            return _cached_result(cached)
        return LiveResult("error", "", [], 0.0, url, "live fetching is disabled")

    hit = _fresh_hit(cached, force, max_age_days)
    if hit is not None:
        return hit

    with _url_lock(url):  # serialize concurrent fetches of the SAME url (no parallel duplicates)
        # another thread may have refreshed while we waited; re-read and re-check freshness.
        cached = read_cache(url)
        now = time.monotonic()
        throttled = not force and (now - _LAST_FETCH.get(url, 0.0)) < _MIN_INTERVAL
        if throttled and cached is not None and cached.status == "ok":
            return _cached_result(cached)  # rate-limit: served the cache instead of re-hitting
        hit = _fresh_hit(cached, force, max_age_days)
        if hit is not None:
            return hit

        _LAST_FETCH[url] = now
        try:
            raw = _http_get(
                url,
                etag=cached.etag if cached else "",
                last_modified=cached.last_modified if cached else "",
                opener=opener,
            )
        except LiveFetchError as exc:
            if cached is not None and cached.status == "ok":
                return _cached_result(cached, f"refresh failed: {exc}")  # keep the prior valid copy
            return LiveResult("error", "", [], 0.0, url, str(exc))

        if raw.status == 304 and cached is not None:
            entry = replace(cached, fetched_at=time.time())
            _write_cache(entry)
            return _cached_result(entry)

        markdown, headings = html_to_markdown(raw.body.decode("utf-8", "replace"))
        entry = CacheEntry(
            url=url,
            fetched_at=time.time(),
            content_hash=hashlib.sha256(raw.body).hexdigest(),
            content_type=raw.content_type,
            etag=raw.etag,
            last_modified=raw.last_modified,
            markdown=markdown,
            headings=headings,
            status="ok",
            source_host=urlparse(url).hostname or "",
        )
        _write_cache(entry)
        return LiveResult("live-refreshed", markdown, headings, entry.fetched_at, url)
