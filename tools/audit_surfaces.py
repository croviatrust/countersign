#!/usr/bin/env python3
"""Audit Crovia Trust's live public surfaces against the canon.

The canon (``CANON.md`` / ``canon/canon.json``) is the single source of truth
for every public surface of croviatrust.com. This tool fetches the LIVE
surfaces (pages, retired paths, the registry.croviatrust.com mirror, public
data files, the Seal service, the MCP endpoint, optional local repo checkouts)
and reports every place where they disagree with the canon: broken or
duplicated pages, stale data, leaked private files, non-canonical Seal
objects, forbidden wording, headline numbers that do not follow from the
underlying data, and MCP answers that contradict the home page.

Run it from the repository root:

    python3 tools/audit_surfaces.py
    python3 tools/audit_surfaces.py --gate          # exit 1 on critical/high
    python3 tools/audit_surfaces.py --base https://staging.example --out /tmp/r

It writes ``reports/surface_audit_<timestamp>.json`` (all findings, a
severity summary and the list of every request made) and
``reports/surface_audit_latest.md`` (human-readable report). Only the Python
standard library is used. The tool is deliberately gentle with the origin:
requests to the same host are spaced by ``--delay`` seconds, everything under
``/registry/data/`` is fetched strictly sequentially, a 429 is retried once
after 30 s, and the multi-megabyte files listed under ``heavy_files`` are only
probed with a one-byte ``Range`` request. It never calls ``POST /v1/sign``.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional, TypeVar

USER_AGENT = "crovia-canon-audit/1.0"
DEFAULT_TIMEOUT = 30.0
RETRY_AFTER_429 = 30.0
RETRY_AFTER_NETWORK_ERROR = 3.0
SEVERITIES = ("critical", "high", "medium", "low", "info")
TS_KEY_RE = re.compile(r"(generated_at|updated_at|checked_at|sealed_at|timestamp|_at)$")
ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js", ".mjs",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map",
)
LINK_CAP = 60
# registry.croviatrust.com serves /var/www/registry as its root, so
# registry.croviatrust.com/<p> must equal croviatrust.com/registry/<p>.
MIRROR_PATHS = ("/registry/", "/registry/seal/", "/registry/lacuna/", "/registry/data/_home_pulse.json")
ADVERTISING_DOCS = ("/registry/api/", "/llms.txt", "/.well-known/openapi.yaml", "/.well-known/ai-plugin.json")
LINK_SOURCE_DOCS = ADVERTISING_DOCS + ("/registry/", "/registry/seal/")
TEXT_DOC_SUFFIXES = ("/llms.txt", "/llms-full.txt")
DATA_PREFIX = "/registry/data/"
REPO_ROOT = Path("/tmp/crovia")

_CDN_EMAIL_RE = re.compile(
    rb'<a [^>]*href="/cdn-cgi/l/email-protection[^"]*"[^>]*>.*?</a>|<a [^>]*href="mailto:[^"]*"[^>]*>.*?</a>'
    rb'|<span class="__cf_email__"[^>]*>.*?</span>|<script data-cfasync="false" src="/cdn-cgi/scripts/[^"]*">\s*</script>'
    rb'|<script[^>]*static\.cloudflareinsights\.com/beacon\.min\.js[^>]*>\s*</script>'
    rb'|info@croviatrust\.com|\s+', re.S)


def _strip_cdn_email(body: bytes) -> bytes:
    """croviatrust.com sits behind Cloudflare, which rewrites e-mail addresses; the mirror does not."""
    return _CDN_EMAIL_RE.sub(b"", body)

T = TypeVar("T")
U = TypeVar("U")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: Any) -> Optional[datetime]:
    """Parse RFC 3339 / ISO 8601 strings (any fraction length, ``Z`` or offset), dates, and epochs."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if value < 1e9:
            return None
        seconds = value / 1000.0 if value > 1e12 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        s += "T00:00:00"
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?)(\.\d+)?(.*)$", s)
    if not m:
        return None
    fraction = (m.group(2) or "")[:7]
    try:
        dt = datetime.fromisoformat(m.group(1) + fraction + m.group(3))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iter_timestamps(obj: Any, depth: int = 0, max_depth: int = 3) -> Iterator[datetime]:
    if depth >= max_depth:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if TS_KEY_RE.search(str(key)):
                ts = parse_ts(value)
                if ts is not None:
                    yield ts
            yield from iter_timestamps(value, depth + 1, max_depth)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_timestamps(item, depth + 1, max_depth)


def freshest_timestamp(obj: Any) -> Optional[datetime]:
    horizon = utcnow() + timedelta(minutes=5)
    candidates = [ts for ts in iter_timestamps(obj) if ts <= horizon]
    return max(candidates) if candidates else None


def get_path(obj: Any, dotted: str) -> Any:
    """Resolve ``a.b.c`` allowing keys that themselves contain dots (``AX.LAC``)."""
    parts = dotted.split(".")
    current = obj
    i = 0
    while i < len(parts):
        if not isinstance(current, dict):
            return None
        for j in range(len(parts), i, -1):
            key = ".".join(parts[i:j])
            if key in current:
                current = current[key]
                i = j
                break
        else:
            return None
    return current


def path_of(url: str) -> str:
    return urllib.parse.urlsplit(url).path or "/"


def host_of(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc.lower()


def is_data_path(url: str) -> bool:
    return path_of(url).startswith(DATA_PREFIX)


def html_title(body: bytes) -> str:
    m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()


def snippet(text: str, position: int, width: int = 70) -> str:
    start = max(0, position - width)
    end = min(len(text), position + width)
    return re.sub(r"\s+", " ", text[start:end]).strip()


def clip(value: Any, limit: int = 200) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
    text = text.replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def parse_json_document(path: str, text: str) -> Any:
    if path.endswith(".jsonl"):
        rows = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"line {number} is not a JSON object")
            rows.append(row)
        return rows
    return json.loads(text)


def parse_jsonrpc(text: str) -> Optional[dict[str, Any]]:
    """Accept either a plain JSON body or a text/event-stream carrying JSON-RPC messages."""
    try:
        message = json.loads(text)
        return message if isinstance(message, dict) else None
    except ValueError:
        pass
    last: Optional[dict[str, Any]] = None
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        try:
            candidate = json.loads(line[5:].strip())
        except ValueError:
            continue
        if isinstance(candidate, dict) and ("result" in candidate or "error" in candidate):
            last = candidate
    return last


@dataclass
class FetchResult:
    url: str
    method: str
    status: int
    final_url: str
    body: bytes
    headers: dict[str, str]
    error: str = ""
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status == 200 and not self.error

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type

    def describe(self) -> str:
        if self.error:
            return f"error: {self.error}"
        return f"HTTP {self.status}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class Fetcher:
    """HTTP client with a response cache, per-host pacing, serialized /registry/data/ access and 429 retry."""

    def __init__(self, delay: float, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.delay = delay
        self.timeout = timeout
        self.log: list[dict[str, Any]] = []
        self._cache: dict[tuple, FetchResult] = {}
        self._cache_lock = threading.Lock()
        self._schedule_lock = threading.Lock()
        self._next_slot: dict[str, float] = {}
        self._data_lock = threading.Lock()
        context = ssl.create_default_context()
        self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        self._opener_no_redirect = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), _NoRedirect()
        )

    def get(
        self,
        url: str,
        *,
        follow: bool = True,
        headers: Optional[dict[str, str]] = None,
        max_bytes: Optional[int] = None,
    ) -> FetchResult:
        key = ("GET", url, follow, tuple(sorted((headers or {}).items())), max_bytes)
        with self._cache_lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = self._request("GET", url, None, headers or {}, follow, max_bytes)
        with self._cache_lock:
            self._cache.setdefault(key, result)
            return self._cache[key]

    def range_probe(self, url: str) -> FetchResult:
        return self.get(url, headers={"Range": "bytes=0-0"}, max_bytes=1024)

    def post(self, url: str, payload: bytes, headers: dict[str, str]) -> FetchResult:
        return self._request("POST", url, payload, headers, True, None)

    def cached_results(self) -> list[FetchResult]:
        with self._cache_lock:
            return list(self._cache.values())

    def _request(
        self,
        method: str,
        url: str,
        payload: Optional[bytes],
        headers: dict[str, str],
        follow: bool,
        max_bytes: Optional[int],
    ) -> FetchResult:
        guard = self._data_lock if is_data_path(url) else nullcontext()
        with guard:
            self._throttle(url)
            result = self._once(method, url, payload, headers, follow, max_bytes)
            if result.status == 429:
                time.sleep(RETRY_AFTER_429)
                self._throttle(url)
                result = self._once(method, url, payload, headers, follow, max_bytes)
            elif result.error:
                time.sleep(RETRY_AFTER_NETWORK_ERROR)
                self._throttle(url)
                result = self._once(method, url, payload, headers, follow, max_bytes)
        self._record(result, headers)
        return result

    def _throttle(self, url: str) -> None:
        host = host_of(url)
        with self._schedule_lock:
            now = time.monotonic()
            slot = max(now, self._next_slot.get(host, 0.0))
            self._next_slot[host] = slot + self.delay
        if slot > now:
            time.sleep(slot - now)

    def _once(
        self,
        method: str,
        url: str,
        payload: Optional[bytes],
        headers: dict[str, str],
        follow: bool,
        max_bytes: Optional[int],
    ) -> FetchResult:
        request = urllib.request.Request(url, data=payload, method=method, headers={"User-Agent": USER_AGENT, **headers})
        opener = self._opener if follow else self._opener_no_redirect
        started = time.monotonic()
        try:
            with opener.open(request, timeout=self.timeout) as response:
                body = response.read(max_bytes) if max_bytes else response.read()
                return FetchResult(
                    url, method, response.status, response.geturl(), body,
                    {k.lower(): v for k, v in response.headers.items()},
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                )
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(max_bytes) if max_bytes else exc.read()
            except Exception:  # noqa: BLE001 - body of an error response is best effort
                body = b""
            return FetchResult(
                url, method, exc.code, exc.geturl() or url, body,
                {k.lower(): v for k, v in exc.headers.items()},
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            return FetchResult(
                url, method, 0, url, b"", {}, error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

    def _record(self, result: FetchResult, headers: dict[str, str]) -> None:
        entry = {
            "url": result.url,
            "method": result.method,
            "status": result.status,
            "final_url": result.final_url,
            "size": len(result.body),
            "content_length": result.headers.get("content-length"),
            "content_range": result.headers.get("content-range"),
            "elapsed_ms": result.elapsed_ms,
            "error": result.error or None,
            "range_probe": "Range" in headers,
            "age_hours": None,
        }
        with self._cache_lock:
            self.log.append(entry)


@dataclass
class Finding:
    check: str
    surface: str
    severity: str
    expected: Any
    observed: Any
    note: str


@dataclass
class Audit:
    canon: dict[str, Any]
    base: str
    fetcher: Fetcher
    concurrency: int
    findings: list[Finding] = field(default_factory=list)
    pages: dict[str, dict[str, Any]] = field(default_factory=dict)
    ages: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        identity = self.canon["identity"]
        self.domain: str = identity["domain"]
        self.mirror: str = identity["mirror"]
        self.seal_host: str = identity["seal_host"]
        self.pages_set = set(self.canon["pages"])
        self.retired_set = set(self.canon["retired_paths"])
        self.heavy_set = set(self.canon.get("heavy_files", []))

    def url(self, path: str, host: Optional[str] = None) -> str:
        if host is None:
            return self.base.rstrip("/") + path
        return f"https://{host}{path}"

    def add(self, check: str, surface: str, severity: str, expected: Any, observed: Any, note: str) -> None:
        with self._lock:
            self.findings.append(Finding(check, surface, severity, expected, observed, note))

    def pmap(self, fn: Callable[[T], U], items: Iterable[T]) -> list[U]:
        with ThreadPoolExecutor(max_workers=max(1, self.concurrency)) as pool:
            return list(pool.map(fn, items))

    def cached_json(self, path: str) -> Any:
        result = self.fetcher.get(self.url(path))
        if not result.ok:
            return None
        try:
            return parse_json_document(path, result.text)
        except ValueError:
            return None

    def run_check(self, name: str, fn: Callable[[], None]) -> None:
        print(f"[{name}] ...", file=sys.stderr, flush=True)
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - a crashing check must not lose the report
            traceback.print_exc()
            self.add(name, self.base, "high", "check completes", f"{type(exc).__name__}: {exc}", "check crashed")

    # ---- a. pages -------------------------------------------------------

    def check_pages(self) -> None:
        for path, result in self.pmap(lambda p: (p, self.fetcher.get(self.url(p))), self.canon["pages"]):
            self._assess_page(path, result)

    def _assess_page(self, path: str, result: FetchResult) -> None:
        surface = self.url(path)
        self.pages[path] = {
            "final_url": result.final_url,
            "status": result.status,
            "size": len(result.body),
            "title": html_title(result.body) if result.is_html else "",
        }
        if result.error:
            self.add("pages", surface, "high", "HTTP 200", result.describe(), "unreachable")
            return
        if result.status != 200:
            self.add("pages", surface, "high", "HTTP 200", result.describe(), "page does not return 200")
            return
        final_host, final_path = host_of(result.final_url), path_of(result.final_url)
        if final_host != self.domain:
            self.add("pages", surface, "high", f"final URL on {self.domain}", result.final_url, "page leaves the canonical domain")
        if final_path in self.retired_set:
            self.add("pages", surface, "high", "final URL is not a retired path", result.final_url, "page redirects to a retired path")
        marker = self.canon.get("smoke_markers", {}).get(path)
        if marker and marker not in result.text:
            self.add("pages", surface, "medium", f"body contains {marker!r}", f"{len(result.body)} bytes, title={self.pages[path]['title']!r}", "smoke marker missing")

    # ---- b. retired paths -----------------------------------------------

    def check_retired(self) -> None:
        items = self.pmap(lambda p: (p, self.fetcher.get(self.url(p), follow=False)), self.canon["retired_paths"])
        for path, result in items:
            self._assess_retired(path, result)

    def _assess_retired(self, path: str, result: FetchResult) -> None:
        surface = self.url(path)
        expected = "301/302/308 to a canonical page"
        if result.error:
            self.add("retired_paths", surface, "high", expected, result.describe(), "unreachable")
        elif result.status in (301, 302, 308):
            target = urllib.parse.urljoin(result.final_url, result.headers.get("location", ""))
            target_path = path_of(target)
            if host_of(target) not in ("", self.domain) or target_path not in self.pages_set:
                self.add("retired_paths", surface, "medium", expected, f"HTTP {result.status} -> {target}", "redirect target is not a canonical page")
        elif result.status == 200:
            self.add("retired_paths", surface, "high", expected, f"HTTP 200, {len(result.body)} bytes, title={html_title(result.body)!r}", "retired path still serves content (duplicate content)")
        elif result.status == 404:
            self.add("retired_paths", surface, "medium", expected, "HTTP 404", "retired path returns 404 instead of a redirect")
        else:
            location = result.headers.get("location", "")
            self.add("retired_paths", surface, "medium", expected, f"HTTP {result.status} {location}".strip(), "unexpected status for a retired path")

    # ---- c. mirror parity -----------------------------------------------

    def check_mirror(self) -> None:
        def fetch_pair(path: str) -> tuple[str, FetchResult, FetchResult]:
            mirror_path = path[len("/registry"):] if path.startswith("/registry") else path
            return path, self.fetcher.get(self.url(path, self.domain)), self.fetcher.get(self.url(mirror_path, self.mirror))

        for path, primary, mirrored in self.pmap(fetch_pair, MIRROR_PATHS):
            surface = self.url(path[len("/registry"):] if path.startswith("/registry") else path, self.mirror)
            if not primary.ok or not mirrored.ok:
                self.add("mirror_parity", surface, "high", "both hosts return 200", f"{self.domain}: {primary.describe()}; {self.mirror}: {mirrored.describe()}", "unreachable or non-200 on one host")
                continue
            digest_primary = hashlib.sha256(primary.body).hexdigest()
            digest_mirror = hashlib.sha256(mirrored.body).hexdigest()
            if digest_primary != digest_mirror and _strip_cdn_email(primary.body) == _strip_cdn_email(mirrored.body):
                self.add("mirror_parity", surface, "info", "same origin body", "identical after removing Cloudflare email obfuscation", "mirror serves the same origin file")
                continue
            if digest_primary != digest_mirror:
                self.add("mirror_parity", surface, "medium", f"sha256 {digest_primary[:16]}… ({len(primary.body)} bytes)", f"sha256 {digest_mirror[:16]}… ({len(mirrored.body)} bytes)", "mirror body differs from canonical domain")

    # ---- d. data files --------------------------------------------------

    def check_data_files(self) -> None:
        for path in self.canon["data_files"]:
            self._assess_data_file(path)
        for path in self.canon.get("heavy_files", []):
            self._probe_heavy_file(path)

    def _assess_data_file(self, path: str) -> None:
        surface = self.url(path)
        result = self.fetcher.get(surface)
        if not result.ok:
            self.add("data_files", surface, "high", "HTTP 200 JSON", result.describe(), "unreachable" if result.error else "data file does not return 200")
            return
        try:
            parsed = parse_json_document(path, result.text)
        except ValueError as exc:
            self.add("data_files", surface, "high", "valid JSON" + ("L" if path.endswith(".jsonl") else ""), f"{type(exc).__name__}: {clip(str(exc), 120)}", "data file does not parse")
            return
        freshest = freshest_timestamp(parsed)
        if freshest is None:
            self.add("data_files", surface, "low", "a timestamp field in the top 3 levels", "none found", "no timestamp field to judge freshness")
            return
        age_hours = (utcnow() - freshest).total_seconds() / 3600.0
        self.ages[surface] = round(age_hours, 2)
        observed = f"freshest timestamp {freshest.isoformat()} ({age_hours:.1f} h old)"
        if age_hours > 30 * 24:
            self.add("data_files", surface, "high", "updated within 30 days", observed, "stale")
        elif age_hours > 48:
            self.add("data_files", surface, "medium", "updated within 48 h", observed, "stale")

    def _probe_heavy_file(self, path: str) -> None:
        surface = self.url(path)
        result = self.fetcher.range_probe(surface)
        size = result.headers.get("content-range", result.headers.get("content-length", "?"))
        if result.status in (200, 206):
            self.add("data_files", surface, "info", "reachable (Range probe only)", f"HTTP {result.status}, {size}", "heavy file present; not downloaded")
        else:
            self.add("data_files", surface, "medium", "HTTP 200/206 on Range probe", result.describe(), "heavy file not reachable")

    # ---- e. private files -----------------------------------------------

    def check_private_files(self) -> None:
        docs = {path: self.fetcher.get(self.url(path)) for path in ADVERTISING_DOCS}
        for private in self.canon["private_files"]:
            self._search_private_reference(private, docs)
        for private, result in self.pmap(lambda p: (p, self.fetcher.get(self.url(p))), self.canon["private_files"]):
            self._assess_private_status(private, result)

    def _search_private_reference(self, private: str, docs: dict[str, FetchResult]) -> None:
        needle = os.path.basename(private)
        for doc_path, result in docs.items():
            if not result.ok:
                continue
            position = result.text.find(needle)
            if position < 0:
                continue
            # In HTML, a professional-tier entry may name the file without linking to it (label
            # "professional"); only a live link or a copy-paste URL counts as advertising.
            is_html = "<html" in result.text[:2000].lower() or doc_path.endswith("/")
            linked = re.search(r'href="[^"]*' + re.escape(needle), result.text) or ("croviatrust.com/registry/data/" + needle) in result.text
            if is_html and not linked and "professional" in result.text[max(0, position - 600):position + 600].lower():
                self.add("private_files", self.url(doc_path), "info", f"{needle} not linked", "named as a professional-tier product, no link", "private file listed as professional, not linked")
                continue
            self.add("private_files", self.url(doc_path), "high", f"no reference to {private}", snippet(result.text, position), "private file is advertised publicly")

    def _assess_private_status(self, private: str, result: FetchResult) -> None:
        surface = self.url(private)
        if result.error:
            self.add("private_files", surface, "high", "HTTP 403/404", result.describe(), "unreachable")
        elif result.status in (403, 404):
            self.add("private_files", surface, "info", "HTTP 403/404", f"HTTP {result.status}", "private file is not served")
        elif result.status == 200:
            self.add("private_files", surface, "medium", "HTTP 403/404", f"HTTP 200, {len(result.body)} bytes", "private file is publicly readable")
        else:
            self.add("private_files", surface, "low", "HTTP 403/404", result.describe(), "unexpected status for a private file")

    # ---- f. links -------------------------------------------------------

    def check_links(self) -> None:
        links = self._collect_links()
        skip = {self.canon["apis"].get("mcp"), self.canon["apis"].get("anchor_post")}
        targets = [u for u in links if u not in skip][:LINK_CAP]

        def probe(link: str) -> tuple[str, FetchResult]:
            if path_of(link) in self.heavy_set:
                return link, self.fetcher.range_probe(link)
            return link, self.fetcher.get(link)

        for link, result in self.pmap(probe, targets):
            self._assess_link(link, links[link], result)

    def _collect_links(self) -> dict[str, str]:
        links: dict[str, str] = {}
        allowed_hosts = {self.domain, self.seal_host}
        for doc_path in LINK_SOURCE_DOCS:
            result = self.fetcher.get(self.url(doc_path))
            if not result.ok:
                continue
            for raw in extract_links(result.text, result.is_html):
                absolute = urllib.parse.urljoin(result.final_url, raw)
                parts = urllib.parse.urlsplit(absolute)
                if parts.scheme not in ("http", "https") or parts.netloc.lower() not in allowed_hosts:
                    continue
                if parts.path.lower().endswith(ASSET_EXTENSIONS) or "{" in absolute:
                    continue
                normalized = urllib.parse.urlunsplit(("https", parts.netloc.lower(), parts.path or "/", parts.query, ""))
                links.setdefault(normalized, self.url(doc_path))
        return links

    def _assess_link(self, link: str, source: str, result: FetchResult) -> None:
        good = (200, 206) if path_of(link) in self.heavy_set else (200,)
        if result.error:
            self.add("links", link, "medium", "HTTP 200", result.describe(), f"unreachable (linked from {source})")
        elif result.status not in good:
            self.add("links", link, "medium", "HTTP 200", result.describe(), f"broken link (linked from {source})")
        path = path_of(link)
        if path in self.retired_set or path.rstrip("/") + "/" in self.retired_set:
            self.add("links", link, "low", "no links to retired paths", f"linked from {source}", "link points to a retired path")

    # ---- g. seal format -------------------------------------------------

    def check_seal(self) -> None:
        for path in ("/v1/stats", "/health"):
            self._assess_seal_endpoint(path)
        log_path = "/registry/data/seal/public_log.jsonl"
        result = self.fetcher.get(self.url(log_path))
        if not result.ok:
            return
        try:
            seals = parse_json_document(log_path, result.text)
        except ValueError:
            return
        self._assess_public_log(self.url(log_path), seals)
        self._assess_spec_page()

    def _assess_spec_page(self) -> None:
        """The spec page is what draft-crovia-seal points to: the text must be inline (no client-side
        rendering), the served SPEC.md must be the bytes canon records, and the vectors it promises
        must be there with the hashes the manifest states."""
        canon_seal = self.canon["seal"]
        spec_url = canon_seal.get("spec_url")
        if not spec_url:
            return
        page = self.fetcher.get(spec_url)
        if not page.ok:
            self.add("seal_format", spec_url, "high", "HTTP 200", page.describe(), "spec page unreachable")
        elif "Loading specification" in page.text or "3.3 Signing payload" not in page.text:
            self.add("seal_format", spec_url, "high", "normative text inline in HTML", "section 3.3 not found in served HTML", "spec page needs JavaScript to show the text")
        else:
            self.add("seal_format", spec_url, "info", "normative text inline in HTML", "section 3.3 present", "spec page readable without scripts")
        src_url, want = canon_seal.get("spec_source_url"), canon_seal.get("spec_sha256")
        if src_url and want:
            src = self.fetcher.get(src_url)
            got = hashlib.sha256(src.body).hexdigest() if src.ok else None
            if got != want:
                self.add("seal_format", src_url, "high", f"sha256 {want[:16]}…", src.describe() if not src.ok else f"sha256 {got[:16]}…", "served SPEC.md differs from canon")
            else:
                self.add("seal_format", src_url, "info", f"sha256 {want[:16]}…", "match", "SPEC.md bytes match canon")
        manifest_url = canon_seal.get("vectors_manifest_url")
        if manifest_url:
            man = self.fetcher.get(manifest_url)
            try:
                files = json.loads(man.text)["files"] if man.ok else []
            except (ValueError, KeyError, TypeError):
                files = []
            if not files:
                self.add("seal_format", manifest_url, "high", "manifest with files[]", man.describe(), "vector manifest missing or malformed")
                return
            base = manifest_url.rsplit("/", 1)[0] + "/"
            probe = [f for f in files if f["path"].endswith(".json")][:3]
            bad = []
            for f in probe:
                r = self.fetcher.get(base + f["path"])
                if not r.ok or hashlib.sha256(r.body).hexdigest() != f["sha256"]:
                    bad.append(f["path"])
            if bad:
                self.add("seal_format", manifest_url, "high", "vector bytes match manifest sha256", f"mismatch: {bad}", "published vectors differ from manifest")
            else:
                self.add("seal_format", manifest_url, "info", "vector bytes match manifest sha256", f"{len(files)} files listed, {len(probe)} probed", "conformance vectors published")

    def _assess_seal_endpoint(self, path: str) -> None:
        surface = self.url(path, self.seal_host)
        result = self.fetcher.get(surface)
        if not result.ok:
            self.add("seal_format", surface, "high", "HTTP 200 JSON", result.describe(), "unreachable" if result.error else "seal service endpoint not 200")
            return
        try:
            payload = json.loads(result.text)
        except ValueError:
            self.add("seal_format", surface, "high", "HTTP 200 JSON", clip(result.text, 120), "seal service endpoint is not JSON")
            return
        self.add("seal_format", surface, "info", "HTTP 200 JSON", clip(payload), "seal service endpoint ok")

    def _assess_public_log(self, surface: str, seals: list[dict[str, Any]]) -> None:
        canon_seal = self.canon["seal"]
        expected_keys = set(canon_seal["signature_keys"])
        bad_version: list[str] = []
        bad_id: list[str] = []
        bad_signature: list[str] = []
        issuers: dict[str, int] = {}
        for index, seal in enumerate(seals):
            label = str(seal.get("seal_id", f"line {index + 1}"))
            if seal.get("seal_version") != canon_seal["seal_version"]:
                bad_version.append(f"{label}: {seal.get('seal_version')!r}")
            if not str(seal.get("seal_id", "")).startswith(canon_seal["seal_id_prefix"]):
                bad_id.append(label)
            signature = seal.get("signature")
            if not isinstance(signature, dict) or set(signature) != expected_keys:
                observed_keys = sorted(signature) if isinstance(signature, dict) else type(signature).__name__
                bad_signature.append(f"{label}: {observed_keys}")
            issuer = seal.get("issuer") or {}
            issuer_id = str(issuer.get("id", "?") if isinstance(issuer, dict) else issuer)
            issuers[issuer_id] = issuers.get(issuer_id, 0) + 1
        if not seals:
            self.add("seal_format", surface, "medium", "at least one seal", "empty log", "public log is empty")
            return
        if bad_version:
            self.add("seal_format", surface, "high", f"seal_version == {canon_seal['seal_version']!r}", f"{len(bad_version)} of {len(seals)}: {clip(bad_version[:3])}", "non-canonical seal_version in public log")
        if bad_id:
            self.add("seal_format", surface, "high", f"seal_id starts with {canon_seal['seal_id_prefix']!r}", f"{len(bad_id)} of {len(seals)}: {clip(bad_id[:3])}", "non-canonical seal_id in public log")
        if bad_signature:
            self.add("seal_format", surface, "high", f"signature keys == {sorted(expected_keys)}", f"{len(bad_signature)} of {len(seals)}: {clip(bad_signature[:3])}", "non-canonical signature object in public log")
        observed_issuers = ", ".join(f"{k} ({v})" for k, v in sorted(issuers.items()))
        if len(issuers) == 1 and "conformance" in next(iter(issuers)):
            self.add("seal_format", surface, "high", f"production issuers {canon_seal['production_issuers']}", observed_issuers, "public log contains only conformance vectors, no production seals")
        else:
            self.add("seal_format", surface, "info", "production issuers present", f"{len(seals)} seals; issuers: {observed_issuers}", "issuer breakdown")

    # ---- h. forbidden markers -------------------------------------------

    def check_forbidden(self) -> None:
        hosts = {self.domain, self.seal_host}
        markers = self.canon["seal"].get("forbidden_markers", [])
        words = self.canon.get("forbidden_words", [])
        seen: set[str] = set()
        for result in self.fetcher.cached_results():
            if result.method != "GET" or not result.ok or host_of(result.final_url) not in hosts:
                continue
            if not (result.is_html or path_of(result.final_url).endswith(TEXT_DOC_SUFFIXES)):
                continue
            if result.final_url in seen:
                continue
            seen.add(result.final_url)
            self._scan_forbidden(result.final_url, result.text, markers, words)

    def _scan_forbidden(self, surface: str, text: str, markers: list[str], words: list[str]) -> None:
        for marker in markers:
            position = text.find(marker)
            if position >= 0:
                self.add("forbidden_markers", surface, "medium", f"no {marker!r}", f"{text.count(marker)}x, e.g. …{snippet(text, position)}…", "non-canonical Seal marker on surface")
        for word in words:
            # A quoted occurrence ("hid", 'refused') is the wording rule itself, not a violation.
            pattern = re.compile(r"(?<![\"'“‘])\b" + re.escape(word) + r"\b(?![\"'”’])", re.I)
            matches = list(pattern.finditer(text))
            if matches:
                self.add("forbidden_markers", surface, "medium", f"no whole word {word!r}", f"{len(matches)}x, e.g. …{snippet(text, matches[0].start())}…", "forbidden wording on surface")

    # ---- i. headline numbers --------------------------------------------

    def check_headline(self) -> None:
        pulse = self.cached_json("/registry/data/_home_pulse.json")
        silence = self.cached_json("/registry/data/silence_index.json")
        anchors = self.cached_json("/registry/data/substrate/ots_anchors.json")
        candidates = self.cached_json("/registry/data/substrate/lacuna_candidates.json")
        trust_root = self.cached_json("/registry/data/substrate/trust_root.json")
        if pulse is None:
            self.add("headline_numbers", self.url("/registry/data/_home_pulse.json"), "high", "parseable pulse", "unavailable", "cannot audit headline numbers without the pulse")
            return
        if candidates is not None:
            self._assess_lacuna(pulse, candidates)
        self._assess_silence(pulse, silence)
        if anchors is not None:
            self._assess_anchors(anchors)
        if trust_root is not None:
            self._assess_consistency(pulse, trust_root)

    def _assess_lacuna(self, pulse: dict[str, Any], candidates_doc: dict[str, Any]) -> None:
        surface = self.url("/registry/data/_home_pulse.json")
        pulse_count = get_path(pulse, self.canon["headline_numbers"]["lacuna_records"]["path"])
        candidates = candidates_doc.get("candidates") or []
        patterns = [re.compile(p) for p in self.canon.get("internal_target_patterns", [])]
        model_targets = [c for c in candidates if not any(p.search(str(c.get("target_id", ""))) for p in patterns)]
        now = utcnow()
        week = timedelta(days=7)
        recent_models = [c for c in model_targets if (ts := parse_ts(c.get("last_seen"))) and now - ts <= week]
        last_seen = [ts for c in candidates if (ts := parse_ts(c.get("last_seen")))]
        newest = max(last_seen) if last_seen else None
        observed = (
            f"pulse AX.LAC={pulse_count}; candidates total={len(candidates)}, model-target={len(model_targets)}, "
            f"model-target seen in last 7d={len(recent_models)}, newest last_seen={newest.isoformat() if newest else 'n/a'}"
        )
        self.add("headline_numbers", surface, "info", "LACUNA count backed by recent model-target candidates", observed, "LACUNA reconciliation")
        if isinstance(pulse_count, (int, float)) and pulse_count > 0 and not recent_models:
            self.add("headline_numbers", surface, "critical", "0 LACUNA records, or model-target candidates observed within 7 days", observed, "LACUNA count shown while no model-target candidate has been observed in the last 7 days")
        collectors = {str(c.get("source_collector")) for c in candidates}
        live = [c for c in candidates if not c.get("stale")]
        if live:
            self.add("headline_numbers", self.url("/registry/data/substrate/lacuna_candidates.json"), "info", "live candidates present", f"{len(live)} non-stale candidates from {sorted({str(c.get('source_collector')) for c in live})}", "LACUNA candidates are live")
        elif candidates and len(collectors) == 1 and newest is not None and now - newest > week:
            self.add("headline_numbers", self.url("/registry/data/substrate/lacuna_candidates.json"), "high", "candidates from live collectors", f"collector={next(iter(collectors))}, newest last_seen={newest.isoformat()} ({(now - newest).days} days ago)", "all candidates from one dead collector")

    def _assess_silence(self, pulse: dict[str, Any], silence: Optional[dict[str, Any]]) -> None:
        surface = self.url("/registry/data/_home_pulse.json")
        top = get_path(pulse, "silence.top_silent") or {}
        if not top:
            self.add("headline_numbers", surface, "low", "silence.top_silent present", "missing", "pulse has no top_silent")
            return
        first_seen, last_seen = parse_ts(top.get("first_seen")), parse_ts(top.get("last_seen"))
        reported = top.get("absence_streak_days")
        if reported is None and silence:
            reported = (get_path(silence, "top_silent") or {}).get("silence_days")
        if first_seen is None or last_seen is None or not isinstance(reported, (int, float)):
            self.add("headline_numbers", surface, "low", "first_seen, last_seen, absence_streak_days", clip(top), "top_silent lacks the fields needed to recompute the streak")
            return
        computed = (last_seen - first_seen).days
        observed = f"{top.get('target_id')}: reported {reported} days, computed last_seen-first_seen = {computed} days, last_seen {last_seen.date().isoformat()}"
        if reported > computed + 2:
            self.add("headline_numbers", surface, "critical", f"absence_streak_days <= {computed + 2}", observed, "silence accrues after last observation")
        else:
            self.add("headline_numbers", surface, "info", "streak bounded by observation window", observed, "top_silent streak consistent with observations")

    def _assess_anchors(self, anchors_doc: dict[str, Any]) -> None:
        surface = self.url("/registry/data/substrate/ots_anchors.json")
        def _anchor_ts(a: dict[str, Any]) -> datetime | None:
            return parse_ts(a.get("stamped_at")) or parse_ts(a.get("anchor_date"))

        anchors = sorted(anchors_doc.get("anchors") or [], key=lambda a: (_anchor_ts(a) or datetime.min.replace(tzinfo=timezone.utc)).isoformat())
        roots = [str(a.get("merkle_root")) for a in anchors]
        longest = run = 0
        for index, root in enumerate(roots):
            run = run + 1 if index and root == roots[index - 1] else 1
            longest = max(longest, run)
        newest = max((ts for a in anchors if (ts := parse_ts(a.get("anchor_date")))), default=None)
        newest_label = newest.date().isoformat() if newest else "n/a"
        age_days = (utcnow() - newest).total_seconds() / 86400.0 if newest else None
        age_label = f" ({age_days:.1f} days old)" if age_days is not None else ""
        observed = (
            f"anchors={len(anchors)}, distinct merkle_root={len(set(roots))}, longest identical-root run={longest}, "
            f"newest anchor_date={newest_label}{age_label}"
        )
        self.add("headline_numbers", surface, "info", f"bitcoin_confirmed={anchors_doc.get('bitcoin_confirmed')} counts distinct roots", observed, "anchor reconciliation")
        # History before the 2026-09-19 fix legitimately holds a 38-long identical-root run. Re-anchoring is a live
        # problem only when the newest anchor repeats the one before it, or when a run of 3 forms inside the last 14 days.
        fortnight = utcnow() - timedelta(days=14)
        recent_roots = [str(a.get("merkle_root")) for a in anchors if (ts := _anchor_ts(a)) and ts >= fortnight]
        recent_run = run = 0
        for index, root in enumerate(recent_roots):
            run = run + 1 if index and root == recent_roots[index - 1] else 1
            recent_run = max(recent_run, run)
        if len(roots) >= 2 and roots[-1] == roots[-2]:
            self.add("headline_numbers", surface, "high", "each new anchor stamps a new root", f"newest anchor ({newest_label}) repeats the previous merkle_root {roots[-1][:16]}…", "repeated anchoring of unchanged root")
        elif recent_run >= 3:
            self.add("headline_numbers", surface, "medium", "each new anchor stamps a new root", f"{recent_run} anchors of the last 14 days share one merkle_root (historical longest run {longest})", "repeated anchoring of unchanged root")
        elif longest >= 3:
            self.add("headline_numbers", surface, "info", "history acknowledged", f"historical identical-root run of {longest} before 2026-09-19; last 14 days: {len(recent_roots)} anchors, {len(set(recent_roots))} distinct roots", "legacy re-anchoring visible in history only")
        if age_days is not None and age_days > 3:
            self.add("headline_numbers", surface, "high", "newest anchor <= 3 days old", f"newest anchor_date {newest_label} is {age_days:.1f} days old", "anchoring stalled")

    def _assess_consistency(self, pulse: dict[str, Any], trust_root: dict[str, Any]) -> None:
        surface = self.url("/registry/data/substrate/trust_root.json")
        pulse_total = get_path(pulse, "ledger.n_envelopes_total")
        root_total = trust_root.get("ledger_envelope_count")
        if not isinstance(pulse_total, (int, float)) or not isinstance(root_total, (int, float)):
            self.add("headline_numbers", surface, "low", "numeric envelope counts", f"pulse={pulse_total!r}, trust_root={root_total!r}", "cannot compare envelope counts")
            return
        drift = abs(pulse_total - root_total) / max(1.0, float(max(pulse_total, root_total)))
        observed = f"pulse n_envelopes_total={pulse_total}, trust_root ledger_envelope_count={root_total} ({drift:.2%} apart)"
        severity = "medium" if drift > 0.02 else "info"
        self.add("headline_numbers", surface, severity, "counts within 2%", observed, "envelope counts disagree" if drift > 0.02 else "envelope counts consistent")

    # ---- j. MCP ---------------------------------------------------------

    def check_mcp(self) -> None:
        endpoint = self.canon["apis"]["mcp"]
        result, message = self._mcp_call(1, "tools/list", {})
        if not result.ok or message is None or "result" not in message:
            self.add("mcp", endpoint, "high", "JSON-RPC tools/list result", f"{result.describe()}: {clip(result.text, 120)}", "MCP tools/list failed")
            return
        names = {str(t.get("name")) for t in message["result"].get("tools", [])}
        expected = set(self.canon["apis"]["mcp_tools"])
        if names != expected:
            self.add("mcp", endpoint, "high", sorted(expected), f"missing={sorted(expected - names)}, extra={sorted(names - expected)}", "MCP tool set differs from canon")
        else:
            self.add("mcp", endpoint, "info", sorted(expected), sorted(names), "MCP tool set matches canon")
        pulse_text = self._mcp_tool_text(2, "crovia_pulse", {})
        if pulse_text is not None:
            self.add("mcp", endpoint, "info", "crovia_pulse answers", clip(pulse_text), "MCP crovia_pulse response")
        self._assess_lookup(endpoint)

    def _assess_lookup(self, endpoint: str) -> None:
        pulse = self.cached_json("/registry/data/_home_pulse.json") or {}
        target = (get_path(pulse, "silence.top_silent") or {}).get("target_id")
        if not target:
            self.add("mcp", endpoint, "low", "top_silent.target_id available", "missing", "cannot cross-check lookup_model without a featured model")
            return
        arg = self.canon["apis"].get("mcp_model_arg", "model")
        text = self._mcp_tool_text(3, "lookup_model", {arg: target})
        if text is None:
            return
        try:
            lookup = json.loads(text)
        except ValueError:
            self.add("mcp", endpoint, "medium", "lookup_model returns JSON text", clip(text), "lookup_model text content is not JSON")
            return
        status = str(lookup.get("disclosure_status", "")) if isinstance(lookup, dict) else ""
        lacuna_empty = isinstance(lookup, dict) and "lacuna" in lookup and not lookup.get("lacuna")
        observed = f"lookup_model({target}) -> disclosure_status={status!r}, lacuna={clip(lookup.get('lacuna') if isinstance(lookup, dict) else None, 80)}"
        if "no_absence" in status or lacuna_empty:
            self.add("mcp", endpoint, "critical", f"lookup_model agrees that {target} is the top silent model", observed, "featured model contradicts MCP lookup")
        else:
            self.add("mcp", endpoint, "info", "lookup_model consistent with pulse", observed, "featured model confirmed by MCP lookup")

    def _mcp_tool_text(self, request_id: int, tool: str, arguments: dict[str, Any]) -> Optional[str]:
        endpoint = self.canon["apis"]["mcp"]
        result, message = self._mcp_call(request_id, "tools/call", {"name": tool, "arguments": arguments})
        if not result.ok or message is None or "result" not in message:
            error = (message or {}).get("error") if message else None
            self.add("mcp", endpoint, "high", f"tools/call {tool} succeeds", f"{result.describe()}: {clip(error or result.text, 120)}", f"MCP {tool} call failed")
            return None
        content = message["result"].get("content") or []
        texts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
        if not texts:
            self.add("mcp", endpoint, "medium", f"{tool} returns text content", clip(message["result"]), f"MCP {tool} returned no text content")
            return None
        return "\n".join(texts)

    def _mcp_call(self, request_id: int, method: str, params: dict[str, Any]) -> tuple[FetchResult, Optional[dict[str, Any]]]:
        payload = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
        headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
        result = self.fetcher.post(self.canon["apis"]["mcp"], payload, headers)
        return result, parse_jsonrpc(result.text) if result.body else None

    # ---- k. repos -------------------------------------------------------

    def check_repos(self) -> None:
        for name, spec in self.canon.get("repos", {}).items():
            repo_dir = REPO_ROOT / name
            if spec.get("state") != "active" or not repo_dir.is_dir():
                continue
            self._assess_repo(name, spec, repo_dir)

    def _assess_repo(self, name: str, spec: dict[str, Any], repo_dir: Path) -> None:
        surface = f"repo:{name}"
        readme = next((p for p in (repo_dir / "README.md", repo_dir / "readme.md", repo_dir / "README.rst") if p.is_file()), None)
        if readme is None:
            self.add("repos", surface, "low", "README.md", "missing", "README does not state canonical role")
        else:
            self._assess_readme(surface, spec, readme.read_text("utf-8", "replace"))
        if not (repo_dir / ".github" / "workflows").is_dir():
            self.add("repos", surface, "low", ".github/workflows present", "missing", "no CI")

    def _assess_readme(self, surface: str, spec: dict[str, Any], text: str) -> None:
        role_head = " ".join(str(spec.get("role", "")).split()[:6])
        one_liner = " ".join(self.canon["identity"]["one_liner"].split())
        flat = " ".join(text.replace("*", "").split())  # README prose is hard-wrapped and may be bold
        if (role_head and role_head in flat) or one_liner in flat:
            self.add("repos", surface, "info", "README states canonical role or one-liner", "present", "README states canonical role")
        else:
            self.add("repos", surface, "low", f"README contains {role_head!r} or the identity one-liner", clip(text.strip().splitlines()[0] if text.strip() else ""), "README does not state canonical role")
        for marker in list(self.canon["seal"].get("forbidden_markers", [])) + list(self.canon["retired_paths"]):
            position = text.find(marker)
            if position >= 0:
                self.add("repos", surface, "medium", f"no {marker!r} in README", f"…{snippet(text, position)}…", "README references a non-canonical Seal marker or a retired path")

    # ---- orchestration --------------------------------------------------

    def run(self) -> None:
        for name, fn in (
            ("pages", self.check_pages),
            ("retired_paths", self.check_retired),
            ("mirror_parity", self.check_mirror),
            ("data_files", self.check_data_files),
            ("private_files", self.check_private_files),
            ("links", self.check_links),
            ("seal_format", self.check_seal),
            ("headline_numbers", self.check_headline),
            ("mcp", self.check_mcp),
            ("forbidden_markers", self.check_forbidden),
            ("repos", self.check_repos),
        ):
            self.run_check(name, fn)


def extract_links(text: str, is_html: bool) -> Iterator[str]:
    absolute = re.compile(r"https?://(?:[a-z0-9-]+\.)*croviatrust\.com(?:/[^\s\"'<>)\]\\,]*)?", re.I)
    for match in absolute.finditer(text):
        yield match.group(0).rstrip(".;:")
    if is_html:
        for match in re.finditer(r"""(?:href|src|action)\s*=\s*["'](/[^"'#]*)["']""", text, re.I):
            if not match.group(1).startswith("//"):
                yield match.group(1)
    else:
        for match in re.finditer(r"(?<![\w:/.@])(/(?:registry|\.well-known|api|mcp|whitepaper|proof|llms|robots|sitemap)[^\s\"'<>)\]\\,`]*)", text):
            yield match.group(1).rstrip(".;:")


def summarize(findings: list[Finding]) -> dict[str, Any]:
    by_severity = {severity: 0 for severity in SEVERITIES}
    by_check: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_check[finding.check] = by_check.get(finding.check, 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_check": dict(sorted(by_check.items()))}


def sort_key(finding: Finding) -> tuple[int, str, str]:
    return SEVERITIES.index(finding.severity), finding.check, finding.surface


def render_markdown(audit: Audit, generated_at: datetime, summary: dict[str, Any]) -> str:
    lines = [
        "# Crovia surface audit",
        "",
        f"- Generated: {generated_at.isoformat(timespec='seconds')}",
        f"- Base: {audit.base}",
        f"- Canon revision: {audit.canon.get('revised')} ({audit.canon.get('schema')})",
        f"- Requests made: {len(audit.fetcher.log)}",
        f"- Findings: {summary['total']}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    lines += [f"| {severity} | {summary['by_severity'].get(severity, 0)} |" for severity in SEVERITIES]
    ordered = sorted(audit.findings, key=sort_key)
    for severity in SEVERITIES:
        group = [f for f in ordered if f.severity == severity]
        if not group:
            continue
        lines += ["", f"## {severity.capitalize()} ({len(group)})", ""]
        for finding in group:
            lines.append(
                f"- **[{finding.check}]** {finding.surface} — {finding.note} "
                f"(expected: {clip(finding.expected)}, observed: {clip(finding.observed)})"
            )
    lines += ["", "## Pages", "", "| Path | Status | Final URL | Size | Title |", "|---|---|---|---|---|"]
    for path, info in audit.pages.items():
        title = clip(info["title"], 60).replace("|", "\\|")
        lines.append(f"| `{path}` | {info['status']} | {info['final_url']} | {info['size']} | {title} |")
    lines.append("")
    return "\n".join(lines)


def write_reports(audit: Audit, out_dir: Path, generated_at: datetime) -> tuple[Path, Path, dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = summarize(audit.findings)
    for entry in audit.fetcher.log:
        entry["age_hours"] = audit.ages.get(entry["url"])
    report = {
        "schema": "crovia.surface_audit.v1",
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "base": audit.base,
        "canon_revision": audit.canon.get("revised"),
        "canon_schema": audit.canon.get("schema"),
        "summary": summary,
        "findings": [asdict(f) for f in sorted(audit.findings, key=sort_key)],
        "pages": audit.pages,
        "fetched": audit.fetcher.log,
    }
    stamp = generated_at.isoformat(timespec="seconds").replace(":", "-")
    json_path = out_dir / f"surface_audit_{stamp}.json"
    md_path = out_dir / "surface_audit_latest.md"
    json_path.write_text(json.dumps(report, indent=2, default=str, ensure_ascii=False) + "\n", "utf-8")
    md_path.write_text(render_markdown(audit, generated_at, summary), "utf-8")
    return json_path, md_path, summary


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit Crovia Trust's live public surfaces against canon.json.")
    parser.add_argument("--canon", default="canon/canon.json", help="path to canon.json")
    parser.add_argument("--out", default="reports/", help="directory for the JSON and Markdown reports")
    parser.add_argument("--base", default="https://croviatrust.com", help="base URL of the canonical site")
    parser.add_argument("--concurrency", type=int, default=3, help="parallel requests (never for /registry/data/)")
    parser.add_argument("--delay", type=float, default=1.5, help="seconds between requests to the same host")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-request timeout in seconds")
    parser.add_argument("--gate", action="store_true", help="exit 1 if any critical or high finding exists")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    canon = json.loads(Path(args.canon).read_text("utf-8"))
    generated_at = utcnow().replace(microsecond=0)
    audit = Audit(canon=canon, base=args.base.rstrip("/"), fetcher=Fetcher(args.delay, args.timeout), concurrency=args.concurrency)
    audit.run()
    json_path, md_path, summary = write_reports(audit, Path(args.out), generated_at)
    counts = summary["by_severity"]
    print(" ".join(f"{severity}={counts.get(severity, 0)}" for severity in SEVERITIES) + f" total={summary['total']}")
    print(f"json: {json_path}")
    print(f"markdown: {md_path}")
    if args.gate and (counts.get("critical", 0) or counts.get("high", 0)):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
