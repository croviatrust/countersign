"""Fetch a surface and record what a verifier needs: status, bytes, TLS leaf hash, peer IP."""
from __future__ import annotations

import hashlib
import http.client
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from .config import USER_AGENT


@dataclass
class Fetched:
    url: str
    status: int
    body: bytes
    tls_cert_sha256: Optional[bytes]
    resolved_ip: Optional[str]
    fetched_at: str
    elapsed_ms: int
    error: Optional[str] = None


class _CapturingHTTPS(http.client.HTTPSConnection):
    """HTTPSConnection that remembers the leaf certificate and peer address."""

    cert_der: Optional[bytes] = None
    peer_ip: Optional[str] = None

    def connect(self) -> None:  # type: ignore[override]
        super().connect()
        try:
            self.cert_der = self.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
            self.peer_ip = self.sock.getpeername()[0]  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            pass


def fetch(url: str, timeout: float = 25.0, max_bytes: int = 8_000_000, max_redirects: int = 4) -> Fetched:
    started = time.time()
    fetched_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    current = url
    cert = ip = None
    for _ in range(max_redirects + 1):
        parts = urlsplit(current)
        if parts.scheme != "https":
            return Fetched(url, 0, b"", None, None, fetched_at, 0, error="only https surfaces are observed")
        ctx = ssl.create_default_context()
        conn = _CapturingHTTPS(parts.hostname, parts.port or 443, timeout=timeout, context=ctx)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        try:
            conn.request("GET", path, headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/markdown, text/plain, text/html;q=0.9, */*;q=0.5",
                "Accept-Encoding": "identity",
            })
            resp = conn.getresponse()
            body = resp.read(max_bytes + 1)
            status = resp.status
            cert = conn.cert_der or cert
            ip = conn.peer_ip or ip
            location = resp.getheader("Location")
        except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout) as e:
            return Fetched(url, 0, b"", None, None, fetched_at, int((time.time() - started) * 1000), error=str(e)[:200])
        finally:
            conn.close()
        if status in (301, 302, 303, 307, 308) and location:
            if location.startswith("/"):
                location = f"{parts.scheme}://{parts.netloc}{location}"
            current = location
            continue
        if len(body) > max_bytes:
            return Fetched(url, status, b"", None, ip, fetched_at, int((time.time() - started) * 1000), error="body exceeds max_bytes")
        return Fetched(
            url=current, status=status, body=body,
            tls_cert_sha256=hashlib.sha256(cert).digest() if cert else None,
            resolved_ip=ip, fetched_at=fetched_at, elapsed_ms=int((time.time() - started) * 1000),
        )
    return Fetched(url, 0, b"", None, ip, fetched_at, int((time.time() - started) * 1000), error="too many redirects")
