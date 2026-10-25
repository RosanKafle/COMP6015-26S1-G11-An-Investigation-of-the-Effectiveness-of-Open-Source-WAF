"""Restricted, bounded HTTP transport shared by every milestone."""
from __future__ import annotations
import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128"))

def validate_url(url: str) -> str:
    """Accept literal private lab addresses or localhost; never resolve arbitrary DNS."""
    if not isinstance(url, str) or any(ord(c) < 33 for c in url) or "\\" in url:
        raise ValueError("URL must be a nonempty HTTP(S) URL without whitespace or backslashes.")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Use an http:// or https:// lab URL.")
    if parts.username is not None or parts.password is not None or parts.fragment or parts.query:
        raise ValueError("Base URL must not contain credentials, query, or fragment.")
    _ = parts.port  # Validate port syntax and range.
    host = parts.hostname
    if host == "localhost":
        return url.rstrip("/")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("Use localhost or a literal RFC1918 lab IP; DNS names are refused.") from exc
    if not any(address.version == net.version and address in net for net in NETWORKS):
        raise ValueError("Target refused: only localhost, loopback and RFC1918 lab IPs are allowed.")
    if "%" in host:
        raise ValueError("Scoped IPv6 addresses are unsupported.")
    return url.rstrip("/")

def validate_endpoint(endpoint: str) -> None:
    """Forbid changing the configured origin through a test case."""
    if not isinstance(endpoint, str) or not endpoint.startswith("/") or endpoint.startswith("//"):
        raise ValueError("Endpoint must start with a single slash.")
    p = urlsplit(endpoint)
    if p.scheme or p.netloc or p.fragment or p.query or "\\" in endpoint:
        raise ValueError("Endpoint must be a relative path with parameters in separate CSV fields.")
    if any(ord(c) < 33 or ord(c) > 126 for c in endpoint):
        raise ValueError("Endpoint must be ASCII without whitespace/control characters.")

@dataclass
class Response:
    status: int
    body: bytes
    headers: dict[str, str]
    truncated: bool

def request(base_url: str, endpoint: str = "/", method: str = "GET",
            query: str = "", body: bytes | None = None,
            headers: dict[str, str] | None = None, timeout: float = 10,
            max_bytes: int = 1048576) -> Response:
    """No redirects, proxies, retries or DNS rebinding; localhost is pinned to 127.0.0.1."""
    base = urlsplit(validate_url(base_url))
    validate_endpoint(endpoint)
    if method not in ("GET", "POST", "HEAD"):
        raise ValueError("Only GET, POST and HEAD are supported.")
    if any(ord(c) < 32 or ord(c) > 126 for c in query):
        raise ValueError("Query must be encoded ASCII.")
    if not 0 < timeout <= 120 or not 1 <= max_bytes <= 10485760:
        raise ValueError("Invalid timeout or response size limit.")
    host = "127.0.0.1" if base.hostname == "localhost" else base.hostname
    port = base.port or (443 if base.scheme == "https" else 80)
    cls = http.client.HTTPSConnection if base.scheme == "https" else http.client.HTTPConnection
    options = {"timeout": timeout}
    if base.scheme == "https":
        options["context"] = ssl.create_default_context()
    connection = cls(host, port, **options)
    path = base.path.rstrip("/") + endpoint
    if query:
        path += "?" + query
    try:
        deadline = time.monotonic() + timeout
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        chunks = bytearray()
        while len(chunks) <= max_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Response exceeded request time budget.")
            # HTTP/1.0 may detach connection.sock while the response owns the socket.
            if connection.sock:
                connection.sock.settimeout(remaining)
            piece = response.read1(min(65536, max_bytes + 1 - len(chunks)))
            if not piece:
                break
            chunks.extend(piece)
        return Response(response.status, bytes(chunks[:max_bytes]),
                        {k.lower(): v for k, v in response.getheaders()}, len(chunks) > max_bytes)
    finally:
        connection.close()

NETWORK_ERRORS = (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout)
