"""SSRF prevention / destination allow-listing.

Policy enforced on EVERY outbound request:
  1. Scheme must be http/https.
  2. Host must EXACTLY match the explicitly approved target host.
  3. DNS is re-resolved per request and every resolved IP is validated:
     - link-local / cloud-metadata ranges are ALWAYS blocked,
     - private/loopback ranges are blocked unless the target was created
       with the explicit "local development" flag (used by the mock APIs).
  4. Redirects are never followed by the client (checked separately).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from app.core.config import ALLOWED_METHODS

LOCALHOST_NAMES = {"localhost", "127.0.0.1", "::1"}


class SSRFBlockedError(Exception):
    """Raised when a request destination violates the allow-list policy."""


def _always_blocked(ip: ipaddress._BaseAddress) -> bool:
    # loopback (::1 is flagged 'reserved' by some Python ipaddress versions)
    # is handled by the explicit allow-localhost policy, never here
    if ip.is_loopback:
        return False
    return (
        ip.is_unspecified
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None
            and _always_blocked(ip.ipv4_mapped))
    )


def validate_destination(url: str, approved_host: str, allow_localhost: bool) -> None:
    """Validate a full URL against the approved target; raise SSRFBlockedError."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError(f"scheme '{parsed.scheme}' not allowed (http/https only)")
    host = (parsed.hostname or "").lower()
    if not host:
        raise SSRFBlockedError("URL has no host component")
    if host != approved_host.lower():
        raise SSRFBlockedError(
            f"host '{host}' is not the explicitly approved host '{approved_host}'"
        )

    # Re-resolve DNS on every request and vet each address.
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                   proto=socket.AF_UNSPEC)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"DNS resolution failed for '{host}': {exc}") from exc

    if not infos:
        raise SSRFBlockedError(f"no DNS answers for '{host}'")

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _always_blocked(ip):
            raise SSRFBlockedError(f"destination {host} resolves to prohibited address {ip}")
        if (ip.is_private or ip.is_loopback) and not allow_localhost:
            raise SSRFBlockedError(
                f"destination {host} resolves to private/loopback address {ip}; "
                "enable 'local development' on the target to allow this"
            )


def normalize_host(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("base_url must be a valid http(s) URL with a host")
    return parsed.hostname.lower()


def assert_method_allowed(method: str) -> None:
    m = method.upper()
    if m not in ALLOWED_METHODS:
        raise ValueError(
            f"method '{m}' is prohibited by the read-only scanning policy "
            f"(allowed: {sorted(ALLOWED_METHODS)})"
        )
