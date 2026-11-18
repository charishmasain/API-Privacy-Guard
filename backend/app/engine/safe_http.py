"""Hardened HTTP client used exclusively by the BOLA detection engine.

Guarantees:
  * read-only methods only (GET/HEAD) - enforced by ssrf_guard.assert_method_allowed
  * destination allow-listing + DNS revalidation on every single request
  * redirects are NEVER followed (a 3xx is reported as-is with its Location)
  * strict timeout and response-size cap
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.core.config import MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_SECONDS
from app.core.ssrf_guard import (
    SSRFBlockedError,
    assert_method_allowed,
    validate_destination,
)


@dataclass
class ResponseOutcome:
    """Normalised result of one HTTP exchange (or an error description)."""

    status: Optional[int] = None
    headers: dict = field(default_factory=dict)
    body_text: str = ""
    truncated: bool = False
    elapsed_ms: float = 0.0
    error: Optional[str] = None          # transport / policy error if any
    blocked_by_policy: bool = False      # SSRF guard stopped the request
    redirect_location: Optional[str] = None
    url: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None

    def json(self) -> Optional[object]:
        try:
            return json.loads(self.body_text)
        except (ValueError, TypeError):
            return None


class SafeHttpClient:
    """Issue credentialed requests ONLY against an explicitly approved host."""

    def __init__(self, base_url: str, approved_host: str, allow_localhost: bool = False):
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"invalid base_url: {base_url}")
        self.base_url = base_url.rstrip("/") + "/"
        self.approved_host = parsed.hostname.lower()
        self.allow_localhost = allow_localhost

    def build_url(self, path: str) -> str:
        # urljoin with a leading-slash path keeps us on the same origin.
        return urljoin(self.base_url, path.lstrip("/"))

    def request(
        self,
        method: str,
        path: str,
        token: Optional[str] = None,
        extra_headers: Optional[dict] = None,
    ) -> ResponseOutcome:
        url = self.build_url(path)
        try:
            assert_method_allowed(method)
            validate_destination(url, self.approved_host, self.allow_localhost)
        except (SSRFBlockedError, ValueError) as exc:
            return ResponseOutcome(url=url, error=str(exc), blocked_by_policy=True)

        headers = dict(extra_headers or {})
        if token:
            headers["Authorization"] = f"Bearer {token}"

        start = time.perf_counter()
        try:
            with httpx.Client(
                timeout=REQUEST_TIMEOUT_SECONDS,
                follow_redirects=False,
                max_redirects=0,
            ) as client:
                with client.stream(method.upper(), url, headers=headers) as resp:
                    chunks: list[bytes] = []
                    total = 0
                    truncated = False
                    for chunk in resp.iter_bytes():
                        chunks.append(chunk[: max(0, MAX_RESPONSE_BYTES - total)])
                        total += len(chunk)
                        if total >= MAX_RESPONSE_BYTES:
                            truncated = True
                            break
                    body = b"".join(chunks)
                    location = resp.headers.get("location")
                    # If a redirect leaks to an unapproved host, flag it loudly.
                    redirect_issue = None
                    if resp.status_code in (301, 302, 303, 307, 308) and location:
                        abs_loc = urljoin(url, location)
                        try:
                            validate_destination(
                                abs_loc, self.approved_host, self.allow_localhost
                            )
                        except SSRFBlockedError as exc:
                            redirect_issue = f"redirect target not approved: {exc}"
                    outcome = ResponseOutcome(
                        status=resp.status_code,
                        headers=dict(resp.headers),
                        body_text=body.decode(resp.encoding or "utf-8", errors="replace"),
                        truncated=truncated,
                        elapsed_ms=(time.perf_counter() - start) * 1000.0,
                        redirect_location=location,
                        url=url,
                    )
                    if redirect_issue:
                        outcome.error = redirect_issue
                        outcome.blocked_by_policy = True
                    return outcome
        except httpx.HTTPError as exc:
            return ResponseOutcome(
                url=url,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=(time.perf_counter() - start) * 1000.0,
            )
