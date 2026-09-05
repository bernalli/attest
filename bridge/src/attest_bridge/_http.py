"""Shared outbound-HTTP primitives: https-only, redirect-REFUSING GET and POST.

Refusing redirects is a security property, not a nicety: the platform APIs are
called with `Authorization: Bearer <api key>`, and Python's default redirect
handler would copy that header across a redirect to another (or non-https)
origin — leaking the key and letting an attacker's response become the
issuance authority. Returning None from `redirect_request` turns any 3xx into
an HTTPError, which each adapter maps to its own *ApiError.
The same argument applies to POST requests carrying `Authorization`.
"""

from __future__ import annotations

import urllib.request
from typing import Any


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # never follow a redirect


_OPENER = urllib.request.build_opener(_NoRedirect)
HTTP_TIMEOUT_SECONDS = 10.0


def https_get(url: str, headers: dict[str, str]) -> bytes:
    """GET `url` (must be https) with `headers`; refuse redirects. Returns the
    response body bytes. Raises `ValueError` on a non-https URL and
    `urllib.error.*` on transport/HTTP errors (callers wrap those)."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing to fetch a non-https URL: {url!r}")
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - https validated; redirects refused
    with _OPENER.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        data: bytes = response.read()
        return data


def https_post(url: str, headers: dict[str, str], body: bytes) -> bytes:
    """POST `body` to `url` (must be https) with `headers`; refuse redirects.

    Returns the response body bytes. Raises `ValueError` on a non-https URL and
    `urllib.error.*` on transport/HTTP errors (callers wrap those).
    """
    if not url.startswith("https://"):
        raise ValueError(f"refusing to fetch a non-https URL: {url!r}")
    request = urllib.request.Request(  # noqa: S310 - https validated; redirects refused
        url, data=body, headers=headers, method="POST"
    )
    with _OPENER.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        data: bytes = response.read()
        return data
