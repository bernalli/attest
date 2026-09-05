"""Tests for `attest_bridge._http`: the shared https-only, redirect-refusing
GET primitive both platform adapters route their `_default_http_get` through
(2026-07 security review, fix 3). The Bearer token these adapters send must never be
replayed across a redirect to another (or non-https) origin -- see the
module docstring in `_http.py` for the full argument. Hermetic: no network.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest
from attest_bridge import _http


def test_https_get_refuses_redirects() -> None:
    # Pins the never-follow contract directly on the handler: whatever
    # `urlopen` would pass in on a 3xx response, `redirect_request` must
    # always return None (which `HTTPRedirectHandler` turns into a plain
    # `HTTPError` instead of a followed redirect).
    handler = _http._NoRedirect()
    result = handler.redirect_request(
        None,  # req
        None,  # fp
        302,  # code
        "redirected",  # msg
        {},  # headers
        "https://attacker.example.test/steal-the-bearer-token",  # newurl
    )
    assert result is None


def test_https_get_rejects_non_https_url() -> None:
    with pytest.raises(ValueError, match="non-https"):
        _http.https_get("http://api.example.test/purchases", {})


def test_https_get_passes_the_shared_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b"{}"

    class Opener:
        def open(self, request: object, *, timeout: float) -> Response:
            seen["timeout"] = timeout
            return Response()

    monkeypatch.setattr(_http, "_OPENER", Opener())
    assert _http.https_get("https://api.example.test/purchases", {}) == b"{}"
    assert seen["timeout"] == _http.HTTP_TIMEOUT_SECONDS


def test_https_post_refuses_a_non_https_url_before_opening(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Opener:
        def open(self, request: object, *, timeout: float) -> None:
            pytest.fail("the opener must not be called for a non-https URL")

    monkeypatch.setattr(_http, "_OPENER", Opener())
    with pytest.raises(ValueError, match="non-https"):
        _http.https_post("http://api.example.test/verify", {}, b"{}")


def test_https_post_sends_the_body_and_headers_verbatim_and_never_follows_a_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}
    body = b'{"raw":"exact bytes"}'
    headers = {
        "Authorization": "Bearer exact-value",
        "Content-Type": "application/json; charset=utf-8",
    }

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"verification_status":"SUCCESS"}'

    class Opener:
        def open(self, request: urllib.request.Request, *, timeout: float) -> Response:
            seen["request"] = request
            seen["timeout"] = timeout
            return Response()

    monkeypatch.setattr(_http, "_OPENER", Opener())
    assert (
        _http.https_post("https://api.example.test/verify", headers, body)
        == b'{"verification_status":"SUCCESS"}'
    )

    request = seen["request"]
    assert isinstance(request, urllib.request.Request)
    assert request.data is body
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == headers["Authorization"]
    assert request.get_header("Content-type") == headers["Content-Type"]
    assert seen["timeout"] == _http.HTTP_TIMEOUT_SECONDS

    redirect_error = urllib.error.HTTPError(
        "https://api.example.test/verify", 302, "Found", {}, None
    )

    class RedirectingOpener:
        def open(self, request: object, *, timeout: float) -> None:
            raise redirect_error

    monkeypatch.setattr(_http, "_OPENER", RedirectingOpener())
    with pytest.raises(urllib.error.HTTPError) as caught:
        _http.https_post("https://api.example.test/verify", headers, body)
    assert caught.value is redirect_error
