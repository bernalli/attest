"""Delivery: merchant SMTP send + zero-config download-link fallback.

No real network: `_FakeSMTP` is injected via `smtp_factory` and records every
call the transport policy makes (`starttls`/`login`/`send_message`/`quit`),
including the context-manager protocol `Delivery.send` relies on.
"""

from __future__ import annotations

import io
import json
import smtplib
import ssl
import stat
import zipfile
from dataclasses import replace
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest
from attest_bridge import pair as pair_mod
from attest_bridge.config import DeliveryConfig
from attest_bridge.delivery import (
    MAX_DELIVERY_ATTEMPTS,
    SMTP_TIMEOUT_SECONDS,
    Delivery,
    DeliveryResult,
    sweep_undelivered,
)
from attest_bridge.ledger import Ledger
from conftest import ISSUER, LEGAL_TEXT, LEGAL_TEXT_SHA256

_SALT = "not-a-real-secret-but-treat-it-like-one"
_RECEIPT_ID = "r_test_0001"
# The slug the bundle filename derives from `merchant.example.com`.
_SLUG = "merchant-example-com"
# Shape-faithful to what `attest.issue.issue` embeds at issuance: the issuer's
# key manifest travels INSIDE the envelope (`delivery.issuer_manifest`), which
# is the only place delivery can read it from — `sweep_undelivered` has no
# issuer identity in scope at all.
_ISSUER_MANIFEST: dict[str, Any] = {"issuer": ISSUER, "manifest_version": 1, "keys": []}

_ENVELOPE: dict[str, Any] = {
    "payload": {
        "receipt_id": _RECEIPT_ID,
        "issuer": {"id": ISSUER, "display_name": "Example Games Store"},
        "work": {"title": "Stardrift Chronicles"},
        "license": {"legal_text_sha256": LEGAL_TEXT_SHA256},
    },
    "delivery": {"salt": _SALT, "issuer_manifest": _ISSUER_MANIFEST},
    "signatures": {"ed25519": "deadbeef"},
}

_LEGAL_TEXTS: dict[str, bytes] = {LEGAL_TEXT_SHA256: LEGAL_TEXT}


class _FakeSMTP:
    """Records starttls/login/send_message/quit calls; supports `with`."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.starttls_calls: list[ssl.SSLContext | None] = []
        self.login_calls: list[tuple[str, str]] = []
        self.sent_messages: list[EmailMessage] = []
        self.quit_called = False

    def starttls(self, *, context: ssl.SSLContext | None = None) -> None:
        self.starttls_calls.append(context)

    def login(self, username: str, password: str) -> None:
        self.login_calls.append((username, password))

    def send_message(self, message: EmailMessage) -> None:
        self.sent_messages.append(message)

    def quit(self) -> None:
        self.quit_called = True

    def __enter__(self) -> _FakeSMTP:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.quit()


class _RaisingSMTP(_FakeSMTP):
    """A fake whose login raises, to exercise the never-raise contract."""

    def __init__(self, host: str, port: int, exc: Exception) -> None:
        super().__init__(host, port)
        self._exc = exc

    def login(self, username: str, password: str) -> None:
        raise self._exc


class _RaisingSmtpCode(smtplib.SMTPException):
    """An SMTP exception whose `smtp_code` accessor itself raises — _safe_detail
    must not let that new exception escape send()."""

    @property
    def smtp_code(self) -> int:
        raise RuntimeError("hostile accessor")


class _HostileInt(int):
    """An int subclass whose formatting emits attacker-controlled text — must
    never reach the sanitized detail (only an EXACT built-in int is formatted)."""

    def __format__(self, spec: str) -> str:
        return "HOSTILE-FORMAT-LEAK"

    def __str__(self) -> str:
        return "HOSTILE-FORMAT-LEAK"


class _HostileCodeException(smtplib.SMTPException):
    smtp_code = _HostileInt(535)


class _HostileNameException(smtplib.SMTPException):
    """Its class __name__ is set to attacker-controlled text below — the
    sanitized detail must come from the trusted type table, not __name__."""


_HostileNameException.__name__ = "HOSTILE-NAME-LEAK"


def _config(*, port: int = 587) -> DeliveryConfig:
    return DeliveryConfig(
        smtp_host="smtp.example.com",
        smtp_port=port,
        smtp_username="merchant",
        smtp_password="hunter2-super-secret",  # noqa: S106 - test fixture, not a real secret
        from_address="receipts@merchant.example.com",
        info_url="https://merchant.example.com/attest/what-is-this",
    )


def _fake_factory(store: list[_FakeSMTP]) -> Any:
    def factory(host: str, port: int) -> _FakeSMTP:
        fake = _FakeSMTP(host, port)
        store.append(fake)
        return fake

    return factory


def _send(
    config: DeliveryConfig,
    factory: Any,
    *,
    info_url: str | None = None,
    envelope: dict[str, Any] | None = None,
    legal_texts: dict[str, bytes] | None = None,
    receipt_id: str = _RECEIPT_ID,
) -> DeliveryResult:
    delivery = Delivery(
        config,
        smtp_factory=factory,
        legal_texts=_LEGAL_TEXTS if legal_texts is None else legal_texts,
    )
    return delivery.send(
        to_email="buyer@example.com",
        receipt_id=receipt_id,
        work_title="Stardrift Chronicles",
        envelope=envelope if envelope is not None else _ENVELOPE,
        download_url="https://receipts.example.com/r/tok_abc123",
        info_url=info_url,
    )


def _attachments(fake: _FakeSMTP) -> list[Any]:
    return list(fake.sent_messages[0].iter_attachments())


def _attachment_bytes(attachment: Any) -> bytes:
    content = attachment.get_content()
    return content.encode("utf-8") if isinstance(content, str) else bytes(content)


# -- message shape --------------------------------------------------------


def test_send_sets_subject_from_and_to() -> None:
    fakes: list[_FakeSMTP] = []
    result = _send(_config(), _fake_factory(fakes))
    assert result.status == "sent"
    message = fakes[0].sent_messages[0]
    assert message["Subject"] == "Your receipt for Stardrift Chronicles"
    assert message["From"] == "receipts@merchant.example.com"
    assert message["To"] == "buyer@example.com"


def test_send_attaches_shareable_and_private_bundle_pair() -> None:
    fakes: list[_FakeSMTP] = []
    assert _send(_config(), _fake_factory(fakes)).status == "sent"
    attachments = _attachments(fakes[0])

    assert [a.get_filename() for a in attachments] == [
        f"{_SLUG}-{_RECEIPT_ID}.attest",
        f"{_SLUG}-{_RECEIPT_ID}.private.attest",
    ]
    assert [a.get_content_type() for a in attachments] == ["application/zip"] * 2

    with zipfile.ZipFile(io.BytesIO(_attachment_bytes(attachments[0]))) as shareable:
        assert set(shareable.namelist()) == {
            f"receipts/{_RECEIPT_ID}.attest.json",
            f"manifests/{ISSUER}.json",
            f"legal/{LEGAL_TEXT_SHA256}.txt",
            "README.html",
        }
        receipt = json.loads(shareable.read(f"receipts/{_RECEIPT_ID}.attest.json"))
        # The salt is gone, but the embedded manifest survives the strip — that
        # is what keeps the extracted receipt verifiable on its own.
        assert "salt" not in receipt.get("delivery", {})
        assert receipt["delivery"]["issuer_manifest"] == _ISSUER_MANIFEST
        assert shareable.read(f"legal/{LEGAL_TEXT_SHA256}.txt") == LEGAL_TEXT

    with zipfile.ZipFile(io.BytesIO(_attachment_bytes(attachments[1]))) as private:
        assert private.namelist() == ["salts.json"]
        assert json.loads(private.read("salts.json")) == {_RECEIPT_ID: _SALT}


def test_no_salt_bearing_attachment_ever_leaves_under_a_shareable_name() -> None:
    """The structural regression for the defect this whole task exists to close.

    A byte-scan of the attachment would prove nothing: bundle members are
    DEFLATE-compressed, so a salt sitting inside a member would not appear in
    the container's bytes. Every non-`.private.attest` attachment is therefore
    opened and each member decompressed.
    """
    fakes: list[_FakeSMTP] = []
    _send(_config(), _fake_factory(fakes))

    checked = 0
    for attachment in _attachments(fakes[0]):
        name = attachment.get_filename()
        assert name is not None
        if name.endswith(".private.attest"):
            continue
        checked += 1
        raw = _attachment_bytes(attachment)
        assert _SALT.encode() not in raw
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for member in zf.namelist():
                content = zf.read(member)
                assert _SALT.encode() not in content
                if member.endswith(".json"):
                    decoded = json.loads(content)
                    delivery = decoded.get("delivery") if isinstance(decoded, dict) else None
                    assert not (isinstance(delivery, dict) and "salt" in delivery)
    assert checked == 1


def test_missing_issuer_manifest_is_a_failed_result_not_a_raise() -> None:
    envelope = json.loads(json.dumps(_ENVELOPE))
    del envelope["delivery"]["issuer_manifest"]
    fakes: list[_FakeSMTP] = []

    result = _send(_config(), _fake_factory(fakes), envelope=envelope)

    assert result == DeliveryResult(status="failed", detail="bundle build failed")
    assert fakes == []


def test_missing_legal_text_is_a_failed_result_not_a_raise() -> None:
    fakes: list[_FakeSMTP] = []

    result = _send(_config(), _fake_factory(fakes), legal_texts={})

    assert result == DeliveryResult(status="failed", detail="bundle build failed")
    assert fakes == []


@pytest.mark.parametrize("bad_id", ["../../evil", "a/b", "", "x" * 65, "we!rd"])
def test_unsafe_receipt_id_never_reaches_a_filename(bad_id: str) -> None:
    envelope = json.loads(json.dumps(_ENVELOPE))
    envelope["payload"]["receipt_id"] = bad_id
    fakes: list[_FakeSMTP] = []

    result = _send(_config(), _fake_factory(fakes), envelope=envelope, receipt_id=bad_id)

    assert result == DeliveryResult(status="failed", detail="bundle build failed")
    assert fakes == []


def test_issuer_id_that_reduces_to_an_empty_slug_is_a_failed_result() -> None:
    envelope = json.loads(json.dumps(_ENVELOPE))
    envelope["payload"]["issuer"]["id"] = "..."
    fakes: list[_FakeSMTP] = []

    result = _send(_config(), _fake_factory(fakes), envelope=envelope)

    assert result == DeliveryResult(status="failed", detail="bundle build failed")
    assert fakes == []


def test_receipt_id_argument_must_match_the_payload() -> None:
    fakes: list[_FakeSMTP] = []

    result = _send(_config(), _fake_factory(fakes), receipt_id="r_test_9999")

    assert result == DeliveryResult(status="failed", detail="bundle build failed")
    assert fakes == []


def test_bundle_workdir_is_owner_only_and_removed_on_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assert the ORDER and the lifecycle, not just the final state.

    The V-A.1-bis review found four real defects that a final-state assertion
    could never have caught, all of them in the order of operations around a
    secret on disk. Here the private bundle exists, briefly, as a file: this
    records that its directory is owner-only WHILE IT LIVES and that it is gone
    afterwards — on the sent path, on an SMTP failure, and on a bundle failure.
    """
    seen: list[tuple[Path, int]] = []
    real_factory = pair_mod._TMPDIR_FACTORY

    class _RecordingTmpDir:
        def __init__(self) -> None:
            self._inner = real_factory()

        def __enter__(self) -> str:
            path = Path(self._inner.__enter__())
            seen.append((path, stat.S_IMODE(path.stat().st_mode)))
            return str(path)

        def __exit__(self, *exc_info: object) -> None:
            self._inner.__exit__(*exc_info)

    monkeypatch.setattr(pair_mod, "_TMPDIR_FACTORY", _RecordingTmpDir)

    fakes: list[_FakeSMTP] = []
    assert _send(_config(), _fake_factory(fakes)).status == "sent"

    def raising_factory(host: str, port: int) -> _FakeSMTP:
        return _RaisingSMTP(host, port, smtplib.SMTPAuthenticationError(535, b"nope"))

    assert _send(_config(), raising_factory).status == "failed"
    # A bundle-build failure must not leave the directory behind either.
    assert _send(_config(), _fake_factory(fakes), legal_texts={}).status == "failed"

    assert len(seen) == 3
    for path, mode in seen:
        assert mode == 0o700
        assert not path.exists()


def test_send_body_contains_download_url_and_configured_info_url() -> None:
    fakes: list[_FakeSMTP] = []
    _send(_config(), _fake_factory(fakes), info_url=None)
    message = fakes[0].sent_messages[0]
    body = message.get_body(preferencelist=("plain",))
    assert body is not None
    text = body.get_content()
    assert "https://receipts.example.com/r/tok_abc123" in text
    assert "https://merchant.example.com/attest/what-is-this" in text


def test_send_body_uses_explicit_info_url_override_when_given() -> None:
    fakes: list[_FakeSMTP] = []
    _send(_config(), _fake_factory(fakes), info_url="https://override.example.com/info")
    message = fakes[0].sent_messages[0]
    body = message.get_body(preferencelist=("plain",))
    assert body is not None
    text = body.get_content()
    assert "https://override.example.com/info" in text
    assert "https://merchant.example.com/attest/what-is-this" not in text


def test_send_body_names_the_private_file_and_warns_not_to_forward() -> None:
    """The buyer must be told which of the two files is a secret, by name.

    Until now the only thing standing between a buyer and handing out a
    replayable bearer proof was a filename convention nobody explained to them.
    The private filename is compared against the ACTUAL attachment rather than
    re-derived here, so the body and the file can never drift apart.
    """
    fakes: list[_FakeSMTP] = []
    _send(_config(), _fake_factory(fakes))
    message = fakes[0].sent_messages[0]
    attachments = _attachments(fakes[0])
    private_name = attachments[1].get_filename()
    shareable_name = attachments[0].get_filename()
    assert private_name is not None and shareable_name is not None

    body = message.get_body(preferencelist=("plain",))
    assert body is not None
    text = body.get_content()

    assert private_name in text
    assert shareable_name in text
    assert "never" in text.lower()
    assert "forward" in text.lower()
    # The pre-existing pointers survive the rewrite.
    assert "https://receipts.example.com/r/tok_abc123" in text
    assert "https://merchant.example.com/attest/what-is-this" in text


def test_send_body_does_not_offer_the_download_link_as_the_shareable_file() -> None:
    """The body must not teach the rule and then break it two lines later.

    The download route serves the bare salt-bearing envelope under the
    SHAREABLE name `receipt-<id>.attest` (`http.py:128-137`), so a buyer who
    follows the link gets the secret under the safe-looking name — exactly what
    the attachment warning exists to prevent. Until that route serves a pair
    too, the body must say what the link actually hands over. Asserting the
    warning sits AFTER the link, not merely somewhere in the message: order is
    the requirement, a caveat above the link is one a reader never reaches.
    """
    fakes: list[_FakeSMTP] = []
    _send(_config(), _fake_factory(fakes))
    body = fakes[0].sent_messages[0].get_body(preferencelist=("plain",))
    assert body is not None
    text = body.get_content()
    lowered = text.lower()

    link_at = text.index("https://receipts.example.com/r/tok_abc123")
    caveat_at = lowered.index("keep it as private", link_at)
    assert caveat_at > link_at
    # The link's own paragraph must tie the download back to the private file,
    # so the buyer has one rule to remember and not two conflicting ones.
    assert ".private.attest" in text[link_at:]
    # And it must not call the download shareable anywhere around the link: an
    # ordering assertion alone would stay green if the text said "download the
    # shareable file here" and only walked it back afterwards.
    assert "shareable" not in lowered[link_at:]
    assert "safe to share" not in lowered[link_at:]


def test_send_never_puts_the_smtp_password_in_the_outgoing_message() -> None:
    # The envelope (and its embedded salt) legitimately IS the attachment —
    # that is delivery working as designed (Global Constraint 10: the buyer
    # needs their own salt to verify offline). `smtp_password` is the one
    # secret here that must never reach the wire in the message itself.
    fakes: list[_FakeSMTP] = []
    config = _config()
    _send(config, _fake_factory(fakes))
    raw = bytes(fakes[0].sent_messages[0]).decode("utf-8", errors="replace")
    assert config.smtp_password not in raw


def _envelope_for(receipt_id: str) -> dict[str, Any]:
    """`_ENVELOPE` whose payload receipt_id is the one the Ledger row stores.

    The sweep passes `stored.receipt_id` alongside `stored.envelope_json`, and
    delivery now refuses a pair whose two ids disagree — so a fixture that let
    them drift would be testing a state the bridge cannot produce.
    """
    envelope = json.loads(json.dumps(_ENVELOPE))
    envelope["payload"]["receipt_id"] = receipt_id
    return envelope


def _record_undelivered(ledger: Ledger, purchase_id: str) -> None:
    ledger.record_receipt(
        "stripe",
        purchase_id,
        f"r_{purchase_id}",
        _envelope_for(f"r_{purchase_id}"),
        "buyer@example.com",
        f"token_{purchase_id}",
        "2026-07-24T10:00:00Z",
    )


def test_sweep_resends_an_undelivered_receipt_and_marks_it_delivered(tmp_path: Any) -> None:
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    _record_undelivered(ledger, "cs_retry")
    fakes: list[_FakeSMTP] = []

    delivered, failures = sweep_undelivered(
        ledger=ledger,
        delivery=Delivery(_config(), smtp_factory=_fake_factory(fakes), legal_texts=_LEGAL_TEXTS),
        public_base_url="https://receipts.example.com",
    )

    assert (delivered, failures) == (1, 0)
    assert len(fakes[0].sent_messages) == 1
    assert ledger.get_receipt("stripe", "cs_retry").delivered_at is not None  # type: ignore[union-attr]


def test_sweep_skips_receipts_at_the_delivery_attempt_cap(tmp_path: Any) -> None:
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    _record_undelivered(ledger, "cs_capped")
    for _ in range(MAX_DELIVERY_ATTEMPTS):
        ledger.record_delivery_failure("stripe", "cs_capped", "failed")
    fakes: list[_FakeSMTP] = []

    assert sweep_undelivered(
        ledger=ledger,
        delivery=Delivery(_config(), smtp_factory=_fake_factory(fakes), legal_texts=_LEGAL_TEXTS),
        public_base_url="https://receipts.example.com",
    ) == (0, 0)
    assert fakes == []


def test_sweep_rechecks_a_stale_candidate_before_sending(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    _record_undelivered(ledger, "cs_stale")
    snapshot = ledger.get_receipt("stripe", "cs_stale")
    assert snapshot is not None
    for _ in range(MAX_DELIVERY_ATTEMPTS):
        ledger.record_delivery_failure("stripe", "cs_stale", "failed")
    monkeypatch.setattr(ledger, "undelivered", lambda: [replace(snapshot, delivery_attempts=0)])
    fakes: list[_FakeSMTP] = []

    assert sweep_undelivered(
        ledger=ledger,
        delivery=Delivery(_config(), smtp_factory=_fake_factory(fakes), legal_texts=_LEGAL_TEXTS),
        public_base_url="https://receipts.example.com",
    ) == (0, 0)
    assert fakes == []


def test_a_raising_sweep_send_does_not_abort_later_rows(tmp_path: Any) -> None:
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    _record_undelivered(ledger, "cs_bad")
    _record_undelivered(ledger, "cs_good")

    class RaisingDelivery:
        def send(self, **kwargs: Any) -> DeliveryResult:
            if kwargs["receipt_id"] == "r_cs_bad":
                raise RuntimeError("broken transport")
            return DeliveryResult("sent", None)

    delivered, failures = sweep_undelivered(
        ledger=ledger,
        delivery=RaisingDelivery(),  # type: ignore[arg-type]
        public_base_url="https://receipts.example.com",
    )
    assert (delivered, failures) == (1, 1)
    assert ledger.get_receipt("stripe", "cs_good").delivered_at is not None  # type: ignore[union-attr]


def test_sweep_is_a_no_op_without_configured_delivery(tmp_path: Any) -> None:
    ledger = Ledger(tmp_path / "ledger.sqlite3")
    _record_undelivered(ledger, "cs_no_delivery")

    assert sweep_undelivered(
        ledger=ledger,
        delivery=Delivery(None),
        public_base_url="https://receipts.example.com",
    ) == (0, 0)


# -- transport policy: TLS-only, mandatory STARTTLS on non-465 ------------


def test_starttls_is_called_with_ssl_context_on_port_587() -> None:
    fakes: list[_FakeSMTP] = []
    _send(_config(port=587), _fake_factory(fakes))
    fake = fakes[0]
    assert len(fake.starttls_calls) == 1
    assert isinstance(fake.starttls_calls[0], ssl.SSLContext)


def test_no_starttls_call_on_port_465_ssl_path() -> None:
    fakes: list[_FakeSMTP] = []
    _send(_config(port=465), _fake_factory(fakes))
    fake = fakes[0]
    assert fake.starttls_calls == []


def test_login_and_send_message_and_quit_are_called() -> None:
    fakes: list[_FakeSMTP] = []
    config = _config()
    _send(config, _fake_factory(fakes))
    fake = fakes[0]
    assert fake.login_calls == [(config.smtp_username, config.smtp_password)]
    assert len(fake.sent_messages) == 1
    assert fake.quit_called is True


def test_default_factory_uses_smtp_ssl_for_port_465(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int]] = []

    class _RecordingSSL(_FakeSMTP):
        def __init__(
            self, host: str, port: int, *, timeout: float, context: ssl.SSLContext
        ) -> None:
            super().__init__(host, port)
            calls.append((host, port))
            assert timeout == SMTP_TIMEOUT_SECONDS
            assert isinstance(context, ssl.SSLContext)

    def _boom_smtp(host: str, port: int, *, timeout: float) -> _FakeSMTP:
        raise AssertionError("smtplib.SMTP must not be used for port 465")

    monkeypatch.setattr(smtplib, "SMTP_SSL", _RecordingSSL)
    monkeypatch.setattr(smtplib, "SMTP", _boom_smtp)
    delivery = Delivery(_config(port=465), legal_texts=_LEGAL_TEXTS)  # default factory
    result = delivery.send(
        to_email="buyer@example.com",
        receipt_id="r_test_0001",
        work_title="Stardrift Chronicles",
        envelope=_ENVELOPE,
        download_url="https://receipts.example.com/r/tok_abc123",
        info_url=None,
    )
    assert result.status == "sent"
    assert calls == [("smtp.example.com", 465)]


def test_default_factory_uses_smtp_with_starttls_for_non_465_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    class _RecordingSMTP(_FakeSMTP):
        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            super().__init__(host, port)
            calls.append((host, port))
            assert timeout == SMTP_TIMEOUT_SECONDS

    def _boom_ssl(host: str, port: int, *, timeout: float, context: ssl.SSLContext) -> _FakeSMTP:
        raise AssertionError("smtplib.SMTP_SSL must not be used for a non-465 port")

    monkeypatch.setattr(smtplib, "SMTP", _RecordingSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _boom_ssl)
    delivery = Delivery(_config(port=587), legal_texts=_LEGAL_TEXTS)
    result = delivery.send(
        to_email="buyer@example.com",
        receipt_id="r_test_0001",
        work_title="Stardrift Chronicles",
        envelope=_ENVELOPE,
        download_url="https://receipts.example.com/r/tok_abc123",
        info_url=None,
    )
    assert result.status == "sent"
    assert calls == [("smtp.example.com", 587)]


# -- never-raise contract --------------------------------------------------


def test_smtp_exception_from_login_becomes_failed_result_not_a_raise() -> None:
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, smtplib.SMTPAuthenticationError(535, b"bad creds"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "smtp auth failed (SMTP code 535)"


def test_os_error_from_login_becomes_failed_result_not_a_raise() -> None:
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, ConnectionRefusedError("connection refused"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "connection refused"


def test_failed_detail_never_contains_the_smtp_password_or_envelope_content() -> None:
    config = _config()
    # Simulate a server/transport whose exception TEXT echoes the submitted
    # password and message content — the sanitized detail must exclude both
    # (only the exception category + numeric SMTP code are safe to surface).
    leaky = smtplib.SMTPException(
        f"535 auth failed: password {config.smtp_password} "
        "body=not-a-real-secret-but-treat-it-like-one"
    )

    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, leaky)

    result = _send(config, factory)
    assert result.status == "failed"
    assert result.detail is not None
    assert config.smtp_password not in result.detail
    assert "not-a-real-secret-but-treat-it-like-one" not in result.detail
    assert result.detail == "smtp error"  # hardcoded label, no server text


def test_factory_raising_on_connect_becomes_failed_result() -> None:
    def factory(host: str, port: int) -> _FakeSMTP:
        raise OSError("no route to host")

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "network error"


def test_non_smtp_transport_exception_becomes_failed_result_not_a_raise() -> None:
    # A transport failure outside SMTPException/OSError (e.g. RuntimeError) must
    # still be converted, not escape — the narrow (SMTPException, OSError) catch
    # was insufficient for the load-bearing never-raise contract.
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, RuntimeError("unexpected transport state"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "delivery failed"


def test_message_construction_failure_becomes_failed_result_not_a_raise() -> None:
    # _build_message runs INSIDE the guarded block: a work title carrying a
    # header separator (EmailMessage -> ValueError on assignment) must become a
    # failed result, and the transport is never reached. The envelope itself is
    # no longer serialized into the message, so header injection — not a
    # non-serializable envelope — is what can still fail message construction.
    fakes: list[_FakeSMTP] = []
    delivery = Delivery(_config(), smtp_factory=_fake_factory(fakes), legal_texts=_LEGAL_TEXTS)

    result = delivery.send(
        to_email="buyer@example.com",
        receipt_id=_RECEIPT_ID,
        work_title="Stardrift\r\nBcc: attacker@example.com",
        envelope=_ENVELOPE,
        download_url="https://receipts.example.com/r/tok_abc123",
        info_url=None,
    )

    assert result.status == "failed"
    assert result.detail == "invalid message"
    assert fakes == []


def test_safe_detail_hostile_smtp_code_accessor_never_escapes() -> None:
    # A hostile exception whose smtp_code property raises must not turn into a
    # raise out of send() — _safe_detail falls back to a constant.
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, _RaisingSmtpCode("auth failed"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail == "delivery failed"


def test_safe_detail_hostile_int_subclass_code_is_not_formatted() -> None:
    # An int-subclass smtp_code with attacker-controlled formatting must never
    # reach the detail: only an EXACT built-in int is formatted, so this falls
    # back to the bare category.
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, _HostileCodeException("auth failed"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail is not None
    assert "HOSTILE-FORMAT-LEAK" not in result.detail
    assert result.detail == "smtp error"  # hardcoded label; subclass code rejected


def test_safe_detail_hostile_class_name_metadata_is_not_surfaced() -> None:
    # A class whose __name__ is attacker-controlled text must not reach the
    # detail: the label comes from a trusted type table via isinstance, never
    # from type(exc).__name__.
    def factory(host: str, port: int) -> _RaisingSMTP:
        return _RaisingSMTP(host, port, _HostileNameException("boom"))

    result = _send(_config(), factory)
    assert result.status == "failed"
    assert result.detail is not None
    assert "HOSTILE-NAME-LEAK" not in result.detail
    assert result.detail == "smtp error"


# -- zero-config fallback ---------------------------------------------------


def test_config_none_returns_skipped_no_smtp_and_never_calls_factory() -> None:
    factory_calls: list[tuple[str, int]] = []

    def factory(host: str, port: int) -> _FakeSMTP:
        factory_calls.append((host, port))
        return _FakeSMTP(host, port)

    delivery = Delivery(None, smtp_factory=factory)
    result = delivery.send(
        to_email="buyer@example.com",
        receipt_id="r_test_0001",
        work_title="Stardrift Chronicles",
        envelope=_ENVELOPE,
        download_url="https://receipts.example.com/r/tok_abc123",
        info_url=None,
    )
    assert result == DeliveryResult(status="skipped_no_smtp", detail=None)
    assert factory_calls == []


def test_connect_timeout_is_bounded_and_reported_as_delivery_failure() -> None:
    def blocked_connect(host: str, port: int, timeout: float) -> _FakeSMTP:
        assert timeout == SMTP_TIMEOUT_SECONDS
        raise TimeoutError("connect did not greet before timeout")

    result = _send(_config(), blocked_connect)
    assert result == DeliveryResult(status="failed", detail="timeout")
