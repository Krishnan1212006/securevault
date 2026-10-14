from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend import audit_service, device_auth


@pytest.fixture
def isolated_device_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    monkeypatch.setattr(audit_service, "APP_DIR", state)
    monkeypatch.setattr(audit_service, "DB_PATH", state / "audit.sqlite3")
    monkeypatch.setattr(audit_service, "KEY_PATH", state / "audit.key")
    monkeypatch.setattr(device_auth.sys, "platform", "win32")
    device_auth.reset_state()
    yield
    device_auth.reset_state()


def _options_json(_options: object) -> str:
    return '{"challenge":"Y2hhbGxlbmdl","rp":{"id":"127.0.0.1"}}'


def test_status_distinguishes_windows_hello_from_specific_biometrics(
    isolated_device_auth: None,
) -> None:
    status = device_auth.status()

    assert status["available"] is True
    assert status["configured"] is False
    assert status["os_supported"] is True
    assert status["credential_count"] == 0
    assert status["registration_status"] == "NOT_REGISTERED"
    assert "Register" in status["message"]


def test_registration_requires_the_securevault_loopback_origin(
    isolated_device_auth: None,
) -> None:
    with pytest.raises(ValueError, match="local application origin"):
        device_auth.begin_registration("https://attacker.example")


def test_registration_verifies_and_persists_only_the_public_credential(
    isolated_device_auth: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import backend.device_auth as module

    monkeypatch.setattr(module, "options_to_json", _options_json)
    monkeypatch.setattr(module, "generate_registration_options", lambda **_: SimpleNamespace(challenge=b"challenge"))
    verified_call: dict = {}

    def verify_registration(**kwargs):
        verified_call.update(kwargs)
        return SimpleNamespace(
            credential_id=b"credential-id",
            credential_public_key=b"public-key-only",
            sign_count=0,
        )

    monkeypatch.setattr(module, "verify_registration_response", verify_registration)
    ceremony = device_auth.begin_registration("http://127.0.0.1:5173")
    status = device_auth.finish_registration(
        ceremony["ceremony_id"],
        {"authenticatorAttachment": "platform"},
        "http://127.0.0.1:5173",
    )
    stored = audit_service.get_webauthn_credential(b"credential-id")

    assert status["configured"] is True
    assert verified_call["expected_challenge"] == b"challenge"
    assert verified_call["expected_rp_id"] == "127.0.0.1"
    assert verified_call["require_user_verification"] is True
    assert stored is not None
    assert stored["public_key"] == b"public-key-only"
    assert "private" not in str(stored).lower()
    with pytest.raises(ValueError, match="expired"):
        device_auth.finish_registration(
            ceremony["ceremony_id"], {"authenticatorAttachment": "platform"}, "http://127.0.0.1:5173",
        )


def test_registration_rejects_non_platform_authenticator(
    isolated_device_auth: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import backend.device_auth as module

    monkeypatch.setattr(module, "options_to_json", _options_json)
    monkeypatch.setattr(module, "generate_registration_options", lambda **_: SimpleNamespace(challenge=b"challenge"))
    ceremony = device_auth.begin_registration("http://localhost:5173")

    with pytest.raises(ValueError, match="platform authenticator"):
        device_auth.finish_registration(
            ceremony["ceremony_id"],
            {"authenticatorAttachment": "cross-platform"},
            "http://localhost:5173",
        )


def test_assertion_requires_user_verification_and_issues_bound_one_time_authorization(
    isolated_device_auth: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import backend.device_auth as module

    credential_id = b"credential-id"
    audit_service.store_webauthn_credential(credential_id, b"public-key-only", 3)
    monkeypatch.setattr(module, "options_to_json", _options_json)
    monkeypatch.setattr(module, "generate_authentication_options", lambda **_: SimpleNamespace(challenge=b"challenge"))
    verification_call: dict = {}

    def verify_assertion(**kwargs):
        verification_call.update(kwargs)
        return SimpleNamespace(new_sign_count=4)

    monkeypatch.setattr(module, "verify_authentication_response", verify_assertion)
    ids = ["file-b", "file-a"]
    ceremony = device_auth.begin_authentication(ids, "output-1", "http://127.0.0.1:5173")
    raw_id = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")
    result = device_auth.finish_authentication(
        ceremony["ceremony_id"],
        {"authenticatorAttachment": "platform", "rawId": raw_id},
        "http://127.0.0.1:5173",
    )

    assert verification_call["expected_challenge"] == b"challenge"
    assert verification_call["expected_rp_id"] == "127.0.0.1"
    assert verification_call["credential_public_key"] == b"public-key-only"
    assert verification_call["credential_current_sign_count"] == 3
    assert verification_call["require_user_verification"] is True
    assert audit_service.get_webauthn_credential(credential_id)["sign_count"] == 4
    device_auth.consume_authorization(result["authorization_id"], ids, "output-1")
    with pytest.raises(ValueError, match="expired"):
        device_auth.finish_authentication(
            ceremony["ceremony_id"], {"authenticatorAttachment": "platform", "rawId": raw_id},
            "http://127.0.0.1:5173",
        )
    with pytest.raises(ValueError, match="expired or was already used"):
        device_auth.consume_authorization(result["authorization_id"], ids, "output-1")


def test_device_authorization_is_bound_to_the_file_list_and_recovery_directory(
    isolated_device_auth: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import backend.device_auth as module

    credential_id = b"credential-id"
    audit_service.store_webauthn_credential(credential_id, b"public-key-only", 0)
    monkeypatch.setattr(module, "options_to_json", _options_json)
    monkeypatch.setattr(module, "generate_authentication_options", lambda **_: SimpleNamespace(challenge=b"challenge"))
    monkeypatch.setattr(module, "verify_authentication_response", lambda **_: SimpleNamespace(new_sign_count=0))
    ceremony = device_auth.begin_authentication(["file-1"], "out-1", "http://localhost:5173")
    raw_id = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")
    result = device_auth.finish_authentication(
        ceremony["ceremony_id"],
        {"authenticatorAttachment": "platform", "rawId": raw_id},
        "http://localhost:5173",
    )

    with pytest.raises(ValueError, match="different file selection or destination"):
        device_auth.consume_authorization(result["authorization_id"], ["file-2"], "out-1")


def test_device_challenge_and_grant_are_bound_to_the_backend_session(
    isolated_device_auth: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import backend.device_auth as module

    credential_id = b"credential-id"
    audit_service.store_webauthn_credential(credential_id, b"public-key-only", 0)
    monkeypatch.setattr(module, "options_to_json", _options_json)
    monkeypatch.setattr(module, "generate_authentication_options", lambda **_: SimpleNamespace(challenge=b"challenge"))
    monkeypatch.setattr(module, "verify_authentication_response", lambda **_: SimpleNamespace(new_sign_count=0))

    ceremony = device_auth.begin_authentication(
        ["file-1"], "out-1", "http://localhost:5173", "session-a",
    )
    raw_id = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")
    with pytest.raises(ValueError, match="different SecureVault session"):
        device_auth.finish_authentication(
            ceremony["ceremony_id"],
            {"authenticatorAttachment": "platform", "rawId": raw_id},
            "http://localhost:5173",
            "session-b",
        )

    ceremony = device_auth.begin_authentication(
        ["file-1"], "out-1", "http://localhost:5173", "session-a",
    )
    result = device_auth.finish_authentication(
        ceremony["ceremony_id"],
        {"authenticatorAttachment": "platform", "rawId": raw_id},
        "http://localhost:5173",
        "session-a",
    )
    with pytest.raises(ValueError, match="different SecureVault session"):
        device_auth.consume_authorization(
            result["authorization_id"], ["file-1"], "out-1", "session-b",
        )


def test_invalid_webauthn_signature_does_not_issue_an_authorization(
    isolated_device_auth: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import backend.device_auth as module

    from webauthn.helpers.exceptions import InvalidAuthenticationResponse

    credential_id = b"credential-id"
    audit_service.store_webauthn_credential(credential_id, b"public-key-only", 0)
    monkeypatch.setattr(module, "options_to_json", _options_json)
    monkeypatch.setattr(module, "generate_authentication_options", lambda **_: SimpleNamespace(challenge=b"challenge"))

    def reject_assertion(**_kwargs):
        raise InvalidAuthenticationResponse("signature invalid")

    monkeypatch.setattr(module, "verify_authentication_response", reject_assertion)
    ceremony = device_auth.begin_authentication(["file-1"], "out-1", "http://localhost:5173")
    raw_id = base64.urlsafe_b64encode(credential_id).decode().rstrip("=")

    with pytest.raises(ValueError, match="device verification failed"):
        device_auth.finish_authentication(
            ceremony["ceremony_id"],
            {"authenticatorAttachment": "platform", "rawId": raw_id},
            "http://localhost:5173",
        )
