from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from . import audit_service

CEREMONY_TTL = 120
AUTHORIZATION_TTL = 90
_lock = threading.Lock()
_ceremonies: dict[str, dict] = {}
_authorizations: dict[str, dict] = {}


def _relying_party(origin: str) -> tuple[str, str]:
    parsed = urlsplit(origin)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.port != 5173:
        raise ValueError("Windows Hello is available only from SecureVault's local application origin.")
    return parsed.hostname, origin


def status() -> dict:
    credentials = audit_service.list_webauthn_credentials()
    registered = bool(credentials)
    supported_platform = sys.platform == "win32"
    return {
        "available": supported_platform,
        "os_supported": supported_platform,
        "configured": registered,
        "credential_count": len(credentials),
        "registration_status": "REGISTERED" if registered else "NOT_REGISTERED" if supported_platform else "UNSUPPORTED_OS",
        "provider": "Windows Hello (platform authenticator)" if supported_platform and registered else None,
        "message": (
            "A SecureVault platform credential is registered. Windows may verify with face, fingerprint, or PIN; the modality is not reported."
            if registered and supported_platform else
            "No SecureVault platform credential is registered. Open SecureVault at its loopback origin in a WebAuthn-capable browser, set up Windows Hello under Settings > Accounts > Sign-in options if needed, then choose Register Windows Hello."
            if supported_platform else
            "Windows Hello platform authentication is available only when SecureVault runs on Windows."
        ),
    }


def _session_binding(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def _store_ceremony(state: dict) -> str:
    now = time.time()
    with _lock:
        for key in [key for key, value in _ceremonies.items() if value["expires"] <= now]:
            del _ceremonies[key]
        ceremony_id = secrets.token_urlsafe(32)
        state["expires"] = now + CEREMONY_TTL
        _ceremonies[ceremony_id] = state
        return ceremony_id


def _take_ceremony(ceremony_id: str, purpose: str, origin: str, session_id: str) -> dict:
    with _lock:
        state = _ceremonies.pop(ceremony_id, None)
    if state is None or state["expires"] <= time.time():
        raise ValueError("The device-verification challenge expired. Start verification again.")
    if state["purpose"] != purpose or state["origin"] != origin:
        raise ValueError("The device-verification challenge does not match this request.")
    if not hmac.compare_digest(state["session_binding"], _session_binding(session_id)):
        raise ValueError("The device-verification challenge belongs to a different SecureVault session.")
    return state


def begin_registration(origin: str, session_id: str = "") -> dict:
    if not status()["available"]:
        raise ValueError("Windows Hello device verification is not available on this operating system.")
    rp_id, expected_origin = _relying_party(origin)
    credentials = audit_service.list_webauthn_credentials()
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="SecureVault",
        user_id=audit_service.webauthn_user_id(),
        user_name="securevault-local",
        user_display_name="SecureVault local user",
        timeout=60000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=bytes(item["credential_id"]))
            for item in credentials
        ],
    )
    ceremony_id = _store_ceremony({
        "purpose": "registration",
        "challenge": options.challenge,
        "rp_id": rp_id,
        "origin": expected_origin,
        "session_binding": _session_binding(session_id),
    })
    return {"ceremony_id": ceremony_id, "public_key": json.loads(options_to_json(options))}


def finish_registration(ceremony_id: str, credential: dict, origin: str, session_id: str = "") -> dict:
    state = _take_ceremony(ceremony_id, "registration", origin, session_id)
    if credential.get("authenticatorAttachment") != "platform":
        raise ValueError("A platform authenticator is required for Windows Hello registration.")
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=state["challenge"],
            expected_rp_id=state["rp_id"],
            expected_origin=state["origin"],
            require_user_verification=True,
        )
    except WebAuthnException as exc:
        raise ValueError(f"Windows Hello registration could not be verified: {exc}") from exc
    audit_service.store_webauthn_credential(
        verified.credential_id,
        verified.credential_public_key,
        verified.sign_count,
    )
    return status()


def begin_authentication(
    encrypted_ids: list[str], output_id: str, origin: str, session_id: str = "",
) -> dict:
    if not status()["available"]:
        raise ValueError("Windows Hello device verification is not available on this operating system.")
    credentials = audit_service.list_webauthn_credentials()
    if not credentials:
        raise ValueError("Register a Windows Hello platform credential in Biometric Settings first.")
    rp_id, expected_origin = _relying_party(origin)
    options = generate_authentication_options(
        rp_id=rp_id,
        timeout=60000,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=bytes(item["credential_id"]))
            for item in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    ceremony_id = _store_ceremony({
        "purpose": "authentication",
        "challenge": options.challenge,
        "rp_id": rp_id,
        "origin": expected_origin,
        "encrypted_ids": tuple(sorted(set(encrypted_ids))),
        "output_id": output_id,
        "session_binding": _session_binding(session_id),
    })
    return {"ceremony_id": ceremony_id, "public_key": json.loads(options_to_json(options))}


def finish_authentication(
    ceremony_id: str, credential: dict, origin: str, session_id: str = "",
) -> dict:
    state = _take_ceremony(ceremony_id, "authentication", origin, session_id)
    if credential.get("authenticatorAttachment") != "platform":
        raise ValueError("A platform authenticator is required for Windows Hello device verification.")
    try:
        credential_id = base64url_to_bytes(credential["rawId"])
        stored = audit_service.get_webauthn_credential(credential_id)
        if stored is None:
            raise ValueError("This Windows Hello credential is not registered with SecureVault.")
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=state["challenge"],
            expected_rp_id=state["rp_id"],
            expected_origin=state["origin"],
            credential_public_key=bytes(stored["public_key"]),
            credential_current_sign_count=int(stored["sign_count"]),
            require_user_verification=True,
        )
    except WebAuthnException as exc:
        raise ValueError(f"Windows Hello device verification failed: {exc}") from exc

    audit_service.update_webauthn_sign_count(credential_id, verified.new_sign_count)
    authorization_id = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(seconds=AUTHORIZATION_TTL)
    with _lock:
        _authorizations[authorization_id] = {
            "encrypted_ids": state["encrypted_ids"],
            "output_id": state["output_id"],
            "expires": expires.timestamp(),
            "session_binding": state["session_binding"],
        }
    return {
        "authorization_id": authorization_id,
        "expires_at": expires.isoformat(),
        "message": "Windows Hello device verification succeeded. Enter the encryption password to recover files.",
    }


def consume_authorization(
    authorization_id: str, encrypted_ids: list[str], output_id: str, session_id: str = "",
) -> None:
    with _lock:
        state = _authorizations.pop(authorization_id, None)
    if state is None or state["expires"] <= time.time():
        raise ValueError("Windows Hello authorization expired or was already used. Verify the device again.")
    if state["encrypted_ids"] != tuple(sorted(set(encrypted_ids))) or state["output_id"] != output_id:
        raise ValueError("Windows Hello authorization is bound to a different file selection or destination.")
    if not hmac.compare_digest(state["session_binding"], _session_binding(session_id)):
        raise ValueError("Windows Hello authorization belongs to a different SecureVault session.")


def discard_authorization(authorization_id: str) -> None:
    with _lock:
        _authorizations.pop(authorization_id, None)


def reset_state() -> None:
    with _lock:
        _ceremonies.clear()
        _authorizations.clear()
