from __future__ import annotations

import sys
import ctypes
from typing import Literal

from .windows_biometrics import (
    BiometricAuthenticationCancelled,
    BiometricProviderError,
    WindowsBiometricFramework,
)

Factor = Literal["face", "fingerprint"]


def provider() -> WindowsBiometricFramework:
    return WindowsBiometricFramework()


def capabilities() -> dict:
    if sys.platform != "win32":
        return {
            "operating_system": {"name": sys.platform, "version": None},
            "windows_biometric_service": {
                "status": "UNSUPPORTED", "message": "Windows Biometric Service is available only on Windows.",
            },
            "native_provider_status": "UNAVAILABLE",
            "native_provider_message": "Windows Biometric Framework is available only on Windows.",
            "provider_status": "UNAVAILABLE",
            "provider_message": "Windows biometric authentication is not available on this operating system.",
            "provider": None,
            "factors": {
                factor: WindowsBiometricFramework._factor_unavailable(
                    "Windows Biometric Framework is available only on Windows."
                )
                for factor in ("face", "fingerprint")
            },
            "two_factor_supported": False,
            "decryption_authorized": False,
        }
    return provider().detect()


def authenticate(factor: Factor) -> dict:
    if sys.platform != "win32":
        detection = capabilities()
    else:
        native_provider = provider()
        detection = native_provider.detect()
    capability = detection["factors"][factor]
    if factor != "fingerprint":
        return {
            "factor": factor,
            "status": capability["status"],
            "message": capability["message"],
            "authorization_id": None,
            "expires_at": None,
        }
    if not capability["available"]:
        return {
            "factor": factor,
            "status": capability["status"],
            "message": capability["message"],
            "authorization_id": None,
            "expires_at": None,
        }
    try:
        native_provider.verify_current_user_fingerprint()
    except BiometricAuthenticationCancelled as exc:
        return {
            "factor": factor,
            "status": "CANCELLED",
            "message": str(exc),
            "authorization_id": None,
            "expires_at": None,
        }
    except (BiometricProviderError, OSError, AttributeError, ctypes.ArgumentError) as exc:
        return {
            "factor": factor,
            "status": "FAILED",
            "message": str(exc),
            "authorization_id": None,
            "expires_at": None,
        }
    return {
        "factor": factor,
        "status": "SUCCESS",
        "message": "Windows Biometric Framework matched a fingerprint to the current Windows account.",
        "authorization_id": None,
        "expires_at": None,
    }
