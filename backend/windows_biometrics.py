from __future__ import annotations

import ctypes
import platform
import sys
from ctypes import wintypes

FINGERPRINT = 0x00000008
FACE = 0x00000010
IDENTITY_SID = 3
TOKEN_QUERY = 0x0008
TOKEN_USER = 1
WINBIO_POOL_SYSTEM = 1
WINBIO_SESSION_FLAG_DEFAULT = 0
WINBIO_SUBTYPE_ANY = 0xFF
WINBIO_E_CANCELED = 0x80098004
WINBIO_E_NO_MATCH = 0x80098005
WINBIO_E_CAPTURE_ABORTED = 0x80098006
WINBIO_E_ENROLLMENT_IN_PROGRESS = 0x80098007

SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SC_STATUS_PROCESS_INFO = 0
SERVICE_RUNNING = 4
HRESULT_ERROR_BUSY = 0x800700AA


class BiometricProviderError(RuntimeError):
    pass


class BiometricAuthenticationCancelled(BiometricProviderError):
    pass


class _AccountSid(ctypes.Structure):
    _fields_ = [("size", wintypes.ULONG), ("data", ctypes.c_ubyte * 68)]


class _IdentityValue(ctypes.Union):
    _fields_ = [
        ("null", wintypes.ULONG),
        ("wildcard", wintypes.ULONG),
        ("template_guid", ctypes.c_ubyte * 16),
        ("account_sid", _AccountSid),
        ("secure_id", ctypes.c_ubyte * 32),
    ]


class _Identity(ctypes.Structure):
    _fields_ = [("type", wintypes.ULONG), ("value", _IdentityValue)]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("user", _SidAndAttributes)]


class _ServiceStatusProcess(ctypes.Structure):
    _fields_ = [
        ("service_type", wintypes.DWORD),
        ("current_state", wintypes.DWORD),
        ("controls_accepted", wintypes.DWORD),
        ("win32_exit_code", wintypes.DWORD),
        ("service_specific_exit_code", wintypes.DWORD),
        ("check_point", wintypes.DWORD),
        ("wait_hint", wintypes.DWORD),
        ("process_id", wintypes.DWORD),
        ("service_flags", wintypes.DWORD),
    ]


def _hresult(value: int) -> int:
    return value & 0xFFFFFFFF


def _close_handle(handle: wintypes.HANDLE) -> None:
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    if handle and not kernel32.CloseHandle(handle):
        raise BiometricProviderError(
            f"Could not release a Windows handle (error {ctypes.get_last_error()})."
        )


class WindowsBiometricFramework:
    def __init__(self) -> None:
        self._dll = None
        self._init_error: str | None = None
        if sys.platform != "win32":
            self._init_error = "Windows Biometric Framework is available only on Windows."
            return
        try:
            self._dll = ctypes.WinDLL("winbio.dll", use_last_error=True)
        except OSError as exc:
            self._init_error = f"Windows Biometric Framework could not be loaded: {exc}"

    def _identity(self) -> tuple[_Identity, ctypes.c_void_p]:
        advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        kernel32.GetCurrentProcess.argtypes = ()
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        token = wintypes.HANDLE()
        advapi32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
            raise BiometricProviderError(f"Could not open the current Windows user token (error {ctypes.get_last_error()}).")

        try:
            required = wintypes.DWORD()
            advapi32.GetTokenInformation.argtypes = (
                wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
            )
            advapi32.GetTokenInformation.restype = wintypes.BOOL
            advapi32.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(required))
            if not required.value:
                raise BiometricProviderError(
                    f"Could not determine the current Windows account SID (error {ctypes.get_last_error()})."
                )
            token_data = ctypes.create_string_buffer(required.value)
            if not advapi32.GetTokenInformation(
                token, TOKEN_USER, token_data, required, ctypes.byref(required),
            ):
                raise BiometricProviderError(
                    f"Could not read the current Windows account SID (error {ctypes.get_last_error()})."
                )
            token_user = ctypes.cast(token_data, ctypes.POINTER(_TokenUser)).contents
            advapi32.GetLengthSid.argtypes = (ctypes.c_void_p,)
            advapi32.GetLengthSid.restype = wintypes.DWORD
            sid_length = advapi32.GetLengthSid(token_user.user.sid)
            if not sid_length or sid_length > 68:
                raise BiometricProviderError("Windows returned an invalid account SID.")
            identity = _Identity()
            identity.type = IDENTITY_SID
            identity.value.account_sid.size = sid_length
            ctypes.memmove(identity.value.account_sid.data, token_user.user.sid, sid_length)
            return identity, token
        except (BiometricProviderError, OSError, AttributeError, ctypes.ArgumentError):
            _close_handle(token)
            raise

    @staticmethod
    def _service_status() -> tuple[str, str]:
        advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        advapi32.OpenSCManagerW.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
        advapi32.OpenSCManagerW.restype = wintypes.HANDLE
        advapi32.OpenServiceW.argtypes = (wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD)
        advapi32.OpenServiceW.restype = wintypes.HANDLE
        advapi32.QueryServiceStatusEx.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        advapi32.QueryServiceStatusEx.restype = wintypes.BOOL
        advapi32.CloseServiceHandle.argtypes = (wintypes.HANDLE,)
        advapi32.CloseServiceHandle.restype = wintypes.BOOL

        manager = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if not manager:
            return "UNKNOWN", f"Could not query Windows services (error {ctypes.get_last_error()})."
        service = None
        try:
            service = advapi32.OpenServiceW(manager, "WbioSrvc", SERVICE_QUERY_STATUS)
            if not service:
                return "UNKNOWN", f"Could not query Windows Biometric Service (error {ctypes.get_last_error()})."
            status = _ServiceStatusProcess()
            needed = wintypes.DWORD()
            if not advapi32.QueryServiceStatusEx(
                service, SC_STATUS_PROCESS_INFO, ctypes.byref(status),
                ctypes.sizeof(status), ctypes.byref(needed),
            ):
                return "UNKNOWN", f"Could not read Windows Biometric Service status (error {ctypes.get_last_error()})."
            if status.current_state == SERVICE_RUNNING:
                return "RUNNING", "Windows Biometric Service is running."
            return (
                "STOPPED",
                f"Windows Biometric Service is not running (state {status.current_state}). "
                "Start it from Windows Services (services.msc) before retrying detection.",
            )
        finally:
            if service:
                advapi32.CloseServiceHandle(service)
            advapi32.CloseServiceHandle(manager)

    def _enumerate_fingerprints(self) -> tuple[int, str | None]:
        if self._dll is None:
            return 0, self._init_error
        units = ctypes.c_void_p()
        count = ctypes.c_size_t()
        enumerate_units = self._dll.WinBioEnumBiometricUnits
        enumerate_units.argtypes = (wintypes.ULONG, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t))
        enumerate_units.restype = ctypes.c_long
        result = enumerate_units(FINGERPRINT, ctypes.byref(units), ctypes.byref(count))
        if result:
            return 0, f"Windows Biometric Framework sensor enumeration failed (HRESULT 0x{_hresult(result):08X})."
        if units:
            self._dll.WinBioFree.argtypes = (ctypes.c_void_p,)
            self._dll.WinBioFree.restype = None
            self._dll.WinBioFree(units)
        return count.value, None

    def _enrolled_factors(self, identity: _Identity) -> tuple[int | None, str | None]:
        if self._dll is None:
            return None, self._init_error
        factors = wintypes.ULONG()
        get_factors = self._dll.WinBioGetEnrolledFactors
        get_factors.argtypes = (ctypes.POINTER(_Identity), ctypes.POINTER(wintypes.ULONG))
        get_factors.restype = ctypes.c_long
        result = get_factors(ctypes.byref(identity), ctypes.byref(factors))
        if result:
            return None, f"Windows enrollment check failed (HRESULT 0x{_hresult(result):08X})."
        return factors.value, None

    def detect(self) -> dict:
        windows_version = platform.version() if sys.platform == "win32" else None
        if self._dll is None:
            return {
                "operating_system": {"name": platform.system(), "version": windows_version},
                "windows_biometric_service": {
                    "status": "UNKNOWN",
                    "message": "Service status could not be checked because the native provider did not load.",
                },
                "native_provider_status": "UNAVAILABLE",
                "native_provider_message": self._init_error or "Windows Biometric Framework is unavailable.",
                "provider_status": "UNAVAILABLE",
                "provider_message": self._init_error or "Windows Biometric Framework is unavailable.",
                "provider": None,
                "factors": {
                    factor: self._factor_unavailable(self._init_error or "Provider unavailable.")
                    for factor in ("face", "fingerprint")
                },
                "two_factor_supported": False,
                "decryption_authorized": False,
            }

        try:
            service_status, service_message = self._service_status()
        except (OSError, AttributeError, ctypes.ArgumentError) as exc:
            service_status = "UNKNOWN"
            service_message = f"Could not query Windows Biometric Service: {exc}"
        try:
            identity, token = self._identity()
            try:
                enrolled, enrollment_error = self._enrolled_factors(identity)
                if service_status == "RUNNING":
                    fingerprint_count, hardware_error = self._enumerate_fingerprints()
                else:
                    fingerprint_count = 0
                    hardware_error = service_message
            finally:
                _close_handle(token)
        except (BiometricProviderError, OSError, AttributeError, ctypes.ArgumentError) as exc:
            enrolled, enrollment_error = None, str(exc)
            fingerprint_count, hardware_error = 0, str(exc)

        fingerprint_enrolled = enrolled is not None and bool(enrolled & FINGERPRINT)
        fingerprint_available = fingerprint_count > 0 and fingerprint_enrolled and not hardware_error and not enrollment_error
        if hardware_error:
            fingerprint_status = "PROVIDER_UNAVAILABLE"
            fingerprint_message = hardware_error
        elif not fingerprint_count:
            fingerprint_status = "HARDWARE_NOT_DETECTED"
            fingerprint_message = (
                "Windows Biometric Framework did not enumerate a fingerprint sensor. Connect or enable a WBF-compatible "
                "sensor and its Windows driver, then retry detection."
            )
        elif enrollment_error:
            fingerprint_status = "PROVIDER_UNAVAILABLE"
            fingerprint_message = enrollment_error
        elif not fingerprint_enrolled:
            fingerprint_status = "ENROLLMENT_MISSING"
            fingerprint_message = (
                "Fingerprint sensor detected, but this Windows account has no enrolled fingerprint. Enroll one under "
                "Settings > Accounts > Sign-in options, then retry detection."
            )
        else:
            fingerprint_status = "READY"
            fingerprint_message = "Windows Biometric Framework enumerated a fingerprint sensor and current-account enrollment."

        if enrollment_error:
            face_enrollment_status = "UNKNOWN"
        else:
            face_enrollment_status = "ENROLLED" if enrolled is not None and enrolled & FACE else "MISSING"
        face = {
            "available": False,
            "status": "UNSUPPORTED",
            "provider_status": "PROVIDER_NOT_IMPLEMENTED",
            "hardware_status": "NOT_EXPOSED_BY_SUPPORTED_API",
            "enrollment_status": face_enrollment_status,
            "device_count": 0,
            "modality_identifiable": False,
            "message": (
                "Windows Biometric Framework enrollment flags indicate whether this account has Windows face enrollment "
                "but its documented sensor-enumeration, session, and matching APIs support fingerprint only. "
                "WebAuthn/Windows Hello user verification does not disclose face versus fingerprint versus PIN."
            ),
        }
        fingerprint = {
            "available": fingerprint_available,
            "status": fingerprint_status,
            "provider_status": "AVAILABLE" if fingerprint_available else fingerprint_status,
            "hardware_status": "UNKNOWN" if hardware_error else "DETECTED" if fingerprint_count else "NOT_DETECTED",
            "enrollment_status": "ENROLLED" if fingerprint_enrolled else "MISSING" if enrolled is not None else "UNKNOWN",
            "device_count": fingerprint_count,
            "modality_identifiable": True,
            "message": fingerprint_message,
        }
        native_ready = (
            service_status == "RUNNING"
            and enrolled is not None
            and enrollment_error is None
            and hardware_error is None
        )
        native_message = (
            "Windows Biometric Framework and Windows Biometric Service responded to native capability checks."
            if native_ready
            else service_message if service_status != "RUNNING"
            else enrollment_error or hardware_error or "Windows biometric capability checks are incomplete."
        )
        return {
            "operating_system": {"name": "Windows", "version": windows_version},
            "windows_biometric_service": {"status": service_status, "message": service_message},
            "native_provider_status": "READY" if native_ready else "UNAVAILABLE",
            "native_provider_message": native_message,
            "provider_status": "AVAILABLE" if native_ready else "UNAVAILABLE",
            "provider_message": native_message,
            "provider": "Windows Biometric Framework",
            "factors": {"face": face, "fingerprint": fingerprint},
            "two_factor_supported": False,
            "decryption_authorized": False,
        }

    @staticmethod
    def _factor_unavailable(message: str) -> dict:
        return {
            "available": False,
            "status": "PROVIDER_UNAVAILABLE",
            "provider_status": "PROVIDER_UNAVAILABLE",
            "hardware_status": "UNKNOWN",
            "enrollment_status": "UNKNOWN",
            "device_count": 0,
            "modality_identifiable": False,
            "message": message,
        }

    def verify_current_user_fingerprint(self) -> None:
        detection = self.detect()
        factor = detection["factors"]["fingerprint"]
        if not factor["available"]:
            raise BiometricProviderError(factor["message"])
        if self._dll is None:
            raise BiometricProviderError(self._init_error or "Windows Biometric Framework is unavailable.")

        identity, token = self._identity()
        session = ctypes.c_void_p()
        winbio = self._dll
        try:
            open_session = winbio.WinBioOpenSession
            open_session.argtypes = (
                wintypes.ULONG, wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p,
                ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
            )
            open_session.restype = ctypes.c_long
            result = open_session(
                FINGERPRINT, WINBIO_POOL_SYSTEM, WINBIO_SESSION_FLAG_DEFAULT,
                None, 0, None, ctypes.byref(session),
            )
            if result:
                raise BiometricProviderError(
                    f"Could not open a fingerprint session (HRESULT 0x{_hresult(result):08X})."
                )

            unit_id, match, reject_detail = wintypes.ULONG(), ctypes.c_ubyte(), wintypes.ULONG()
            verify = winbio.WinBioVerify
            verify.argtypes = (
                ctypes.c_void_p, ctypes.POINTER(_Identity), wintypes.ULONG,
                ctypes.POINTER(wintypes.ULONG), ctypes.POINTER(ctypes.c_ubyte),
                ctypes.POINTER(wintypes.ULONG),
            )
            verify.restype = ctypes.c_long
            # WinBioAcquireFocus is restricted to Local System and is not needed for WinBioVerify.
            result = verify(
                session, ctypes.byref(identity), WINBIO_SUBTYPE_ANY, ctypes.byref(unit_id),
                ctypes.byref(match), ctypes.byref(reject_detail),
            )

            if _hresult(result) == WINBIO_E_NO_MATCH or (result == 0 and not match.value):
                raise BiometricProviderError("Fingerprint did not match the current Windows account.")
            if _hresult(result) in {WINBIO_E_CANCELED, WINBIO_E_CAPTURE_ABORTED}:
                raise BiometricAuthenticationCancelled(
                    "Fingerprint verification was cancelled or its capture was aborted in the Windows prompt."
                )
            if _hresult(result) == WINBIO_E_ENROLLMENT_IN_PROGRESS:
                raise BiometricProviderError(
                    "The fingerprint sensor is busy with another Windows enrollment operation. Try again after it finishes."
                )
            if _hresult(result) == HRESULT_ERROR_BUSY:
                raise BiometricProviderError(
                    "The fingerprint sensor is busy with another Windows biometric operation. Try again shortly."
                )
            if result:
                raise BiometricProviderError(
                    f"Fingerprint verification failed (HRESULT 0x{_hresult(result):08X}, capture detail {reject_detail.value})."
                )
        finally:
            try:
                if session:
                    close_session = winbio.WinBioCloseSession
                    close_session.argtypes = (ctypes.c_void_p,)
                    close_session.restype = ctypes.c_long
                    close_result = close_session(session)
                    if close_result:
                        raise BiometricProviderError(
                            f"Could not close the Windows biometric session "
                            f"(HRESULT 0x{_hresult(close_result):08X})."
                        )
            finally:
                _close_handle(token)
