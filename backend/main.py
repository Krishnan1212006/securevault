from __future__ import annotations

import os
import secrets
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from tkinter import Tk, filedialog
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from . import audit_service
from . import biometric_auth
from . import device_auth
from .decryption import SecureVaultFormatError, decrypt_file
from .encryption import _publish_no_overwrite, encrypt_file
from .excel_logger import make_report
from .hashing import sha256_file
from .scanner import scan_folder

app = FastAPI(title="SecureVault Local API", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False, allow_methods=["GET", "POST", "PUT"], allow_headers=["Content-Type", "X-SecureVault-Token"],
)
SESSION_TOKEN = secrets.token_urlsafe(32)
JOBS: dict[str, dict] = {}
FILES: dict[str, dict] = {}
ENCRYPTED: dict[str, dict] = {}
JOB_LOCK = threading.Lock()
SELECTED_FOLDERS: dict[str, Path] = {}


class PathRequest(BaseModel):
    folder_id: str = Field(min_length=1, max_length=100)


class EncryptRequest(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=1000)
    output_id: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)


class DecryptRequest(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=1000)
    output_id: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=1024)
    device_authorization_id: str | None = Field(default=None, max_length=100)
    authentication_mode: Literal["password_fallback", "face_and_fingerprint"] = "password_fallback"


class DeviceRegistrationFinishRequest(BaseModel):
    ceremony_id: str = Field(min_length=1, max_length=100)
    credential: dict


class DeviceAuthenticationOptionsRequest(BaseModel):
    encrypted_ids: list[str] = Field(min_length=1, max_length=1000)
    output_id: str = Field(min_length=1, max_length=100)


class DeviceAuthenticationFinishRequest(BaseModel):
    ceremony_id: str = Field(min_length=1, max_length=100)
    credential: dict


class BiometricAuthRequest(BaseModel):
    factor: Literal["face", "fingerprint"]
    encrypted_ids: list[str] = Field(min_length=1, max_length=1000)


class SettingRequest(BaseModel):
    enabled: bool


def _auth(token: str | None) -> None:
    if token is None or not secrets.compare_digest(token, SESSION_TOKEN):
        raise HTTPException(status_code=401, detail="Local session authentication failed. Restart SecureVault to reconnect.")


@app.get("/api/session")
def session(request: Request):
    return {"token": SESSION_TOKEN}


@app.middleware("http")
async def protect_api(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.path != "/api/session":
        token = request.headers.get("x-securevault-token")
        if not token or not secrets.compare_digest(token, SESSION_TOKEN):
            return Response(content='{"detail":"Local session authentication failed."}', status_code=401, media_type="application/json")
    if request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if origin is None:
            referer = request.headers.get("referer", "")
            parsed = urlsplit(referer)
            origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None
        if origin not in {"http://127.0.0.1:5173", "http://localhost:5173"}:
            return Response(content='{"detail":"Request origin is not allowed."}', status_code=403, media_type="application/json")
    return await call_next(request)


def _pick(kind: str) -> str | None:
    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        if kind == "folder":
            return filedialog.askdirectory(title="Select a folder to scan") or None
        paths = filedialog.askopenfilenames(title="Select SecureVault encrypted files", filetypes=[("SecureVault encrypted", "*.svlt"), ("All files", "*.*")])
        return "\n".join(paths) if paths else None
    finally:
        root.destroy()


@app.post("/api/pick/folder")
def pick_folder(x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    if sys.platform != "win32":
        raise HTTPException(status_code=501, detail="Native folder selection is currently supported on Windows.")
    selected = _pick("folder")
    if not selected:
        return {"id": "", "path": ""}
    path = Path(selected).expanduser()
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        raise HTTPException(status_code=400, detail="Selecting a symbolic link or junction as a folder is not allowed.")
    path = path.resolve(strict=True)
    if not path.is_dir():
        raise HTTPException(status_code=400, detail="The selected path is not a directory.")
    selection_id = str(uuid.uuid4())
    SELECTED_FOLDERS[selection_id] = path
    return {"id": selection_id, "path": str(path)}


@app.post("/api/pick/encrypted")
def pick_encrypted(x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    if sys.platform != "win32":
        raise HTTPException(status_code=501, detail="Native file selection is currently supported on Windows.")
    selected = _pick("files")
    entries = []
    for raw_path in selected.splitlines() if selected else []:
        candidate = Path(raw_path)
        if candidate.is_symlink() or getattr(candidate, "is_junction", lambda: False)():
            continue
        path = candidate.resolve(strict=True)
        if path.is_file() and path.suffix.lower() == ".svlt":
            key = str(uuid.uuid4())
            ENCRYPTED[key] = {"path": path, "reference": audit_service.trusted_record_for_encrypted(str(path))}
            entries.append({"id": key, "path": str(path), "name": path.name, "size": path.stat().st_size})
    return {"files": entries}


@app.get("/api/biometric/capabilities")
def get_biometric_capabilities(x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    return biometric_auth.capabilities()


@app.get("/api/device-auth/status")
def get_device_auth_status(x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    return device_auth.status()


@app.post("/api/device-auth/register/options")
def start_device_registration(request: Request, x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    try:
        return device_auth.begin_registration(
            request.headers.get("origin", ""), x_securevault_token or "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/device-auth/register/complete")
def complete_device_registration(
    body: DeviceRegistrationFinishRequest, request: Request,
    x_securevault_token: str | None = Header(default=None),
):
    _auth(x_securevault_token)
    try:
        result = device_auth.finish_registration(
            body.ceremony_id, body.credential, request.headers.get("origin", ""),
            x_securevault_token or "",
        )
        _activity(
            "Windows Hello platform credential", "DEVICE_AUTH_REGISTER", "SUCCESS",
            "local-device", 0, None, auth_result="DEVICE_CREDENTIAL_REGISTERED",
        )
        return result
    except (ValueError, KeyError, TypeError) as exc:
        _activity(
            "Windows Hello platform credential", "DEVICE_AUTH_REGISTER", "FAILED",
            "local-device", 0, None, error=str(exc)[:500], auth_result="DEVICE_REGISTRATION_FAILED",
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/device-auth/authenticate/options")
def start_device_authentication(
    body: DeviceAuthenticationOptionsRequest, request: Request,
    x_securevault_token: str | None = Header(default=None),
):
    _auth(x_securevault_token)
    if any(file_id not in ENCRYPTED for file_id in body.encrypted_ids):
        raise HTTPException(status_code=400, detail="Select encrypted files again before Windows Hello verification.")
    if body.output_id not in SELECTED_FOLDERS:
        raise HTTPException(status_code=400, detail="Choose the recovery directory again before device verification.")
    try:
        return device_auth.begin_authentication(
            body.encrypted_ids, body.output_id, request.headers.get("origin", ""),
            x_securevault_token or "",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/device-auth/authenticate/complete")
def complete_device_authentication(
    body: DeviceAuthenticationFinishRequest, request: Request,
    x_securevault_token: str | None = Header(default=None),
):
    _auth(x_securevault_token)
    try:
        result = device_auth.finish_authentication(
            body.ceremony_id, body.credential, request.headers.get("origin", ""),
            x_securevault_token or "",
        )
        _activity(
            "Windows Hello device verification", "DEVICE_AUTH", "SUCCESS",
            "local-device", 0, None, auth_result="WINDOWS_HELLO_VERIFIED",
        )
        return result
    except (ValueError, KeyError, TypeError) as exc:
        _activity(
            "Windows Hello device verification", "DEVICE_AUTH", "FAILED",
            "local-device", 0, None, error=str(exc)[:500], auth_result="DEVICE_AUTH_FAILED",
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/biometric/authenticate")
def authenticate_biometric(body: BiometricAuthRequest, x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    if any(file_id not in ENCRYPTED for file_id in body.encrypted_ids):
        raise HTTPException(status_code=400, detail="Select encrypted files again before requesting authentication.")
    result = biometric_auth.authenticate(body.factor)
    encrypted_names = ", ".join(ENCRYPTED[file_id]["path"].name for file_id in dict.fromkeys(body.encrypted_ids))
    _activity(
        encrypted_names, f"BIOMETRIC_{body.factor.upper()}", result["status"], encrypted_names,
        0, None, error=result["message"],
        face_status=result["status"] if body.factor == "face" else None,
        fingerprint_status=result["status"] if body.factor == "fingerprint" else None,
        auth_result=result["status"],
    )
    return result


def _new_job() -> dict:
    job_id = str(uuid.uuid4())
    item = {"id": job_id, "status": "queued", "progress": 0, "total": 0, "completed": 0,
            "message": "Queued", "results": [], "cancel": threading.Event()}
    with JOB_LOCK:
        JOBS[job_id] = item
    return item


def _activity(name: str, operation: str, status: str, relative: str, size: int, sha: str | None,
              encrypted: str | None = None, verification: str | None = None, error: str | None = None,
              face_status: str | None = None, fingerprint_status: str | None = None,
              auth_result: str | None = None, decrypted_path: str | None = None,
              recovered_sha256: str | None = None) -> dict:
    item = {"id": str(uuid.uuid4()), "filename": name, "operation": operation,
            "timestamp": datetime.now(timezone.utc).isoformat(), "status": status,
            "verification_result": verification, "encrypted_path": encrypted,
            "relative_source_path": relative, "file_size": size, "sha256": sha, "error_details": error,
            "face_authentication_status": face_status, "fingerprint_authentication_status": fingerprint_status,
            "authentication_result": auth_result, "decrypted_path": decrypted_path,
            "recovered_sha256": recovered_sha256}
    audit_service.record_activity(item)
    return item


def _run_scan(job: dict, selected: Path) -> None:
    job["status"], job["message"] = "running", "Scanning and hashing files"
    try:
        def progress(processed_bytes, total_bytes, completed_files, total_files):
            job["completed"] = completed_files
            job["total"] = total_files
            job["progress"] = (int(100 * processed_bytes / total_bytes) if total_bytes
                               else int(100 * completed_files / total_files) if total_files else 0)
            if job["cancel"].is_set():
                raise InterruptedError("Scan cancelled.")

        files, errors = scan_folder(
            selected, progress=progress, cancelled=job["cancel"].is_set,
            excluded_paths=[audit_service.APP_DIR, *audit_service.encrypted_output_paths()],
        )
        stored = []
        for item in files:
            record = {**item, "id": str(uuid.uuid4()), "scan_root": str(selected)}
            FILES[record["id"]] = record
            stored.append(record)
        audit_service.store_files(stored)
        for item in stored:
            _activity(item["name"], "SCAN", "SUCCESS", item["relative_path"], item["size"], item["sha256"])
        job["files"] = [{key: value for key, value in item.items() if key not in {"path", "scan_root"}} for item in stored]
        job["errors"] = errors
        if errors:
            for item in errors:
                _activity(Path(item["path"]).name or str(item["path"]), "SCAN",
                          "FAILED", item["path"], 0, None, error=item["error"])
        job["total"] = len(stored)
        job["completed"] = len(stored)
        job["progress"] = 100
        job["status"] = "cancelled" if job["cancel"].is_set() else "completed"
        job["message"] = f"{len(stored)} files scanned and SHA-256 hashed" + (f"; {len(errors)} file or folder access errors" if errors else "")
    except InterruptedError:
        job["status"], job["message"] = "cancelled", "Scan cancelled"
    except Exception as exc:
        job["status"], job["message"] = "failed", f"Scan failed: {exc}"


def _run_encrypt(job: dict, items: list[dict], output_dir: Path, password: str) -> None:
    job["status"], job["total"] = "running", len(items)
    for index, record in enumerate(items):
        if job["cancel"].is_set():
            job["status"], job["message"] = "cancelled", "Operation cancelled"
            break
        try:
            if not output_dir.is_dir() or output_dir.resolve(strict=True) != output_dir:
                raise ValueError("Output directory changed after selection; choose it again.")
            source = Path(record["path"])
            if source.resolve(strict=True) != source or not source.is_file():
                raise ValueError("Source file path changed after scanning; scan the folder again.")
            if output_dir.resolve() == Path(record["scan_root"]).resolve():
                raise ValueError("Encrypted files must be saved in a separate directory from their source folder.")
            relative_source = Path(record["relative_path"])
            target = (output_dir / relative_source.parent / f"{relative_source.name}.svlt").resolve()
            target.relative_to(output_dir.resolve())
            def progress(processed: int, total: int) -> None:
                fraction = min(1.0, processed / total) if total else 1
                job["progress"] = max(job["progress"], int(100 * (index + fraction) / len(items)))

            encrypt_file(source, target, password, job["cancel"].is_set, record["sha256"], progress)
            encrypted_id = str(uuid.uuid4())
            ENCRYPTED[encrypted_id] = {"path": target, "reference": record}
            audit_service.link_encrypted_file(str(target), record["id"])
            result = _activity(record["name"], "ENCRYPT", "SUCCESS", record["relative_path"], record["size"],
                               record["sha256"], str(target))
            job["results"].append(result)
        except InterruptedError:
            job["status"], job["message"] = "cancelled", "Encryption cancelled; temporary encrypted output was removed"
            break
        except Exception as exc:
            job["results"].append(_activity(record["name"], "ENCRYPT", "FAILED", record["relative_path"],
                                             record["size"], record["sha256"], error=str(exc)))
        job["completed"] = index + 1
        job["progress"] = int(100 * job["completed"] / job["total"])
    else:
        failed = sum(result["status"] == "FAILED" for result in job["results"])
        job["status"] = "failed" if failed == len(items) else "completed"
        job["message"] = f"Encryption finished: {len(items) - failed} succeeded, {failed} failed"


def _run_decrypt(
    job: dict, items: list[tuple[str, dict]], output_dir: Path, password: str,
    device_verified: bool = False,
) -> None:
    job["status"], job["total"] = "running", len(items)
    for index, (_, item) in enumerate(items):
        if job["cancel"].is_set():
            job["status"], job["message"] = "cancelled", "Decryption cancelled"
            break
        source = Path(item["path"])
        reference = item.get("reference")
        relative = str(reference.get("relative_path", "")) if reference else ""
        original_size = int(reference.get("size", 0)) if reference else 0
        trusted_sha = reference.get("sha256") if reference else None
        staged_path: Path | None = None
        authenticated = False
        recovered_sha: str | None = None
        verification: str | None = None
        try:
            if not output_dir.is_dir() or output_dir.resolve(strict=True) != output_dir:
                raise ValueError("Recovery directory changed after selection; choose it again.")
            if source.is_symlink() or source.resolve(strict=True) != source or not source.is_file():
                raise ValueError("Encrypted file path changed after selection; select it again.")
            if source.suffix.lower() != ".svlt":
                raise ValueError("Selected file is not a SecureVault .svlt file.")
            if source.parent.resolve() == output_dir.resolve():
                raise ValueError("Choose a recovery directory separate from the encrypted source directory.")

            if reference:
                relative_path = Path(relative)
                if relative_path.is_absolute() or not relative_path.parts or ".." in relative_path.parts:
                    raise ValueError("Trusted source path is invalid; no recovery file was written.")
            else:
                recovered_name = source.name[:-len(source.suffix)]
                if not recovered_name:
                    raise ValueError("Encrypted filename does not contain a recoverable name.")
                relative_path = Path(recovered_name)

            target = (output_dir / relative_path).resolve()
            target.relative_to(output_dir.resolve())
            target.parent.mkdir(parents=True, exist_ok=True)
            target = (target.parent / target.name).resolve(strict=False)
            target.relative_to(output_dir.resolve())
            if target.exists():
                raise FileExistsError(f"Recovery file already exists: {target.name}")

            fd, staged_name = tempfile.mkstemp(
                prefix=".securevault-recovery-", suffix=".tmp", dir=target.parent,
            )
            os.close(fd)
            staged_path = Path(staged_name)
            staged_path.unlink()

            def report_progress(processed: int, encrypted_size: int) -> None:
                fraction = min(1.0, processed / encrypted_size) if encrypted_size else 1.0
                job["progress"] = max(job["progress"], int(100 * (index + fraction) / len(items)))

            decrypt_file(source, staged_path, password, job["cancel"].is_set, report_progress)
            authenticated = True
            recovered_sha = sha256_file(staged_path, job["cancel"].is_set)
            if reference is None:
                original_size = staged_path.stat().st_size
                relative = str(relative_path)
            if trusted_sha is None:
                verification = "UNAVAILABLE"
            elif secrets.compare_digest(recovered_sha, trusted_sha):
                verification = "MATCH"
            else:
                verification = "MISMATCH"
                raise ValueError(
                    f"Integrity verification failed: recovered SHA-256 {recovered_sha} "
                    f"does not match trusted original SHA-256 {trusted_sha}. No plaintext was published."
                )

            _publish_no_overwrite(staged_path, target)
            staged_path = None
            name = Path(relative_path).name
            result = _activity(
                name, "DECRYPT", "SUCCESS", relative, original_size, trusted_sha,
                encrypted=str(source), verification=verification,
                error=("No trusted original SHA-256 record is available; authenticated decryption "
                       "completed without an independent integrity comparison."
                       if verification == "UNAVAILABLE" else None),
                face_status=biometric_auth.capabilities()["factors"]["face"]["status"],
                fingerprint_status=biometric_auth.capabilities()["factors"]["fingerprint"]["status"],
                auth_result=("WINDOWS_HELLO_AND_PASSWORD" if device_verified else "PASSWORD_FALLBACK"),
                decrypted_path=str(target),
                recovered_sha256=recovered_sha,
            )
            job["results"].append(result)
        except InterruptedError as exc:
            if staged_path is not None:
                staged_path.unlink(missing_ok=True)
            job["results"].append(_activity(
                source.name, "DECRYPT", "CANCELLED", relative, original_size, trusted_sha,
                encrypted=str(source), error=str(exc),
                face_status=biometric_auth.capabilities()["factors"]["face"]["status"],
                fingerprint_status=biometric_auth.capabilities()["factors"]["fingerprint"]["status"],
                auth_result=(
                    "WINDOWS_HELLO_AND_PASSWORD" if device_verified else "PASSWORD_FALLBACK"
                ) if authenticated else "NOT_COMPLETED",
                recovered_sha256=recovered_sha,
            ))
            job["status"], job["message"] = "cancelled", "Decryption cancelled; incomplete plaintext was removed"
            job["completed"] = index + 1
            job["progress"] = int(100 * job["completed"] / len(items))
            break
        except Exception as exc:
            if staged_path is not None:
                staged_path.unlink(missing_ok=True)
            if str(exc).startswith("Integrity verification failed:"):
                verification = "MISMATCH"
            auth_result = (
                ("PASSWORD_FAILED_AFTER_WINDOWS_HELLO" if device_verified else "PASSWORD_FAILED")
                if isinstance(exc, SecureVaultFormatError)
                and str(exc).startswith("Authentication failed:")
                else ("WINDOWS_HELLO_AND_PASSWORD" if device_verified else "PASSWORD_FALLBACK") if authenticated
                else "NOT_COMPLETED"
            )
            job["results"].append(_activity(
                source.name, "DECRYPT", "FAILED", relative, original_size, trusted_sha,
                encrypted=str(source), verification=verification, error=str(exc),
                face_status=biometric_auth.capabilities()["factors"]["face"]["status"],
                fingerprint_status=biometric_auth.capabilities()["factors"]["fingerprint"]["status"],
                auth_result=auth_result, recovered_sha256=recovered_sha,
            ))
        job["completed"] = index + 1
        job["progress"] = int(100 * job["completed"] / len(items))
    else:
        failed = sum(result["status"] == "FAILED" for result in job["results"])
        unverified = sum(result["verification_result"] == "UNAVAILABLE" for result in job["results"])
        job["status"] = "failed" if failed == len(items) else "completed"
        job["message"] = f"Decryption finished: {len(items) - failed} succeeded, {failed} failed"
        if unverified:
            job["message"] += f"; {unverified} file(s) had no trusted hash for independent verification"


@app.post("/api/scan")
def start_scan(body: PathRequest, x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    selected = SELECTED_FOLDERS.get(body.folder_id)
    if selected is None:
        raise HTTPException(status_code=400, detail="Select the folder again; the folder selection has expired.")
    if not selected.is_dir():
        raise HTTPException(status_code=400, detail="The selected scan folder is no longer available.")
    job = _new_job()
    threading.Thread(target=_run_scan, args=(job, selected), daemon=True).start()
    return {"job_id": job["id"]}


@app.post("/api/encrypt")
def start_encrypt(body: EncryptRequest, x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    if len(body.password.encode("utf-8")) > 1024:
        raise HTTPException(status_code=400, detail="Password exceeds the supported length.")
    output_dir = SELECTED_FOLDERS.get(body.output_id)
    if output_dir is None:
        raise HTTPException(status_code=400, detail="Choose the output directory again; the selection has expired.")
    if not output_dir.is_dir() or output_dir.resolve(strict=True) != output_dir:
        raise HTTPException(status_code=400, detail="The selected output directory is no longer available.")
    missing = [item for item in body.ids if item not in FILES]
    if missing:
        raise HTTPException(status_code=400, detail="Some selected files are no longer available; scan the folder again.")
    items = [FILES[item] for item in dict.fromkeys(body.ids)]
    job = _new_job()
    threading.Thread(target=_run_encrypt, args=(job, items, output_dir, body.password), daemon=True).start()
    return {"job_id": job["id"]}


@app.post("/api/decrypt")
def start_decrypt(body: DecryptRequest, x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    if len(body.password.encode("utf-8")) > 1024:
        raise HTTPException(status_code=400, detail="Password exceeds the supported length.")
    if body.authentication_mode == "face_and_fingerprint":
        capabilities = biometric_auth.capabilities()
        _activity(
            "Biometric recovery authorization", "DECRYPT", "FAILED", "", 0, None,
            error=(
                "Face-and-fingerprint authorization was requested, but Windows Biometric Framework exposes "
                "fingerprint only to this application. No two-factor biometric authorization was granted."
            ),
            face_status=capabilities["factors"]["face"]["status"],
            fingerprint_status=capabilities["factors"]["fingerprint"]["status"],
            auth_result="REQUIRED_BIOMETRIC_FACTORS_UNAVAILABLE",
        )
        raise HTTPException(
            status_code=501,
            detail="Face-and-fingerprint recovery is unavailable: this system does not expose an independently verifiable face provider. Choose the explicitly labeled password fallback or configure a supported face provider.",
        )
    output_dir = SELECTED_FOLDERS.get(body.output_id)
    if output_dir is None:
        raise HTTPException(status_code=400, detail="Choose the recovery directory again; the selection has expired.")
    if not output_dir.is_dir() or output_dir.resolve(strict=True) != output_dir:
        raise HTTPException(status_code=400, detail="The selected recovery directory is no longer available.")
    missing = [item for item in body.ids if item not in ENCRYPTED]
    if missing:
        raise HTTPException(status_code=400, detail="Some selected encrypted files are no longer available; select them again.")
    items = [(item_id, ENCRYPTED[item_id]) for item_id in dict.fromkeys(body.ids)]
    device_verified = body.device_authorization_id is not None
    if body.device_authorization_id:
        try:
            device_auth.consume_authorization(
                body.device_authorization_id, body.ids, body.output_id,
                x_securevault_token or "",
            )
        except ValueError as exc:
            _activity(
                "Windows Hello device authorization", "DECRYPT", "FAILED", "", 0, None,
                error=str(exc), auth_result="DEVICE_AUTH_FAILED",
            )
            raise HTTPException(status_code=401, detail=str(exc)) from exc
    job = _new_job()
    threading.Thread(
        target=_run_decrypt,
        args=(job, items, output_dir, body.password, device_verified),
        daemon=True,
    ).start()
    return {"job_id": job["id"]}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str, x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Operation not found.")
    return {key: value for key, value in job.items() if key != "cancel"}


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str, x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Operation not found.")
    job["cancel"].set()
    return {"status": "cancellation requested"}


@app.get("/api/dashboard")
def get_dashboard(x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    return audit_service.dashboard()


@app.get("/api/audit")
def get_audit(x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    return {"records": audit_service.list_activities()}


@app.get("/api/audit/export")
def export_audit(x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    try:
        data = make_report(audit_service.list_activities())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not generate Excel report: {exc}") from exc
    return Response(content=data, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": 'attachment; filename="securevault-audit.xlsx"'})


@app.get("/api/settings/audit-protection")
def get_audit_setting(x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    return audit_service.audit_status()


@app.put("/api/settings/audit-protection")
def update_audit_setting(body: SettingRequest, x_securevault_token: str | None = Header(default=None)):
    _auth(x_securevault_token)
    audit_service.set_audit_enabled(body.enabled)
    return audit_service.audit_status()
