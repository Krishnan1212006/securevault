from __future__ import annotations

import threading
from pathlib import Path

import pytest

from backend import audit_service, main


@pytest.fixture
def isolated_app_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / "state"
    monkeypatch.setattr(audit_service, "APP_DIR", state)
    monkeypatch.setattr(audit_service, "DB_PATH", state / "audit.sqlite3")
    monkeypatch.setattr(audit_service, "KEY_PATH", state / "audit.key")
    monkeypatch.setattr(main, "FILES", {})
    monkeypatch.setattr(main, "ENCRYPTED", {})


def test_scan_encrypt_decrypt_and_verify_against_persisted_trusted_hash(
    tmp_path: Path, isolated_app_state: None,
) -> None:
    source = tmp_path / "source"
    output = tmp_path / "encrypted"
    recovered = tmp_path / "recovered"
    (source / "nested").mkdir(parents=True)
    output.mkdir()
    recovered.mkdir()
    original = source / "nested" / "private résumé.txt"
    original.write_text("local secret content", encoding="utf-8")

    scan_job = {"id": "scan", "status": "queued", "cancel": threading.Event()}
    main._run_scan(scan_job, source)
    assert scan_job["status"] == "completed", scan_job.get("message")
    file_record = scan_job["files"][0]
    internal_record = main.FILES[file_record["id"]]

    encrypt_job = {"id": "encrypt", "status": "queued", "progress": 0, "cancel": threading.Event(), "results": []}
    main._run_encrypt(encrypt_job, [internal_record], output, "test password")
    assert encrypt_job["results"][0]["status"] == "SUCCESS", encrypt_job["results"][0]["error_details"]
    encrypted_id, selection = next(iter(main.ENCRYPTED.items()))
    assert selection["path"] == output / "nested" / "private résumé.txt.svlt"
    assert selection["reference"]["sha256"] == file_record["sha256"]

    original.write_text("changed after encryption", encoding="utf-8")
    rescan_job = {"id": "rescan", "status": "queued", "cancel": threading.Event()}
    main._run_scan(rescan_job, source)
    assert rescan_job["files"][0]["sha256"] != file_record["sha256"]
    trusted = audit_service.trusted_record_for_encrypted(str(selection["path"]))
    assert trusted is not None
    assert trusted["sha256"] == file_record["sha256"]

    original.write_text("local secret content", encoding="utf-8")
    decrypt_job = {"id": "decrypt", "status": "queued", "progress": 0, "cancel": threading.Event(), "results": []}
    main._run_decrypt(decrypt_job, [(encrypted_id, selection)], recovered, "test password")
    recovered_file = recovered / "nested" / original.name
    assert decrypt_job["status"] == "completed"
    assert recovered_file.read_text(encoding="utf-8") == "local secret content"
    assert decrypt_job["results"][0]["verification_result"] == "MATCH"
    assert decrypt_job["results"][0]["authentication_result"] == "PASSWORD_FALLBACK"
    dashboard = audit_service.dashboard()
    assert dashboard["total_scanned"] == 1
    assert dashboard["total_encrypted"] == 1
    assert dashboard["total_decrypted"] == 1
    assert dashboard["verifications_passed"] == 1


def test_wrong_password_is_audited_and_never_publishes_plaintext(
    tmp_path: Path, isolated_app_state: None,
) -> None:
    from backend.encryption import encrypt_file

    encrypted_dir = tmp_path / "encrypted"
    recovered = tmp_path / "recovered"
    encrypted_dir.mkdir()
    recovered.mkdir()
    plaintext = tmp_path / "private.txt"
    plaintext.write_bytes(b"private contents")
    selected_path = encrypted_dir / "private.txt.svlt"
    encrypt_file(plaintext, selected_path, "correct password")
    main.ENCRYPTED["selected"] = {"path": selected_path, "reference": None}

    job = {"id": "decrypt", "status": "queued", "progress": 0, "cancel": threading.Event(), "results": []}
    main._run_decrypt(job, [("selected", main.ENCRYPTED["selected"])], recovered, "incorrect password")

    assert job["status"] == "failed"
    assert not (recovered / "private.txt").exists()
    assert not list(recovered.glob(".securevault-recovery-*.tmp"))
    record = audit_service.list_activities()[0]
    assert record["status"] == "FAILED"
    assert record["authentication_result"] == "PASSWORD_FAILED"
    assert "password is incorrect or the file was modified" in record["error_details"]
    assert "incorrect password" not in str(record)
    assert audit_service.dashboard()["failed_authentication_attempts"] == 1


def test_corrupted_encrypted_file_is_audited_and_never_published(
    tmp_path: Path, isolated_app_state: None,
) -> None:
    from backend.encryption import HEADER, encrypt_file

    encrypted_dir = tmp_path / "encrypted"
    recovered = tmp_path / "recovered"
    encrypted_dir.mkdir()
    recovered.mkdir()
    plaintext = tmp_path / "external.txt"
    plaintext.write_bytes(b"encrypted contents")
    selected_path = encrypted_dir / "external.txt.svlt"
    encrypt_file(plaintext, selected_path, "password")
    damaged = bytearray(selected_path.read_bytes())
    damaged[HEADER.size + 8] ^= 0x01
    selected_path.write_bytes(damaged)
    main.ENCRYPTED["selected"] = {"path": selected_path, "reference": None}

    job = {"id": "decrypt", "status": "queued", "progress": 0, "cancel": threading.Event(), "results": []}
    main._run_decrypt(job, [("selected", main.ENCRYPTED["selected"])], recovered, "password")

    assert job["status"] == "failed"
    assert selected_path.exists()
    assert not (recovered / "external.txt").exists()
    assert audit_service.list_activities()[0]["status"] == "FAILED"


def test_hash_mismatch_prevents_plaintext_publication(
    tmp_path: Path, isolated_app_state: None,
) -> None:
    from backend.encryption import encrypt_file

    encrypted_dir, recovered = tmp_path / "encrypted", tmp_path / "recovered"
    encrypted_dir.mkdir()
    recovered.mkdir()
    original = tmp_path / "document.txt"
    original.write_bytes(b"real source content")
    encrypted_path = encrypted_dir / "document.txt.svlt"
    encrypt_file(original, encrypted_path, "correct password")
    selection = {"path": encrypted_path, "reference": {
        "relative_path": "document.txt", "size": original.stat().st_size,
        "sha256": "0" * 64,
    }}

    job = {"id": "decrypt", "status": "queued", "progress": 0, "cancel": threading.Event(), "results": []}
    main._run_decrypt(job, [("selected", selection)], recovered, "correct password")

    assert job["status"] == "failed"
    assert encrypted_path.exists()
    assert not (recovered / "document.txt").exists()
    record = audit_service.list_activities()[0]
    assert record["verification_result"] == "MISMATCH"
    assert record["recovered_sha256"] != "0" * 64


def test_missing_trusted_hash_is_reported_as_unavailable_after_authenticated_recovery(
    tmp_path: Path, isolated_app_state: None,
) -> None:
    from backend.encryption import encrypt_file

    encrypted_dir, recovered = tmp_path / "encrypted", tmp_path / "recovered"
    encrypted_dir.mkdir()
    recovered.mkdir()
    original = tmp_path / "standalone.txt"
    original.write_bytes(b"authenticated but no baseline")
    encrypted_path = encrypted_dir / "standalone.txt.svlt"
    encrypt_file(original, encrypted_path, "correct password")

    job = {"id": "decrypt", "status": "queued", "progress": 0, "cancel": threading.Event(), "results": []}
    main._run_decrypt(job, [("selected", {"path": encrypted_path, "reference": None})], recovered, "correct password")

    assert job["status"] == "completed"
    assert (recovered / "standalone.txt").read_bytes() == original.read_bytes()
    record = audit_service.list_activities()[0]
    assert record["verification_result"] == "UNAVAILABLE"
    assert "No trusted original SHA-256" in record["error_details"]


def test_decrypt_api_requires_password_and_starts_backend_job(
    tmp_path: Path, isolated_app_state: None, monkeypatch: pytest.MonkeyPatch,
) -> None:
    encrypted_path = tmp_path / "private.svlt"
    encrypted_path.write_bytes(b"not decrypted during request")
    main.ENCRYPTED["selected"] = {"path": encrypted_path, "reference": None}
    main.SELECTED_FOLDERS["output"] = tmp_path / "recovered"
    main.SELECTED_FOLDERS["output"].mkdir()
    started: list[dict] = []

    class CapturedThread:
        def __init__(self, *, target, args, daemon):
            started.append({"target": target, "args": args, "daemon": daemon})

        def start(self):
            return None

    monkeypatch.setattr(main.threading, "Thread", CapturedThread)
    consumed: list[tuple[str, list[str], str, str]] = []
    monkeypatch.setattr(
        main.device_auth, "consume_authorization",
        lambda auth_id, ids, output_id, session_id: consumed.append((auth_id, ids, output_id, session_id)),
    )
    body = main.DecryptRequest(
        ids=["selected"], output_id="output", password="secret", device_authorization_id="grant",
    )
    result = main.start_decrypt(body, main.SESSION_TOKEN)

    assert result["job_id"]
    assert started[0]["target"] is main._run_decrypt
    assert started[0]["args"][3] == "secret"
    assert started[0]["args"][4] is True
    assert consumed == [("grant", ["selected"], "output", main.SESSION_TOKEN)]
    assert encrypted_path.exists()
    assert not list(main.SELECTED_FOLDERS["output"].iterdir())


def test_existing_encrypted_output_is_recorded_as_failure_without_overwrite(
    tmp_path: Path, isolated_app_state: None,
) -> None:
    source_dir = tmp_path / "source"
    output_dir = tmp_path / "out"
    source_dir.mkdir()
    output_dir.mkdir()
    source = source_dir / "data.bin"
    source.write_bytes(b"source data")
    scan_job = {"id": "scan", "status": "queued", "cancel": threading.Event()}
    main._run_scan(scan_job, source_dir)
    assert scan_job["status"] == "completed", scan_job.get("message")
    record = main.FILES[scan_job["files"][0]["id"]]
    existing = output_dir / "data.bin.svlt"
    existing.write_bytes(b"keep the existing output")

    job = {"id": "encrypt", "status": "queued", "progress": 0, "cancel": threading.Event(), "results": []}
    main._run_encrypt(job, [record], output_dir, "password")

    assert job["results"][0]["status"] == "FAILED"
    assert existing.read_bytes() == b"keep the existing output"
    assert "password" not in (job["results"][0]["error_details"] or "")
