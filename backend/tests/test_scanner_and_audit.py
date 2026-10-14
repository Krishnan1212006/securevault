from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from openpyxl import load_workbook

from backend import audit_service
from backend.excel_logger import make_report
from backend.scanner import scan_folder


def test_scans_nested_and_unicode_files_and_excludes_generated_folders(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "nested").mkdir(parents=True)
    (root / ".venv").mkdir()
    (root / "reports").mkdir()
    (root / "nested" / "résumé 🔐.txt").write_text("hello", encoding="utf-8")
    (root / ".venv" / "ignored.py").write_text("ignored", encoding="utf-8")
    (root / "reports" / "report.xlsx").write_bytes(b"generated")
    records, errors = scan_folder(root)
    assert errors == []
    assert len(records) == 1
    assert records[0]["relative_path"] == "nested/résumé 🔐.txt"
    assert records[0]["sha256"] == hashlib.sha256(b"hello").hexdigest()


def test_invalid_scan_path_is_reported(tmp_path: Path) -> None:
    with pytest.raises((OSError, ValueError)):
        scan_folder(tmp_path / "missing")


def test_securevault_output_folders_are_excluded_from_recursive_scan(tmp_path: Path) -> None:
    root = tmp_path / "source"
    output = root / "my-output"
    output.mkdir(parents=True)
    (root / "regular.txt").write_text("scan this", encoding="utf-8")
    (output / "encrypted.svlt").write_bytes(b"do not scan")
    records, errors = scan_folder(root, excluded_paths=[output])
    assert errors == []
    assert [item["relative_path"] for item in records] == ["regular.txt"]


def test_selected_securevault_output_folder_is_not_scanned(tmp_path: Path) -> None:
    output = tmp_path / "securevault-output"
    output.mkdir()
    with pytest.raises(ValueError, match="output or audit folder"):
        scan_folder(output, excluded_paths=[output])


def test_excel_formula_injection_is_neutralized() -> None:
    record = {
        "id": "record-1", "filename": "=HYPERLINK(\"https://example.invalid\")", "relative_source_path": "+SUM(A1:A2)",
        "file_size": 1, "sha256": "a" * 64, "encrypted_path": "@payload", "operation": "SCAN",
        "timestamp": "2025-01-01T00:00:00Z", "status": "SUCCESS", "verification_result": None,
        "error_details": "-2+3",
    }
    workbook = load_workbook(filename=__import__("io").BytesIO(make_report([record])))
    sheet = workbook.active
    assert sheet["B2"].value.startswith("'=")
    assert sheet["C2"].value.startswith("'+")
    assert sheet["G2"].value.startswith("'@")
    assert sheet["R2"].value.startswith("'-")


def test_audit_chain_detects_record_tampering(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audit_service, "APP_DIR", tmp_path / "state")
    monkeypatch.setattr(audit_service, "DB_PATH", tmp_path / "state" / "audit.sqlite3")
    monkeypatch.setattr(audit_service, "KEY_PATH", tmp_path / "state" / "audit.key")
    record = {
        "id": "entry-1", "filename": "sample", "operation": "SCAN", "timestamp": "2025-01-01T00:00:00Z",
        "status": "SUCCESS", "verification_result": None, "encrypted_path": None,
        "relative_source_path": "sample", "file_size": 1, "sha256": "a" * 64, "error_details": None,
    }
    audit_service.set_audit_enabled(True)
    audit_service.record_activity(record)
    assert audit_service.audit_status()["verified"] is True
    with audit_service._connect() as db:
        db.execute("UPDATE activities SET filename='changed' WHERE id='entry-1'")
    assert audit_service.audit_status()["verified"] is False
