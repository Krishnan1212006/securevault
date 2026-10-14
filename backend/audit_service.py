from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

APP_DIR = Path(os.environ.get("SECUREVAULT_HOME", Path.home() / ".securevault"))
DB_PATH = APP_DIR / "audit.sqlite3"
KEY_PATH = APP_DIR / "audit.key"
LEGACY_AUDIT_COLUMNS = (
    "id", "filename", "operation", "timestamp", "status", "verification_result", "encrypted_path",
    "relative_source_path", "file_size", "sha256", "error_details",
)
AUDIT_COLUMNS = (*LEGACY_AUDIT_COLUMNS, "face_authentication_status", "fingerprint_authentication_status",
                 "authentication_result", "decrypted_path", "recovered_sha256", "audit_version")


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("""CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY, path TEXT NOT NULL, relative_path TEXT NOT NULL, name TEXT NOT NULL,
            size INTEGER NOT NULL, modified_at TEXT NOT NULL, sha256 TEXT NOT NULL, scanned_at TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS activities (
            id TEXT PRIMARY KEY, filename TEXT NOT NULL, operation TEXT NOT NULL, timestamp TEXT NOT NULL,
            status TEXT NOT NULL, verification_result TEXT, encrypted_path TEXT, relative_source_path TEXT NOT NULL,
            file_size INTEGER NOT NULL, sha256 TEXT, error_details TEXT,
            face_authentication_status TEXT, fingerprint_authentication_status TEXT,
            authentication_result TEXT, decrypted_path TEXT, recovered_sha256 TEXT,
            audit_version INTEGER NOT NULL DEFAULT 2
        )""")
        activity_columns = {row["name"] for row in db.execute("PRAGMA table_info(activities)")}
        for column in (
            "face_authentication_status", "fingerprint_authentication_status",
            "authentication_result", "decrypted_path", "recovered_sha256",
        ):
            if column not in activity_columns:
                db.execute(f"ALTER TABLE activities ADD COLUMN {column} TEXT")
        if "audit_version" not in activity_columns:
            db.execute("ALTER TABLE activities ADD COLUMN audit_version INTEGER NOT NULL DEFAULT 1")
        db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("""CREATE TABLE IF NOT EXISTS audit_seal (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_id TEXT NOT NULL, mac TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS encrypted_files (
            path TEXT PRIMARY KEY, file_id TEXT NOT NULL REFERENCES files(id)
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS webauthn_credentials (
            credential_id BLOB PRIMARY KEY, public_key BLOB NOT NULL,
            sign_count INTEGER NOT NULL, created_at TEXT NOT NULL
        )""")
        db.commit()
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _key(create: bool = False) -> bytes:
    if create and not KEY_PATH.exists():
        APP_DIR.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(KEY_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as key_file:
                key_file.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
    return KEY_PATH.read_bytes()


def _canonical_record(record: dict) -> dict:
    columns = AUDIT_COLUMNS if record.get("audit_version", 1) >= 2 else LEGACY_AUDIT_COLUMNS
    return {column: record.get(column) for column in columns}


def _seal_value(record: dict, previous: str, key: bytes | None = None) -> str:
    payload = json.dumps({"record": _canonical_record(record), "previous": previous}, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key if key is not None else _key(create=True), payload, hashlib.sha256).hexdigest()


def audit_enabled() -> bool:
    with _connect() as db:
        row = db.execute("SELECT value FROM settings WHERE key='audit_protection'").fetchone()
        return row is not None and row["value"] == "true"


def audit_status() -> dict:
    with _connect() as db:
        enabled_row = db.execute("SELECT value FROM settings WHERE key='audit_protection'").fetchone()
        enabled = enabled_row is not None and enabled_row["value"] == "true"
        count = db.execute("SELECT COUNT(*) AS n FROM activities").fetchone()["n"]
        seal = db.execute("SELECT last_id, mac FROM audit_seal WHERE singleton=1").fetchone()
        if not enabled:
            return {"enabled": False, "verified": True, "records": count}
        if not seal:
            return {"enabled": True, "verified": count == 0, "records": count}
        try:
            key = _key()
        except FileNotFoundError:
            return {"enabled": True, "verified": False, "records": count}
        previous = ""
        records = db.execute("SELECT * FROM activities ORDER BY rowid").fetchall()
        for row in records:
            record = dict(row)
            previous = _seal_value(record, previous, key)
        verified = ((not records and seal["last_id"] == "" and seal["mac"] == "") or
                    (bool(records) and records[-1]["id"] == seal["last_id"] and hmac.compare_digest(previous, seal["mac"])))
        return {"enabled": True, "verified": verified, "records": count}


def set_audit_enabled(enabled: bool) -> None:
    with _connect() as db:
        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('audit_protection',?)", ("true" if enabled else "false",))
        if enabled:
            key = _key(create=True)
            previous = ""
            for row in db.execute("SELECT * FROM activities ORDER BY rowid").fetchall():
                previous = _seal_value(dict(row), previous, key)
            last = db.execute("SELECT id FROM activities ORDER BY rowid DESC LIMIT 1").fetchone()
            db.execute("INSERT OR REPLACE INTO audit_seal(singleton,last_id,mac) VALUES(1,?,?)", (last["id"] if last else "", previous))
        else:
            db.execute("DELETE FROM audit_seal")
        db.commit()


def store_files(files: list[dict]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as db:
        for item in files:
            db.execute(
                """INSERT OR IGNORE INTO files VALUES(?,?,?,?,?,?,?,?)""",
                (item["id"], item["path"], item["relative_path"], item["name"], item["size"],
                 item["modified_at"], item["sha256"], now),
            )
        db.commit()


def link_encrypted_file(path: str, file_id: str) -> None:
    with _connect() as db:
        db.execute("INSERT OR REPLACE INTO encrypted_files(path,file_id) VALUES(?,?)", (path, file_id))


def trusted_record_for_encrypted(path: str) -> dict | None:
    with _connect() as db:
        row = db.execute(
            """SELECT files.* FROM files JOIN encrypted_files ON encrypted_files.file_id=files.id
            WHERE encrypted_files.path=?""",
            (path,),
        ).fetchone()
        return dict(row) if row else None


def encrypted_output_paths() -> list[Path]:
    with _connect() as db:
        return [Path(row["path"]).parent for row in db.execute("SELECT path FROM encrypted_files")]


def webauthn_user_id() -> bytes:
    with _connect() as db:
        row = db.execute("SELECT value FROM settings WHERE key='webauthn_user_id'").fetchone()
        if row:
            return bytes.fromhex(row["value"])
        user_id = secrets.token_bytes(32)
        db.execute("INSERT INTO settings(key,value) VALUES('webauthn_user_id',?)", (user_id.hex(),))
        return user_id


def list_webauthn_credentials() -> list[dict]:
    with _connect() as db:
        return [dict(row) for row in db.execute(
            "SELECT credential_id, public_key, sign_count, created_at FROM webauthn_credentials"
        )]


def get_webauthn_credential(credential_id: bytes) -> dict | None:
    with _connect() as db:
        row = db.execute(
            "SELECT credential_id, public_key, sign_count, created_at FROM webauthn_credentials WHERE credential_id=?",
            (credential_id,),
        ).fetchone()
        return dict(row) if row else None


def store_webauthn_credential(credential_id: bytes, public_key: bytes, sign_count: int) -> None:
    with _connect() as db:
        db.execute(
            "INSERT INTO webauthn_credentials(credential_id,public_key,sign_count,created_at) VALUES(?,?,?,?)",
            (credential_id, public_key, sign_count, datetime.now(timezone.utc).isoformat()),
        )


def update_webauthn_sign_count(credential_id: bytes, sign_count: int) -> None:
    with _connect() as db:
        db.execute(
            "UPDATE webauthn_credentials SET sign_count=? WHERE credential_id=?",
            (sign_count, credential_id),
        )


def list_files() -> list[dict]:
    with _connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM files ORDER BY scanned_at DESC, relative_path")]


def get_file(file_id: str) -> dict | None:
    with _connect() as db:
        row = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        return dict(row) if row else None


def record_activity(item: dict) -> None:
    with _connect() as db:
        columns = ("id", "filename", "operation", "timestamp", "status", "verification_result", "encrypted_path",
                   "relative_source_path", "file_size", "sha256", "error_details",
                   "face_authentication_status", "fingerprint_authentication_status", "authentication_result",
                   "decrypted_path", "recovered_sha256", "audit_version")
        values = tuple(item.get(column) if column in item else (2 if column == "audit_version" else None) for column in columns)
        db.execute(f"INSERT INTO activities({','.join(columns)}) VALUES({','.join('?' for _ in columns)})", values)
        enabled_row = db.execute("SELECT value FROM settings WHERE key='audit_protection'").fetchone()
        if enabled_row is not None and enabled_row["value"] == "true":
            previous_row = db.execute("SELECT mac FROM audit_seal WHERE singleton=1").fetchone()
            previous = previous_row["mac"] if previous_row else ""
            mac = _seal_value(dict(zip(columns, values)), previous)
            db.execute("INSERT OR REPLACE INTO audit_seal(singleton,last_id,mac) VALUES(1,?,?)", (item["id"], mac))
        db.commit()


def list_activities() -> list[dict]:
    with _connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM activities ORDER BY timestamp DESC")]


def dashboard() -> dict:
    with _connect() as db:
        counts = db.execute("""
            SELECT COUNT(*) AS scanned,
            SUM(CASE WHEN operation='ENCRYPT' AND status='SUCCESS' THEN 1 ELSE 0 END) AS encrypted,
            SUM(CASE WHEN operation='DECRYPT' AND status='SUCCESS' THEN 1 ELSE 0 END) AS decrypted,
            SUM(CASE WHEN verification_result='MATCH' THEN 1 ELSE 0 END) AS verified,
            SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) AS failed,
            SUM(CASE WHEN operation='BIOMETRIC_FACE' AND status='SUCCESS' THEN 1 ELSE 0 END) AS face_success,
            SUM(CASE WHEN operation='BIOMETRIC_FINGERPRINT' AND status='SUCCESS' THEN 1 ELSE 0 END) AS fingerprint_success,
            SUM(CASE WHEN operation='DEVICE_AUTH' AND status='SUCCESS' THEN 1 ELSE 0 END) AS device_auth_success,
            SUM(CASE WHEN (operation IN ('BIOMETRIC_FACE','BIOMETRIC_FINGERPRINT','DEVICE_AUTH') AND status IN ('FAILED','CANCELLED'))
                      OR (operation='DECRYPT' AND authentication_result IN ('PASSWORD_FAILED','PASSWORD_FAILED_AFTER_WINDOWS_HELLO'))
                     THEN 1 ELSE 0 END) AS auth_failed
            FROM activities
        """).fetchone()
        total = db.execute("SELECT COUNT(DISTINCT path) AS n FROM files").fetchone()["n"]
        recent = [dict(row) for row in db.execute("SELECT * FROM activities ORDER BY timestamp DESC LIMIT 8")]
        return {"total_scanned": total, "total_encrypted": counts["encrypted"] or 0,
                "total_decrypted": counts["decrypted"] or 0, "verifications_passed": counts["verified"] or 0,
                "failed_operations": counts["failed"] or 0, "face_authentications": counts["face_success"] or 0,
                "fingerprint_authentications": counts["fingerprint_success"] or 0,
                "windows_hello_authentications": counts["device_auth_success"] or 0,
                "failed_authentication_attempts": counts["auth_failed"] or 0, "recent": recent}
