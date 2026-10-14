from __future__ import annotations

import hmac
from pathlib import Path
from tempfile import TemporaryDirectory

from .decryption import decrypt_file
from .hashing import sha256_file


def verify_encrypted(
    encrypted: Path, reference: dict | None, password: str, cancelled=None, progress=None,
) -> tuple[str, str]:
    if reference is None:
        return "UNAVAILABLE", "No trusted original SHA-256 record is available for verification."
    with TemporaryDirectory(prefix="securevault-verify-") as temp_dir:
        temporary = Path(temp_dir) / "recovered.tmp"
        def report_progress(processed: int, _encrypted_size: int) -> None:
            if progress:
                progress(processed, reference["size"])

        decrypt_file(encrypted, temporary, password, cancelled, report_progress)
        actual = sha256_file(temporary, cancelled)
        expected = reference["sha256"]
        return ("MATCH", "Recovered SHA-256 matches the trusted original.") if hmac.compare_digest(actual, expected) else (
            "MISMATCH", f"Recovered SHA-256 {actual} does not match the trusted original {expected}."
        )
