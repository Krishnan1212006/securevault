from __future__ import annotations

import hashlib
import hmac
import os
import struct
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .key_manager import derive_key, new_salt

MAGIC = b"SVLT"
VERSION = 1
CHUNK_SIZE = 1024 * 1024
HEADER = struct.Struct(">4sB16s12sI")
FRAME = struct.Struct(">II")
TAG_SIZE = 16


class SecureVaultFormatError(ValueError):
    pass


def _nonce(base: bytes, index: int) -> bytes:
    if index > 0xFFFFFFFF:
        raise ValueError("File exceeds the supported number of authenticated chunks.")
    suffix = int.from_bytes(base[8:], "big") ^ index
    return base[:8] + suffix.to_bytes(4, "big")


def _publish_no_overwrite(temp_path: Path, target: Path) -> None:
    try:
        os.link(temp_path, target)
    except FileExistsError:
        raise FileExistsError(f"Output already exists: {target.name}") from None
    except OSError as exc:
        raise OSError(f"Could not safely publish output file: {exc}") from exc
    finally:
        temp_path.unlink(missing_ok=True)


def encrypt_file(
    source: Path, target: Path, password: str, cancelled=None,
    expected_sha256: str | None = None, progress=None,
) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(f"Output already exists: {target.name}")
    salt, base_nonce = new_salt(), os.urandom(12)
    header = HEADER.pack(MAGIC, VERSION, salt, base_nonce, CHUNK_SIZE)
    cipher = AESGCM(derive_key(password, salt))
    source_size = source.stat().st_size
    fd, temp_name = tempfile.mkstemp(prefix=".securevault-", suffix=".tmp", dir=target.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
            output.write(header)
            index = 0
            digest = hashlib.sha256()
            processed_bytes = 0
            while chunk := input_file.read(CHUNK_SIZE):
                if cancelled and cancelled():
                    raise InterruptedError("Encryption cancelled.")
                digest.update(chunk)
                aad = header + index.to_bytes(4, "big") + len(chunk).to_bytes(4, "big")
                output.write(FRAME.pack(index, len(chunk)))
                output.write(cipher.encrypt(_nonce(base_nonce, index), chunk, aad))
                index += 1
                processed_bytes += len(chunk)
                if progress:
                    progress(processed_bytes, source_size)
            if expected_sha256 and not hmac.compare_digest(digest.hexdigest(), expected_sha256):
                raise ValueError("Source file content changed since its trusted SHA-256 scan.")
            final_aad = header + index.to_bytes(4, "big") + (0).to_bytes(4, "big")
            output.write(FRAME.pack(index, 0))
            output.write(cipher.encrypt(_nonce(base_nonce, index), b"", final_aad))
            output.flush()
            os.fsync(output.fileno())
        if progress:
            progress(source_size, source_size)
        _publish_no_overwrite(temp_path, target)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
