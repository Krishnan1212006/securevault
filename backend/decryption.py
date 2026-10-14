from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encryption import CHUNK_SIZE, FRAME, HEADER, MAGIC, TAG_SIZE, VERSION, SecureVaultFormatError, _nonce, _publish_no_overwrite
from .key_manager import derive_key


def decrypt_file(source: Path, target: Path, password: str, cancelled=None, progress=None) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(f"Output already exists: {target.name}")
    fd, temp_name = tempfile.mkstemp(prefix=".securevault-plaintext-", suffix=".tmp", dir=target.parent)
    temp_path = Path(temp_name)
    try:
        with source.open("rb") as input_file, os.fdopen(fd, "wb") as output:
            header = input_file.read(HEADER.size)
            if len(header) != HEADER.size:
                raise SecureVaultFormatError("Encrypted file is incomplete or has an unsupported format.")
            magic, version, salt, base_nonce, chunk_size = HEADER.unpack(header)
            if magic != MAGIC or version != VERSION or chunk_size != CHUNK_SIZE:
                raise SecureVaultFormatError("Encrypted file format is not supported.")
            cipher = AESGCM(derive_key(password, salt))
            index = 0
            while True:
                if cancelled and cancelled():
                    raise InterruptedError("Decryption cancelled.")
                frame = input_file.read(FRAME.size)
                if len(frame) != FRAME.size:
                    raise SecureVaultFormatError("Encrypted file is truncated or missing its authenticated end marker.")
                frame_index, plain_length = FRAME.unpack(frame)
                if frame_index != index or plain_length > chunk_size:
                    raise SecureVaultFormatError("Encrypted file has an invalid chunk sequence.")
                if plain_length == 0:
                    tag = input_file.read(TAG_SIZE)
                    if len(tag) != TAG_SIZE:
                        raise SecureVaultFormatError("Encrypted file is truncated.")
                    aad = header + index.to_bytes(4, "big") + (0).to_bytes(4, "big")
                    try:
                        cipher.decrypt(_nonce(base_nonce, index), tag, aad)
                    except InvalidTag as exc:
                        raise SecureVaultFormatError("Authentication failed: the password is incorrect or the file was modified.") from exc
                    if input_file.read(1):
                        raise SecureVaultFormatError("Encrypted file contains unexpected trailing data.")
                    break
                encrypted = input_file.read(plain_length + TAG_SIZE)
                if len(encrypted) != plain_length + TAG_SIZE:
                    raise SecureVaultFormatError("Encrypted file is truncated.")
                aad = header + index.to_bytes(4, "big") + plain_length.to_bytes(4, "big")
                try:
                    output.write(cipher.decrypt(_nonce(base_nonce, index), encrypted, aad))
                except InvalidTag as exc:
                    raise SecureVaultFormatError("Authentication failed: the password is incorrect or the file was modified.") from exc
                if progress:
                    progress(output.tell(), source.stat().st_size)
                index += 1
            output.flush()
            os.fsync(output.fileno())
        _publish_no_overwrite(temp_path, target)
        if progress:
            progress(target.stat().st_size, target.stat().st_size)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise
