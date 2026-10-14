from __future__ import annotations

import os
from pathlib import Path

import pytest

from backend.decryption import decrypt_file
from backend.encryption import CHUNK_SIZE, HEADER, SecureVaultFormatError, encrypt_file
from backend.hashing import sha256_file
from backend.verification import verify_encrypted


@pytest.mark.parametrize("contents", [b"", b"SecureVault text", bytes(range(256)) * 32, "vault-🔐".encode()])
def test_encrypt_decrypt_round_trip(tmp_path: Path, contents: bytes) -> None:
    original = tmp_path / "original.bin"
    encrypted = tmp_path / "original.bin.svlt"
    recovered = tmp_path / "recovered.bin"
    original.write_bytes(contents)
    encrypt_file(original, encrypted, "correct horse battery staple")
    decrypt_file(encrypted, recovered, "correct horse battery staple")
    assert recovered.read_bytes() == contents
    assert sha256_file(original) == sha256_file(recovered)


def test_large_files_are_processed_in_authenticated_chunks(tmp_path: Path) -> None:
    original = tmp_path / "large.bin"
    encrypted = tmp_path / "large.bin.svlt"
    recovered = tmp_path / "large-copy.bin"
    original.write_bytes(os.urandom(CHUNK_SIZE * 2 + 173))
    encrypt_file(original, encrypted, "large file passphrase")
    assert encrypted.stat().st_size > original.stat().st_size
    assert encrypted.read_bytes().startswith(b"SVLT")
    assert HEADER.size < encrypted.stat().st_size
    decrypt_file(encrypted, recovered, "large file passphrase")
    assert sha256_file(original) == sha256_file(recovered)


def test_wrong_password_leaves_no_plaintext(tmp_path: Path) -> None:
    original, encrypted, recovered = tmp_path / "secret.txt", tmp_path / "secret.txt.svlt", tmp_path / "recovered.txt"
    original.write_bytes(b"secret bytes")
    encrypt_file(original, encrypted, "correct")
    with pytest.raises(SecureVaultFormatError, match="Authentication failed"):
        decrypt_file(encrypted, recovered, "incorrect")
    assert not recovered.exists()
    assert not list(tmp_path.glob(".securevault-plaintext-*.tmp"))


def test_tampering_and_truncation_are_rejected(tmp_path: Path) -> None:
    original = tmp_path / "data"
    encrypted = tmp_path / "data.svlt"
    original.write_bytes(b"authenticated payload")
    encrypt_file(original, encrypted, "pass")
    damaged = bytearray(encrypted.read_bytes())
    damaged[HEADER.size + 8] ^= 1
    encrypted.write_bytes(damaged)
    with pytest.raises(SecureVaultFormatError):
        decrypt_file(encrypted, tmp_path / "tampered", "pass")
    assert not (tmp_path / "tampered").exists()
    encrypt_file(original, tmp_path / "fresh.svlt", "pass")
    truncated = tmp_path / "fresh.svlt"
    truncated.write_bytes(truncated.read_bytes()[:-4])
    with pytest.raises(SecureVaultFormatError):
        decrypt_file(truncated, tmp_path / "truncated", "pass")
    assert not (tmp_path / "truncated").exists()


def test_existing_outputs_are_never_overwritten(tmp_path: Path) -> None:
    original, encrypted = tmp_path / "source", tmp_path / "source.svlt"
    original.write_bytes(b"first")
    encrypt_file(original, encrypted, "pass")
    encrypted_bytes = encrypted.read_bytes()
    original.write_bytes(b"second")
    with pytest.raises(FileExistsError):
        encrypt_file(original, encrypted, "pass")
    assert encrypted.read_bytes() == encrypted_bytes
    recovered = tmp_path / "recovered"
    recovered.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        decrypt_file(encrypted, recovered, "pass")
    assert recovered.read_bytes() == b"keep"


def test_verification_uses_independent_trusted_hash(tmp_path: Path) -> None:
    original, encrypted = tmp_path / "source", tmp_path / "source.svlt"
    original.write_bytes(b"original content")
    encrypt_file(original, encrypted, "pass")
    trusted = {"sha256": sha256_file(original)}
    assert verify_encrypted(encrypted, trusted, "pass")[0] == "MATCH"
    assert verify_encrypted(encrypted, {"sha256": "0" * 64}, "pass")[0] == "MISMATCH"
    assert verify_encrypted(encrypted, None, "pass")[0] == "UNAVAILABLE"


def test_empty_password_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"content")
    with pytest.raises(ValueError, match="Password cannot be empty"):
        encrypt_file(source, tmp_path / "source.svlt", "")


def test_encryption_rejects_a_source_changed_since_the_trusted_scan(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "source.svlt"
    source.write_bytes(b"changed content")
    with pytest.raises(ValueError, match="changed since its trusted SHA-256 scan"):
        encrypt_file(source, target, "password", expected_sha256="0" * 64)
    assert not target.exists()
    assert not list(tmp_path.glob(".securevault-*.tmp"))


def test_cancellation_cleans_temporary_encrypted_and_plaintext_files(tmp_path: Path) -> None:
    source = tmp_path / "source"
    encrypted = tmp_path / "source.svlt"
    source.write_bytes(os.urandom(CHUNK_SIZE * 2))
    with pytest.raises(InterruptedError, match="Encryption cancelled"):
        encrypt_file(source, encrypted, "password", cancelled=lambda: True)
    assert not encrypted.exists()
    assert not list(tmp_path.glob(".securevault-*.tmp"))

    encrypt_file(source, encrypted, "password")
    recovered = tmp_path / "recovered"
    with pytest.raises(InterruptedError, match="Decryption cancelled"):
        decrypt_file(encrypted, recovered, "password", cancelled=lambda: True)
    assert not recovered.exists()
    assert not list(tmp_path.glob(".securevault-plaintext-*.tmp"))
