from __future__ import annotations

import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16
KEY_SIZE = 32


def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")
    return Scrypt(salt=salt, length=KEY_SIZE, n=2**14, r=8, p=1).derive(password.encode("utf-8"))
