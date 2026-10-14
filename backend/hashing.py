from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path, cancelled=None, progress=None) -> str:
    digest = hashlib.sha256()
    processed = 0
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            if cancelled and cancelled():
                raise InterruptedError("File scan cancelled.")
            digest.update(chunk)
            processed += len(chunk)
            if progress:
                progress(processed)
    return digest.hexdigest()
