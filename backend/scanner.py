from __future__ import annotations

import os
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .hashing import sha256_file

EXCLUDED_DIRS = {
    ".venv", "venv", "node_modules", "__pycache__", ".git", "dist", "build",
    ".pytest_cache", ".mypy_cache", "securevault-output", "reports",
}
EXCLUDED_FILES = {".securevault.sqlite3", ".securevault.audit.key", "securevault-audit.xlsx"}


def scan_folder(root: Path, progress=None, cancelled=None, excluded_paths: Iterable[Path] = ()) -> tuple[list[dict], list[dict]]:
    if root.is_symlink() or getattr(root, "is_junction", lambda: False)():
        raise ValueError("Scanning a symbolic link or junction as the selected root is not allowed.")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("The selected path is not a directory.")
    candidates: list[tuple[Path, str, int, float]] = []
    results: list[dict] = []
    errors: list[dict] = []
    excluded_files = {path.resolve() for path in excluded_paths}
    excluded_dirs = {path.resolve() for path in excluded_paths if path.is_dir()}
    if root in excluded_dirs:
        raise ValueError("The selected folder is a SecureVault output or audit folder.")
    stack = [root]
    while stack:
        if cancelled and cancelled():
            break
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            errors.append({"path": str(current.relative_to(root)), "error": str(exc)})
            continue
        for entry in entries:
            if cancelled and cancelled():
                break
            try:
                if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    directory = Path(entry.path)
                    if entry.name.casefold() not in EXCLUDED_DIRS and not entry.name.startswith(".securevault-") and directory.resolve() not in excluded_dirs:
                        stack.append(directory)
                    continue
                if not entry.is_file(follow_symlinks=False) or entry.name in EXCLUDED_FILES or entry.name.startswith(".securevault-"):
                    continue
                path = Path(entry.path)
                if path.resolve() in excluded_files:
                    continue
                stat = entry.stat(follow_symlinks=False)
                candidates.append((path, path.relative_to(root).as_posix(), stat.st_size, stat.st_mtime))
            except InterruptedError:
                raise
            except (OSError, ValueError) as exc:
                errors.append({"path": str(Path(entry.path).relative_to(root)), "error": str(exc)})
    total_bytes = sum(item[2] for item in candidates)
    processed_bytes = 0
    for index, (path, relative_path, size, modified) in enumerate(candidates, start=1):
        if cancelled and cancelled():
            break
        try:
            def file_progress(file_bytes: int) -> None:
                if progress:
                    progress(processed_bytes + file_bytes, total_bytes, index - 1, len(candidates))

            results.append({
                "name": path.name,
                "relative_path": relative_path,
                "extension": path.suffix.lower() or "—",
                "size": size,
                "modified_at": datetime.fromtimestamp(modified, timezone.utc).isoformat(),
                "sha256": sha256_file(path, cancelled, file_progress),
                "path": str(path.resolve(strict=True)),
            })
        except InterruptedError:
            raise
        except (OSError, ValueError) as exc:
            errors.append({"path": relative_path, "error": str(exc)})
        processed_bytes += size
        if progress:
            progress(processed_bytes, total_bytes, index, len(candidates))
    return results, errors
