"""Evidence hashing and verification. Hashes establish byte identity, not truth or authorship."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def create_manifest(root: str | Path, output: str | Path | None = None) -> dict[str, Any]:
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir():
        raise ValueError("Evidence root must be a directory")
    output_path = Path(output).expanduser().resolve() if output else None
    records: list[dict[str, Any]] = []

    for current, dirs, names in os.walk(base, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(d for d in dirs if not (current_path / d).is_symlink())
        for name in sorted(names):
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            resolved = candidate.resolve(strict=True)
            if not _inside(resolved, base):
                continue
            if output_path is not None and resolved == output_path:
                continue
            digest = hashlib.sha256()
            size = 0
            with candidate.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            records.append({
                "path": candidate.relative_to(base).as_posix(),
                "size_bytes": size,
                "sha256": digest.hexdigest(),
            })

    manifest = {
        "schema_version": "1.0",
        "created_at": datetime.now(UTC).isoformat(),
        "algorithm": "sha256",
        "root": str(base),
        "files": records,
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def verify_manifest(manifest_path: str | Path, detect_unlisted: bool = True) -> dict[str, Any]:
    source = Path(manifest_path).expanduser().resolve(strict=True)
    manifest = json.loads(source.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != "1.0" or manifest.get("algorithm") != "sha256":
        raise ValueError("Unsupported evidence manifest schema or algorithm")
    root = Path(manifest["root"]).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Manifest root is not a directory")

    seen: set[str] = set()
    results = []
    for item in manifest.get("files", []):
        rel = Path(item["path"])
        if rel.is_absolute() or ".." in rel.parts:
            raise ValueError(f"Unsafe manifest path: {item['path']}")
        candidate = root / rel
        # Reject symlinks in any path component. Resolving first would erase
        # evidence that the recorded path has changed into a symlink.
        cursor = root
        has_symlink = False
        for part in rel.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                has_symlink = True
                break
        seen.add(rel.as_posix())
        if has_symlink:
            results.append({"path": rel.as_posix(), "status": "unsafe_symlink"})
            continue
        target = candidate.resolve(strict=False)
        if not _inside(target, root):
            raise ValueError(f"Manifest path escapes root: {item['path']}")
        if not target.is_file():
            results.append({"path": rel.as_posix(), "status": "missing"})
            continue
        digest = hashlib.sha256()
        size = 0
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        actual = digest.hexdigest()
        status = "match" if actual == item["sha256"] and size == item["size_bytes"] else "changed"
        results.append({"path": rel.as_posix(), "status": status, "actual_sha256": actual, "actual_size_bytes": size})

    extras: list[str] = []
    if detect_unlisted:
        for current, dirs, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            dirs[:] = [d for d in dirs if not (current_path / d).is_symlink()]
            for name in names:
                candidate = current_path / name
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                rel = candidate.relative_to(root).as_posix()
                if rel not in seen and candidate.resolve() != source:
                    extras.append(rel)
    extras.sort()
    failures = sum(1 for result in results if result["status"] != "match")
    return {
        "verified": failures == 0 and not extras,
        "checked_files": len(results),
        "matching_files": len(results) - failures,
        "results": results,
        "unlisted_files": extras,
    }
