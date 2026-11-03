"""Evidence hashing and verification. Hashes establish byte identity, not truth or authorship."""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any


SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


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


def _validated_manifest(manifest: Any) -> tuple[Path, list[dict[str, Any]]]:
    if not isinstance(manifest, dict):
        raise ValueError("Evidence manifest must be a JSON object")
    if manifest.get("schema_version") != "1.0" or manifest.get("algorithm") != "sha256":
        raise ValueError("Unsupported evidence manifest schema or algorithm")
    root_value = manifest.get("root")
    if not isinstance(root_value, str) or not root_value:
        raise ValueError("Manifest root must be a non-empty path string")
    root = Path(root_value).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Manifest root is not a directory")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("Manifest files must be an array")

    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise ValueError(f"Manifest file entry {index} must be an object")
        path_value = item.get("path")
        digest = item.get("sha256")
        size = item.get("size_bytes")
        if not isinstance(path_value, str) or not path_value.strip():
            raise ValueError(f"Manifest file entry {index} has an invalid path")
        rel = Path(path_value)
        windows_path = PureWindowsPath(path_value)
        if (
            rel.is_absolute()
            or windows_path.is_absolute()
            or windows_path.drive
            or "\\" in path_value
            or ":" in path_value
            or ".." in rel.parts
            or rel.as_posix() in {"", "."}
        ):
            raise ValueError(f"Unsafe manifest path: {path_value}")
        normalized = rel.as_posix()
        if normalized in seen:
            raise ValueError(f"Duplicate manifest path: {normalized}")
        seen.add(normalized)
        if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            raise ValueError(f"Invalid SHA-256 digest for manifest path: {normalized}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"Invalid byte size for manifest path: {normalized}")
    return root, files


def verify_manifest(manifest_path: str | Path, detect_unlisted: bool = True) -> dict[str, Any]:
    source = Path(manifest_path).expanduser().resolve(strict=True)
    manifest = json.loads(source.read_text(encoding="utf-8"))
    root, files = _validated_manifest(manifest)

    seen: set[str] = set()
    results = []
    for item in files:
        rel = Path(item["path"])
        normalized = rel.as_posix()
        candidate = root / rel
        cursor = root
        has_symlink = False
        for part in rel.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                has_symlink = True
                break
        seen.add(normalized)
        if has_symlink:
            results.append({"path": normalized, "status": "unsafe_symlink"})
            continue
        target = candidate.resolve(strict=False)
        if not _inside(target, root):
            raise ValueError(f"Manifest path escapes root: {item['path']}")
        if not target.is_file():
            results.append({"path": normalized, "status": "missing"})
            continue
        digest = hashlib.sha256()
        size = 0
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        actual = digest.hexdigest()
        status = "match" if actual == item["sha256"].lower() and size == item["size_bytes"] else "changed"
        results.append({
            "path": normalized,
            "status": status,
            "actual_sha256": actual,
            "actual_size_bytes": size,
        })

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
