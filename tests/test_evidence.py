import pytest

from halloween_osint.evidence import create_manifest, verify_manifest


def test_manifest_and_verification(tmp_path):
    evidence = tmp_path / "case"
    evidence.mkdir()
    (evidence / "note.txt").write_text("original", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest = create_manifest(evidence, manifest_path)
    assert len(manifest["files"]) == 1
    assert verify_manifest(manifest_path)["verified"] is True

    (evidence / "note.txt").write_text("altered", encoding="utf-8")
    result = verify_manifest(manifest_path)
    assert result["verified"] is False
    assert result["results"][0]["status"] == "changed"


def test_unlisted_file_detected(tmp_path):
    evidence = tmp_path / "case"
    evidence.mkdir()
    (evidence / "one.txt").write_text("one", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    create_manifest(evidence, manifest_path)
    (evidence / "two.txt").write_text("two", encoding="utf-8")
    result = verify_manifest(manifest_path)
    assert result["verified"] is False
    assert result["unlisted_files"] == ["two.txt"]


def test_symlink_substitution_is_not_accepted(tmp_path):
    evidence = tmp_path / "case"
    evidence.mkdir()
    original = evidence / "note.txt"
    original.write_text("original", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    create_manifest(evidence, manifest_path)

    original.unlink()
    target = evidence / "target.txt"
    target.write_text("original", encoding="utf-8")
    original.symlink_to(target)

    result = verify_manifest(manifest_path)
    assert result["verified"] is False
    assert result["results"][0]["status"] == "unsafe_symlink"


def test_duplicate_manifest_paths_are_rejected(tmp_path):
    import json
    import pytest

    evidence = tmp_path / "case"
    evidence.mkdir()
    (evidence / "note.txt").write_text("original", encoding="utf-8")
    manifest_path = tmp_path / "manifest.json"
    manifest = create_manifest(evidence)
    manifest["files"].append(dict(manifest["files"][0]))
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate manifest path"):
        verify_manifest(manifest_path)


@pytest.mark.parametrize(
    "path",
    ["../outside.txt", "/etc/passwd", "C:\\Windows\\win.ini", "folder\\..\\secret"],
)
def test_unsafe_manifest_paths_are_rejected(tmp_path, path):
    import json
    import pytest

    evidence = tmp_path / "case"
    evidence.mkdir()
    manifest = {
        "schema_version": "1.0",
        "algorithm": "sha256",
        "root": str(evidence),
        "files": [{"path": path, "size_bytes": 0, "sha256": "0" * 64}],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsafe manifest path"):
        verify_manifest(manifest_path)


@pytest.mark.parametrize(
    "entry",
    [
        {"path": "file.txt", "size_bytes": -1, "sha256": "0" * 64},
        {"path": "file.txt", "size_bytes": True, "sha256": "0" * 64},
        {"path": "file.txt", "size_bytes": 0, "sha256": "not-a-hash"},
    ],
)
def test_malformed_manifest_file_metadata_is_rejected(tmp_path, entry):
    import json
    import pytest

    evidence = tmp_path / "case"
    evidence.mkdir()
    manifest = {
        "schema_version": "1.0",
        "algorithm": "sha256",
        "root": str(evidence),
        "files": [entry],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError):
        verify_manifest(manifest_path)


def test_manifest_files_must_be_an_array(tmp_path):
    import json
    import pytest

    evidence = tmp_path / "case"
    evidence.mkdir()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "schema_version": "1.0",
        "algorithm": "sha256",
        "root": str(evidence),
        "files": {},
    }), encoding="utf-8")

    with pytest.raises(ValueError, match="files must be an array"):
        verify_manifest(manifest_path)
