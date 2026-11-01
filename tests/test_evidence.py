import json

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
