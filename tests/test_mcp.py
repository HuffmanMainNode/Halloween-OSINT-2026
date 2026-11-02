import io
import json
import sys

import pytest

from halloween_osint.mcp_server import handle, main


def test_initialize_handshake():
    result = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert result["result"]["serverInfo"]["name"] == "halloween-osint"
    assert "tools" in result["result"]["capabilities"]


def test_tools_are_discoverable():
    result = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {tool["name"] for tool in result["result"]["tools"]}
    assert names == {
        "create_evidence_manifest", "verify_evidence_manifest",
        "observe_domain", "analyze_transactions"
    }


def test_mcp_rejects_path_outside_root(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside.json"
    root.mkdir()
    outside.write_text("{}")
    request = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "verify_evidence_manifest", "arguments": {"manifest": str(outside)}},
    }
    result = handle(request, root.resolve())
    assert result["result"]["isError"] is True
    assert "outside the configured" in result["result"]["content"][0]["text"]


def test_mcp_rejects_symlink_escape(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside.json"
    root.mkdir()
    outside.write_text("{}")
    link = root / "escape.json"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    request = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "verify_evidence_manifest", "arguments": {"manifest": str(link)}},
    }
    result = handle(request, root.resolve())
    assert result["result"]["isError"] is True
    assert "outside the configured" in result["result"]["content"][0]["text"]


def test_mcp_refuses_output_overwrite_without_explicit_permission(tmp_path):
    root = tmp_path / "root"
    evidence = root / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "record.txt").write_text("evidence")
    output = root / "manifest.json"
    output.write_text("existing")
    request = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "create_evidence_manifest",
            "arguments": {"directory": str(evidence), "output": str(output)},
        },
    }
    result = handle(request, root.resolve())
    assert result["result"]["isError"] is True
    assert output.read_text() == "existing"


def test_mcp_allows_explicit_output_overwrite(tmp_path):
    root = tmp_path / "root"
    evidence = root / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "record.txt").write_text("evidence")
    output = root / "manifest.json"
    output.write_text("existing")
    request = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "create_evidence_manifest",
            "arguments": {
                "directory": str(evidence), "output": str(output), "overwrite": True
            },
        },
    }
    result = handle(request, root.resolve())
    assert result["result"]["isError"] is False
    assert json.loads(output.read_text())["entries"]


def test_malformed_json_returns_parse_error(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["halloween-osint-mcp", "--root", str(tmp_path)])
    stdin = io.StringIO("{not-json}\n")
    stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    main()
    response = json.loads(stdout.getvalue())
    assert response["error"]["code"] == -32700
    assert response["id"] is None
