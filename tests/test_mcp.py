from halloween_osint.mcp_server import handle


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
