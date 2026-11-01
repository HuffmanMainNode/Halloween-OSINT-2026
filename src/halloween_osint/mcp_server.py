"""Minimal stdio MCP server exposing bounded local investigative tools."""
from __future__ import annotations

import json
import sys
from typing import Any

from .evidence import create_manifest, verify_manifest
from .infrastructure import observe_domain
from .ledger import analyze_transactions

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "create_evidence_manifest",
        "description": "Create a SHA-256 manifest for regular files beneath a local directory. Symlinks are skipped. Hashes establish byte identity, not truth or authorship.",
        "inputSchema": {"type": "object", "properties": {
            "directory": {"type": "string", "description": "Local evidence directory"},
            "output": {"type": "string", "description": "Path for manifest JSON"}
        }, "required": ["directory", "output"], "additionalProperties": False}
    },
    {
        "name": "verify_evidence_manifest",
        "description": "Recalculate file hashes and report missing, changed, and unlisted files.",
        "inputSchema": {"type": "object", "properties": {
            "manifest": {"type": "string", "description": "Local manifest JSON path"}
        }, "required": ["manifest"], "additionalProperties": False}
    },
    {
        "name": "observe_domain",
        "description": "Perform ordinary DNS resolution and a TLS handshake on port 443 for an explicitly supplied hostname. No scanning or exploitation.",
        "inputSchema": {"type": "object", "properties": {
            "hostname": {"type": "string"},
            "timeout": {"type": "number", "minimum": 0.1, "maximum": 20}
        }, "required": ["hostname"], "additionalProperties": False}
    },
    {
        "name": "analyze_transactions",
        "description": "Analyze an operator-supplied local CSV or JSON transaction export offline. Does not validate chain inclusion or identify wallet owners.",
        "inputSchema": {"type": "object", "properties": {
            "input": {"type": "string", "description": "Local CSV or JSON file path"}
        }, "required": ["input"], "additionalProperties": False}
    }
]


def _call_tool(name: str, arguments: dict[str, Any]) -> Any:
    if name == "create_evidence_manifest":
        return create_manifest(arguments["directory"], arguments["output"])
    if name == "verify_evidence_manifest":
        return verify_manifest(arguments["manifest"])
    if name == "observe_domain":
        return observe_domain(arguments["hostname"], float(arguments.get("timeout", 5.0)))
    if name == "analyze_transactions":
        return analyze_transactions(arguments["input"])
    raise ValueError(f"Unknown tool: {name}")


def _response(request_id: Any, result: Any = None, error: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        message["error"] = error
    else:
        message["result"] = result
    return message


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if method == "notifications/initialized" or (method or "").startswith("notifications/"):
        return None
    if method == "initialize":
        return _response(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "halloween-osint", "version": "0.1.0"}
        })
    if method == "ping":
        return _response(request_id, {})
    if method == "tools/list":
        return _response(request_id, {"tools": TOOLS})
    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        try:
            result = _call_tool(name, arguments)
            return _response(request_id, {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}], "isError": False})
        except Exception as exc:
            return _response(request_id, {"content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}], "isError": True})
    if request_id is None:
        return None
    return _response(request_id, error={"code": -32601, "message": f"Method not found: {method}"})


def main() -> None:
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = handle(request)
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            sys.stderr.write(f"protocol input error: {type(exc).__name__}: {exc}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    main()
