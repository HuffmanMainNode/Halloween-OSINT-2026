"""Minimal stdio MCP server exposing bounded local investigative tools."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
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
            "output": {"type": "string", "description": "Path for manifest JSON"},
            "overwrite": {"type": "boolean", "default": False, "description": "Allow replacing an existing output file"}
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
        "description": "Perform ordinary DNS resolution and a TLS handshake on port 443 for an explicitly supplied public DNS hostname. Private, loopback, link-local, and other non-global addresses are rejected.",
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


def _scoped_path(value: str, root: Path | None, *, must_exist: bool, overwrite: bool = False) -> Path:
    candidate = Path(value).expanduser()
    resolved = candidate.resolve(strict=must_exist)
    if root is not None:
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError("path is outside the configured Halloween OSINT root") from exc
    if must_exist and not resolved.exists():
        raise ValueError("input path does not exist")
    if not must_exist and resolved.exists() and not overwrite:
        raise FileExistsError("output already exists; set overwrite=true to replace it")
    if not must_exist and not resolved.parent.exists():
        raise FileNotFoundError("output parent directory does not exist")
    return resolved


def _call_tool(
    name: str, arguments: dict[str, Any], root: Path | None = None
) -> Any:
    if name == "create_evidence_manifest":
        directory = _scoped_path(arguments["directory"], root, must_exist=True)
        output = _scoped_path(
            arguments["output"], root, must_exist=False,
            overwrite=bool(arguments.get("overwrite", False)),
        )
        return create_manifest(str(directory), str(output))
    if name == "verify_evidence_manifest":
        manifest = _scoped_path(arguments["manifest"], root, must_exist=True)
        manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
        if root is not None:
            _scoped_path(manifest_data["root"], root, must_exist=True)
        return verify_manifest(str(manifest))
    if name == "observe_domain":
        return observe_domain(arguments["hostname"], float(arguments.get("timeout", 5.0)))
    if name == "analyze_transactions":
        source = _scoped_path(arguments["input"], root, must_exist=True)
        return analyze_transactions(str(source))
    raise ValueError(f"Unknown tool: {name}")


def _response(request_id: Any, result: Any = None, error: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        message["error"] = error
    else:
        message["result"] = result
    return message


def handle(message: dict[str, Any], root: Path | None = None) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if method == "notifications/initialized" or (method or "").startswith("notifications/"):
        return None
    if method == "initialize":
        return _response(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "halloween-osint", "version": __version__}
        })
    if method == "ping":
        return _response(request_id, {})
    if method == "tools/list":
        return _response(request_id, {"tools": TOOLS})
    if method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        # Tool arguments are untrusted; any tool failure becomes a structured MCP error.
        try:
            result = _call_tool(name, arguments, root)
            return _response(request_id, {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}], "isError": False})
        except Exception as exc:  # noqa: BLE001
            return _response(request_id, {"content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}], "isError": True})
    if request_id is None:
        return None
    return _response(request_id, error={"code": -32601, "message": f"Method not found: {method}"})


def main() -> None:
    parser = argparse.ArgumentParser(prog="halloween-osint-mcp")
    parser.add_argument(
        "--root",
        default=os.environ.get("HALLOWEEN_OSINT_ROOT"),
        help="restrict all MCP file paths to this directory (or set HALLOWEEN_OSINT_ROOT)",
    )
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve(strict=True) if args.root else None
    if root is not None and not root.is_dir():
        parser.error("--root must be an existing directory")
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            response = _response(None, error={"code": -32700, "message": "Parse error"})
        else:
            # Malformed request objects must not terminate the stdio server process.
            try:
                response = handle(request, root)
            except Exception as exc:  # noqa: BLE001
                response = _response(
                    request.get("id") if isinstance(request, dict) else None,
                    error={"code": -32603, "message": f"Internal error: {type(exc).__name__}"},
                )
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
