"""Read-only EVM JSON-RPC transaction inspection.

The operator supplies the node endpoint. No API key or hosted provider is required.
This module never broadcasts transactions or signs messages.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler

from . import __version__

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
CHAIN_ID = re.compile(r"^0x[0-9a-fA-F]+$")


class _NoRedirect(HTTPRedirectHandler):
    """Do not allow an RPC endpoint to redirect requests to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_endpoint(endpoint: str) -> str:
    if not isinstance(endpoint, str):
        raise TypeError("RPC endpoint must be a string")
    if not endpoint or any(char.isspace() for char in endpoint):
        raise ValueError("RPC endpoint must be a valid absolute URL")
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("RPC endpoint contains invalid URL or port syntax") from exc

    local = hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError("RPC endpoint must use HTTPS; HTTP is allowed only for localhost")
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("RPC endpoint must not contain credentials, query parameters, fragments, or an invalid port")
    return endpoint


def _rpc(endpoint: str, method: str, params: list[Any], timeout: float) -> Any:
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
    }).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"HalloweenOSINT/{__version__}",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"RPC returned HTTP {response.status}")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.URLError as exc:
        # Do not echo the endpoint: callers may have placed sensitive routing
        # information in a URL despite the validation policy.
        raise RuntimeError(f"RPC connection failed: {type(exc).__name__}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("RPC response exceeds 2 MiB safety limit")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("RPC returned invalid JSON") from exc
    if (
        not isinstance(document, dict)
        or document.get("jsonrpc") != "2.0"
        or document.get("id") != 1
    ):
        raise ValueError("invalid JSON-RPC response or mismatched response ID")
    error = document.get("error")
    if error is not None:
        if isinstance(error, dict):
            code = error.get("code")
            message = error.get("message")
            if isinstance(code, int) and isinstance(message, str):
                raise RuntimeError(f"RPC error {code}: {message[:200]}")  # noqa: TRY004
        raise RuntimeError("RPC returned a malformed error object")
    if "result" not in document:
        raise ValueError("JSON-RPC response is missing result")
    return document["result"]


def inspect_transaction(endpoint: str, tx_hash: str, timeout: float = 10.0) -> dict[str, Any]:
    """Retrieve a transaction, receipt, and chain ID using read-only JSON-RPC calls."""
    endpoint = _validate_endpoint(endpoint)
    if not isinstance(tx_hash, str):
        raise TypeError("transaction hash must be a string")
    if not TX_HASH.fullmatch(tx_hash):
        raise ValueError("transaction hash must be a 32-byte 0x-prefixed hex value")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise TypeError("timeout must be a number")
    if not 0 < timeout <= 30:
        raise ValueError("timeout must be greater than 0 and no more than 30 seconds")

    chain_id = _rpc(endpoint, "eth_chainId", [], timeout)
    if not isinstance(chain_id, str):
        raise TypeError("node returned a non-string chain ID")
    if not CHAIN_ID.fullmatch(chain_id):
        raise ValueError("node returned an invalid chain ID")
    transaction = _rpc(endpoint, "eth_getTransactionByHash", [tx_hash], timeout)
    receipt = _rpc(endpoint, "eth_getTransactionReceipt", [tx_hash], timeout)
    if transaction is not None and not isinstance(transaction, dict):
        raise TypeError("node returned a non-object transaction")
    if receipt is not None and not isinstance(receipt, dict):
        raise TypeError("node returned a non-object receipt")
    if (
        transaction is not None
        and transaction.get("hash") is not None
        and transaction["hash"].lower() != tx_hash.lower()
    ):
        raise ValueError("node returned a transaction with a mismatched hash")
    if (
        receipt is not None
        and receipt.get("transactionHash") is not None
        and receipt["transactionHash"].lower() != tx_hash.lower()
    ):
        raise ValueError("node returned a receipt with a mismatched transaction hash")
    if transaction is None and receipt is not None:
        raise ValueError("node returned a receipt without a matching transaction")

    return {
        "schema_version": "1.0",
        "source": "operator_supplied_evm_json_rpc",
        "rpc_endpoint_host": urlsplit(endpoint).hostname,
        "chain_id_hex": chain_id.lower(),
        "transaction_hash": tx_hash.lower(),
        "transaction": transaction,
        "receipt": receipt,
        "status": "not_found" if transaction is None else (
            "pending" if receipt is None else "mined"
        ),
        "limitations": [
            "Data is reported by the operator-selected RPC node and is not independently consensus-verified.",
            "A transaction hash does not identify the real-world owner of an address.",
            "No transaction was broadcast, signed, or modified.",
            "A null result may mean the node has not indexed the transaction.",
        ],
    }
