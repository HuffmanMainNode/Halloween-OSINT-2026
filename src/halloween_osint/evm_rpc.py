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

from . import __version__

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
TX_HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")


def _validate_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError("RPC endpoint must use HTTPS; HTTP is allowed only for localhost")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("RPC endpoint must be an absolute URL without credentials or fragment")
    return endpoint


def _rpc(endpoint: str, method: str, params: list[Any], timeout: float) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        endpoint, data=payload, headers={"Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": f"HalloweenOSINT/{__version__}"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310: endpoint scheme and host are validated
            if response.status != 200:
                raise RuntimeError(f"RPC returned HTTP {response.status}")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"RPC connection failed: {exc}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("RPC response exceeds 2 MiB safety limit")
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("jsonrpc") != "2.0":
        raise ValueError("invalid JSON-RPC response")
    if document.get("error"):
        raise RuntimeError(f"RPC error: {document['error']}")
    if "result" not in document:
        raise ValueError("JSON-RPC response is missing result")
    return document["result"]


def inspect_transaction(endpoint: str, tx_hash: str, timeout: float = 10.0) -> dict[str, Any]:
    """Retrieve a transaction, receipt, and chain ID using read-only JSON-RPC calls."""
    endpoint = _validate_endpoint(endpoint)
    if not TX_HASH.fullmatch(tx_hash):
        raise ValueError("transaction hash must be a 32-byte 0x-prefixed hex value")
    if not 0 < timeout <= 30:
        raise ValueError("timeout must be greater than 0 and no more than 30 seconds")

    chain_id = _rpc(endpoint, "eth_chainId", [], timeout)
    transaction = _rpc(endpoint, "eth_getTransactionByHash", [tx_hash], timeout)
    receipt = _rpc(endpoint, "eth_getTransactionReceipt", [tx_hash], timeout)
    if transaction is not None and not isinstance(transaction, dict):
        raise ValueError("node returned an invalid transaction object")
    if receipt is not None and not isinstance(receipt, dict):
        raise ValueError("node returned an invalid receipt object")
    return {
        "schema_version": "1.0",
        "source": "operator_supplied_evm_json_rpc",
        "rpc_endpoint_host": urlsplit(endpoint).hostname,
        "chain_id_hex": chain_id,
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
            "A null result may mean the node has not indexed the transaction."
        ]
    }
