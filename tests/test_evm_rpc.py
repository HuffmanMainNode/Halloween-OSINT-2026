import json
from unittest.mock import patch

import pytest

from halloween_osint.evm_rpc import _NoRedirect, inspect_transaction

TX = "0x" + "a" * 64


class Response:
    status = 200

    def __init__(self, result, response_id=1):
        self.document = {"jsonrpc": "2.0", "id": response_id, "result": result}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return json.dumps(self.document).encode()


class Opener:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        return Response(next(self.results))


def test_inspect_transaction_uses_read_only_calls():
    values = iter([
        "0x1",
        {"hash": TX, "value": "0x10"},
        {"transactionHash": TX, "status": "0x1"},
    ])
    opener = Opener(values)
    with patch("urllib.request.build_opener", return_value=opener):
        result = inspect_transaction("https://node.example/rpc", TX)
    assert result["status"] == "mined"
    assert result["chain_id_hex"] == "0x1"
    assert len(opener.calls) == 3
    assert "not independently consensus-verified" in result["limitations"][0]
    assert all(call[0].get_method() == "POST" for call in opener.calls)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://node.example/rpc",
        "file:///etc/passwd",
        "https://user:password@node.example/rpc",
        "https://node.example/rpc?token=secret",
        "https://node.example:invalid/rpc",
        "https://node.example:99999/rpc",
        "https://node.example/rpc#fragment",
    ],
)
def test_rejects_insecure_or_ambiguous_endpoint(endpoint):
    with pytest.raises(ValueError):
        inspect_transaction(endpoint, TX)


def test_allows_http_only_for_loopback():
    values = iter(["0x1", {"hash": TX}, {"transactionHash": TX}])
    opener = Opener(values)
    with patch("urllib.request.build_opener", return_value=opener):
        result = inspect_transaction("http://127.0.0.1:8545", TX)
    assert result["status"] == "mined"


def test_rejects_malformed_hash_and_timeout():
    with pytest.raises(ValueError):
        inspect_transaction("https://node.example/rpc", "0x1234")
    with pytest.raises(ValueError):
        inspect_transaction("https://node.example/rpc", TX, timeout=float("nan"))
    with pytest.raises(ValueError):
        inspect_transaction("https://node.example/rpc", TX, timeout=True)


def test_rejects_mismatched_json_rpc_response_id():
    opener = Opener(["0x1"])
    opener.open = lambda request, timeout: Response("0x1", response_id=2)
    with patch("urllib.request.build_opener", return_value=opener), pytest.raises(
        ValueError, match="mismatched response ID"
    ):
        inspect_transaction("https://node.example/rpc", TX)


@pytest.mark.parametrize(
    "results, message",
    [
        (["not-a-chain-id"], "invalid chain ID"),
        (["0x1", {"hash": "0x" + "b" * 64}, None], "mismatched hash"),
        (["0x1", {"hash": TX}, {"transactionHash": "0x" + "b" * 64}], "mismatched transaction hash"),
        (["0x1", None, {"transactionHash": TX}], "receipt without a matching transaction"),
    ],
)
def test_rejects_inconsistent_node_results(results, message):
    opener = Opener(results)
    with patch("urllib.request.build_opener", return_value=opener), pytest.raises(
        ValueError, match=message
    ):
        inspect_transaction("https://node.example/rpc", TX)


def test_rejects_oversized_rpc_response():
    class LargeResponse(Response):
        def read(self, limit):
            return b"x" * limit

    opener = Opener(["0x1"])
    opener.open = lambda request, timeout: LargeResponse("0x1")
    with patch("urllib.request.build_opener", return_value=opener), pytest.raises(
        ValueError, match="2 MiB"
    ):
        inspect_transaction("https://node.example/rpc", TX)


def test_redirects_are_not_followed():
    handler = _NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://internal.example/") is None


def test_rpc_errors_are_bounded():
    opener = Opener(["0x1"])
    def fail(request, timeout):
        response = type("ErrorResponse", (), {"status": 200, "read": lambda self, limit: json.dumps({
            "jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "x" * 1000}
        }).encode(), "__enter__": lambda self: self, "__exit__": lambda self, *args: False})()
        return response
    opener.open = fail
    with patch("urllib.request.build_opener", return_value=opener), pytest.raises(
        RuntimeError, match="x{200}$"
    ):
        inspect_transaction("https://node.example/rpc", TX)
