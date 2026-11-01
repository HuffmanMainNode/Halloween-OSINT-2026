import json
from unittest.mock import patch

import pytest

from halloween_osint.evm_rpc import inspect_transaction

TX = "0x" + "a" * 64


class Response:
    status = 200

    def __init__(self, result):
        self.result = result

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return json.dumps({"jsonrpc": "2.0", "id": 1, "result": self.result}).encode()


def test_inspect_transaction_uses_read_only_calls():
    values = iter(["0x1", {"hash": TX, "value": "0x10"}, {"status": "0x1"}])
    with patch("urllib.request.urlopen", side_effect=lambda *a, **k: Response(next(values))):
        result = inspect_transaction("https://node.example/rpc", TX)
    assert result["status"] == "mined"
    assert result["chain_id_hex"] == "0x1"
    assert "not independently consensus-verified" in result["limitations"][0]


@pytest.mark.parametrize("endpoint", ["http://node.example/rpc", "file:///etc/passwd"])
def test_rejects_insecure_remote_or_non_http_endpoint(endpoint):
    with pytest.raises(ValueError):
        inspect_transaction(endpoint, TX)


def test_rejects_malformed_hash():
    with pytest.raises(ValueError):
        inspect_transaction("https://node.example/rpc", "0x1234")
