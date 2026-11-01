# Test suite

The tests cover evidence manifest creation and verification, altered and unlisted files, symlink substitution, transaction aggregation and malformed amounts, hostname input validation, and MCP initialization/tool discovery.

Run the suite from the repository root:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

Tests are designed to be deterministic and do not require live network access. A green test suite verifies tested software behavior only. It does not validate external data, investigative conclusions, or operational suitability.
