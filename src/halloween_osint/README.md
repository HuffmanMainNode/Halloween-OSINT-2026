# Source package

This directory contains the installable Python package. It is intentionally dependency-light and uses the Python 3.11+ standard library at runtime.

## Modules

- `evidence.py`: SHA-256 manifests and verification for local evidence directories.
- `infrastructure.py`: bounded DNS and TLS observations for one explicitly supplied hostname.
- `ledger.py`: offline CSV/JSON transaction-export analysis using decimal arithmetic.
- `cli.py`: command-line entry points.
- `mcp_server.py`: local stdio agent interface.

## Development

Run from the repository root:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

Read [the project README](../../README.md) and [methods and limitations](../../docs/METHODS-AND-LIMITATIONS.md) before operational use.
