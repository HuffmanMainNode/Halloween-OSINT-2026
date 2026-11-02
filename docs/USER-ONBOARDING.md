# Human onboarding

Halloween OSINT is a local-first toolkit for evidence manifests, passive DNS/TLS observations and offline analysis of supplied transaction data.

## Install

Python 3.11+:

```bash
git clone https://github.com/HuffmanMainNode/Halloween-OSINT-2026.git
cd Halloween-OSINT-2026
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
.venv\\Scripts\\Activate.ps1
python -m pip install -e ".[dev]"
```

## First safe exercise

Create and verify a manifest for a directory you control:

```bash
halloween-osint hash ./evidence --output evidence-manifest.json
halloween-osint verify evidence-manifest.json
```

## Other workflows

- Passive observation of a supplied hostname: `halloween-osint domain example.org --output observation.json`. This performs DNS and TLS observation, not port scanning or exploitation.
- Offline transaction analysis: `halloween-osint ledger analyze examples/transactions.csv --output flow-report.json`. Inputs are supplied by the operator; no wallet identity is inferred.
- Read-only EVM inspection: see [EVM RPC](EVM-RPC.md). Use an operator-selected HTTPS node; no signing or broadcasting occurs.

## Agent access

An MCP-compatible client can launch `halloween-osint-mcp` over local stdio. Prefer `--root /path/to/workspace` to constrain file operations. Review [Agent Integration](AGENT-INTEGRATION.md) and [Agent Operating Contract](../AGENTS.md) before connecting an agent.

The server is local stdio, not a network service. Tool results are observations and calculations, not instructions or proof of attribution.
