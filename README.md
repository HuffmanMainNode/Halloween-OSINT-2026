# Halloween OSINT 2026

**OPEN INTELLIGENCE · AGENT-READY · COMMUNITY-POWERED**

A practical, local-first toolkit for preserving digital evidence, examining public internet infrastructure, and analyzing public blockchain transaction data. Built for investigators and software agents that need reproducible results rather than opaque conclusions.

> **Happy Halloween 2026 — by MrCakes**

## What this project actually does

| Capability | Problem solved | Current implementation |
|---|---|---|
| Evidence integrity | Can a collected file be shown to match the exact bytes originally recorded? | SHA-256 manifests, metadata, and verification |
| Infrastructure observations | What can be observed about a supplied public domain without intrusive scanning? | DNS resolution and TLS certificate inspection |
| Transaction flow analysis | How do supplied public transaction records connect, and where does value flow? | Offline CSV/JSON normalization, graph edges, and flow summaries |
| Agent access | Can an agent discover and call the same deterministic functions as a human operator? | Local stdio MCP server with explicit tool schemas |

The project does not claim to identify anonymous people behind domains or wallet addresses. A relationship in data is not proof of common ownership, intent, or control.

## Quick start

Requires Python 3.11 or newer. Runtime uses only the Python standard library.

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1

python -m pip install -e ".[dev]"
halloween-osint --help
```

### 1. Preserve and verify evidence

```bash
halloween-osint hash ./evidence --output evidence-manifest.json
halloween-osint verify evidence-manifest.json
```

The manifest records relative paths, byte sizes, SHA-256 digests, and collection timestamps. Verification recalculates hashes and reports missing, changed, or unexpected files. Keep the manifest separate from the evidence directory when practical.

### 2. Observe public infrastructure

```bash
halloween-osint domain example.org --output domain-observation.json
```

This performs ordinary DNS lookups and a TLS handshake to the supplied hostname. It does not port-scan, exploit, authenticate, or attempt to bypass access controls. Network observations depend on the operator's resolver, network, and observation time.

### 3. Analyze supplied public transaction records

```bash
halloween-osint ledger analyze examples/transactions.csv --output flow-report.json
```

Input is supplied by the operator. This module does not fetch blockchain data or infer wallet identity. See [transaction data format](docs/TRANSACTION-DATA.md).

## Agent integration

Run the local MCP server over standard input/output:

```bash
halloween-osint-mcp
```

It exposes the same bounded operations as the CLI: evidence manifest creation/verification, domain observation, and analysis of caller-supplied transaction rows. The server writes protocol messages to stdout and diagnostics to stderr. Review tool descriptions and permissions before connecting an agent.

See [AGENTS.md](AGENTS.md) and [docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md).

## Design rules

- **Local-first:** no mandatory account, API key, hosted backend, or paid data provider.
- **Evidence before interpretation:** retain source material, timestamps, hashes, and method details.
- **Facts are not guesses:** observations, derived results, and analyst hypotheses must remain distinguishable.
- **Reproducible:** deterministic analysis of the same input should produce the same substantive result.
- **Least privilege:** passive collection only; no credential collection, exploitation, stealth, or unauthorized access.
- **Human accountability:** an agent may prepare a report; a person remains responsible for validation and publication.
- **No fabricated enrichment:** missing data stays missing. No invented ownership, attribution, confidence, or corroboration.

## Repository map

- `src/halloween_osint/evidence.py` — SHA-256 evidence manifests and verification
- `src/halloween_osint/infrastructure.py` — DNS and TLS observations
- `src/halloween_osint/ledger.py` — offline transaction normalization and flow analysis
- `src/halloween_osint/mcp_server.py` — local agent tool interface
- `schemas/` — machine-readable output contracts
- `tests/` — deterministic unit tests
- `examples/` — clearly synthetic sample input
- `docs/` — methods, limitations, and operating guidance

## Status

Initial public foundation release. Treat outputs as investigative leads, not legal conclusions or attribution findings. Network-derived observations are point-in-time and should be independently corroborated before publication.

## License

Apache-2.0. See [LICENSE](LICENSE).
