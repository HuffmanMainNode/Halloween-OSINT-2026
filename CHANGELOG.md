# Changelog

## 0.1.1 - Unreleased

- Clarify that commit `cb07208` wired the EVM inspection command only; SBOM inventory and KEV correlation are implemented in Huffman Cyber Observatory, not this repository.
- Add public-hostname SSRF protections to passive domain observation and root-scoped MCP filesystem access.
- Document the read-only EVM CLI inspector and its current CLI-only status.

## 0.1.0 - 2026-10-31

Initial public foundation release.

- SHA-256 evidence manifest creation and verification.
- Passive DNS and TLS certificate observation for a supplied hostname.
- Offline CSV/JSON transaction aggregation with per-asset totals and address-flow edges.
- Local stdio MCP interface exposing the same bounded operations.
- JSON schema, sample data, methods documentation, security policy, and automated tests.

This release is an initial implementation. Network-dependent behavior and integration should be validated in the target environment before operational use.
