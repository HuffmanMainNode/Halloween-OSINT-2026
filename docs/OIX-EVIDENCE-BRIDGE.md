# Open Intelligence Exchange evidence bridge

Halloween OSINT can optionally create a signed OIX `evidence.submit` envelope for a selected local artifact.

## What is exchanged

The bridge hashes the chosen file and includes only:
- SHA-256 digest and byte size
- Media type
- Evidence type and identifier
- Collector and method versions
- Collection timestamp and optional source reference
- A caller-supplied summary and limitations
- Classification and status assertions

The artifact itself is not uploaded, attached, or transmitted by this helper. The helper also does not fetch the source URL or open a network connection. The returned envelope can be passed to an OIX transport or local inbox separately.

## Setup

Install both projects in the same Python environment. The interoperability CI checks out OIX at the reviewed immutable commit recorded in `.github/workflows/oix-evidence-interoperability.yml`; it does not follow a moving integration branch.

Generate an OIX identity using the OIX onboarding guide, then call `create_evidence_message` with the identity directory, recipient agent ID, artifact path, evidence type, method name/version, summary, and limitations.

## Review boundary

- The sender's summary, classification, status, and source URI are assertions supplied by the caller.
- A valid signature proves possession of the signing key, not the operator's real-world identity or the truth of the evidence.
- The receiving OIX inbox validates the schema and signature and places the item into pending review. An operator must approve it before downstream processing.
- The bridge's artifact hash detects byte changes relative to the digest; it does not prove the file's source or authorship.
- Never send private case files or personal data without an appropriate legal basis and explicit authorization.

See [OIX Agent Onboarding](https://github.com/HuffmanMainNode/Open-Intelligence-Exchange/blob/main/docs/AGENT-ONBOARDING.md) and [Halloween OSINT Agent Integration](AGENT-INTEGRATION.md).
