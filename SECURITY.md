# Security policy

## Scope

This project is designed for local evidence handling, passive DNS/TLS observations, and offline analysis of transaction records supplied by the operator.

## Reporting a vulnerability

Please do not publish exploitable details in a public issue. Use GitHub's private vulnerability reporting feature for this repository if enabled, or contact the repository maintainer through the contact information on the GitHub profile.

Include the affected version, reproduction steps, impact, and a proposed mitigation where possible. Do not include real personal data or private investigation material.

## Safety boundaries

- No credential collection, exploitation, stealth, persistence, or unauthorized access.
- No automated targeting of private individuals.
- Domain observation is limited to standard DNS resolution and a TLS handshake to a hostname explicitly supplied by the operator.
- Transaction analysis consumes local input; it does not deanonymize wallet owners.
- Evidence manifests hash file contents but do not establish who created a file or whether its contents are truthful.

## Data handling

Investigators are responsible for lawful collection, secure storage, retention, and redaction of sensitive information. Do not commit private case files, credentials, API tokens, or personal data.
