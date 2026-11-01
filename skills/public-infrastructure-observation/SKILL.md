# Skill: Observe a public hostname without intrusive scanning

## Objective

Record a bounded DNS and TLS observation for a hostname explicitly supplied by the operator.

## Procedure

1. Confirm the hostname is in scope and the operator is authorized to investigate it.
2. Run `halloween-osint domain HOSTNAME --output observation.json`.
3. Preserve the output and note the collection environment and time.
4. If change over time matters, repeat at a later time and compare the raw observations.
5. Corroborate important claims with independent sources.

## Boundaries

This operation performs system DNS resolution and a TLS handshake to TCP port 443 only. It does not enumerate hosts, scan ports, crawl content, authenticate, or exploit. An IP address or certificate field is not proof of ownership or maliciousness.
