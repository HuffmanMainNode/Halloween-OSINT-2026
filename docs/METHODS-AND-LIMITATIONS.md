# Methods and limitations

## Evidence integrity

The manifest hashes regular files with SHA-256 and records relative path and byte count. Verification compares current bytes with the recorded digest and reports unlisted files. It does not provide a trusted timestamp, prove chain of custody before collection, establish authorship, or prove that a file's contents are accurate. Store manifests and source files with access controls; sign or timestamp manifests through an independently trusted process when stronger assurance is required.

## Public infrastructure observation

The domain observer uses the operating system's configured resolver and makes one TLS connection to TCP port 443. It records returned IP addresses and certificate metadata visible to the local TLS stack. It does not enumerate subdomains, scan ports, crawl pages, exploit services, or test application security. Resolver results may differ by geography, network, DNS caching, and time. TLS validation is performed against the machine's configured trust store.

## Transaction flow analysis

The ledger module parses local CSV/JSON rows, rejects malformed rows, de-duplicates transaction identifiers, and groups transfers by asset and address pair. It does not query a blockchain, validate signatures or confirmations, decode contract calls, account for fees, interpret token decimals, or attribute addresses. A transaction row in an export remains an unverified input until independently checked against the relevant chain and source.

## Confidence and attribution

The initial release intentionally does not assign confidence scores. A numeric score without a documented calibration dataset and validation method would create false precision. Analysts should record independent corroboration and distinguish observed facts, derived calculations, and hypotheses in their own case notes.
