# Reproducible case workflow

This workflow keeps source material separate from analysis and avoids turning a lead into an attribution claim.

## 1. Create a case directory

Use a new local directory for each investigation. Preserve original exports unchanged. Record where each source came from and when it was acquired in a separate case log. Do not place credentials or unnecessary personal information in the repository.

## 2. Preserve source bytes

Run the evidence manifest command against the source directory and store the manifest outside that directory. Record the manifest's own SHA-256 in the case log through an independently trusted process if required by the case.

## 3. Collect bounded observations

For infrastructure work, supply one hostname at a time to the domain observer. Record the observation timestamp and the machine/network context. Repeat observations at separate times if change detection matters. A single DNS/TLS observation is not a historical record.

For transaction work, retain the original chain export and its source URL or retrieval method. Analyze a working copy. Validate relevant transaction IDs independently against the appropriate chain before relying on them.

## 4. Analyze and report

Keep three categories separate:

- **Observed:** bytes, DNS answers, certificate fields, or rows present in supplied input.
- **Derived:** hashes, grouped totals, and graph edges calculated by this software.
- **Hypothesis:** a proposed explanation that requires independent corroboration.

Never label a wallet, domain, or address as belonging to a person or organization solely because of a graph connection or a public label.

## 5. Verify before sharing

Re-run evidence verification before exporting or sharing. Include method, time, input provenance, errors, and limitations in the report. Redact sensitive information and obtain human review before publication.
