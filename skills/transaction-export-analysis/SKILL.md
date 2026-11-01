# Skill: Analyze a supplied public transaction export

## Objective

Summarize transfers and address-to-address edges in a local CSV or JSON export without inventing identity or chain context.

## Procedure

1. Obtain the export from an identified source and preserve the original file.
2. Confirm the export's chain, asset units, time basis, and extraction method outside this tool.
3. Run `halloween-osint ledger analyze EXPORT.csv --output flow-report.json`.
4. Review rejected rows and duplicate transaction IDs.
5. Validate material transaction IDs against the relevant chain and inspect chain-specific semantics.
6. Report address-flow relationships as technical observations, not identity or intent claims.

## Boundaries

The analyzer is offline. It does not query a blockchain, validate confirmations, decode contracts, calculate fiat values, or deanonymize addresses. Totals are grouped by the asset label supplied in the file.
