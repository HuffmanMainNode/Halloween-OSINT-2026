# Skill: Preserve and verify a digital evidence directory

## Objective

Create a reproducible SHA-256 manifest for a local evidence directory and later detect missing, altered, or unlisted files.

## Procedure

1. Confirm the operator has authority to handle the directory.
2. Preserve originals. Work from a copy where analysis may modify files.
3. Run `halloween-osint hash CASE_DIR --output CASE_DIR.manifest.json`.
4. Store the manifest separately from the evidence directory.
5. Record acquisition source and time in the case log. The manifest timestamp is generated locally and is not a trusted timestamp authority.
6. Run `halloween-osint verify CASE_DIR.manifest.json` before sharing.
7. Treat any non-match, missing file, or unlisted file as a review item.

## Interpretation

A matching digest supports the conclusion that the current file bytes match the bytes recorded in the manifest. It does not prove authorship, authenticity, truth, or pre-manifest chain of custody.
