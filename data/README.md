# Local research data

`data/` is reserved for local inputs and generated device/capture data (for example
HAR files, extracted IPA contents, device registrations, and session material). These
files are intentionally ignored because they may be large, licensed third-party
content, or include device identifiers and credentials.

Do not commit production captures or credentials. Use sanitized, minimal fixtures
under `src/test/resources/` when a test needs versioned input data.
