# cfr-to-text

`cfr-to-text` extracts text from Code of Federal Regulations XML files into plain text or JSONL.

## Intent

Turn bulky CFR XML inputs into cleaner downstream-friendly text artifacts while preserving enough structure and metadata to support later indexing or analysis.

## Ambition

The output-format options and config-oriented workflow suggest a practical pipeline component for legal-text extraction rather than a browser or viewer.

## Current Status

The repo is a focused single-binary CLI with a config file and a mature usage-oriented README. It looks purpose-built and relatively complete for its current scope.

## Core Capabilities Or Focus Areas

- Read CFR XML inputs.
- Emit plain text or JSONL output.
- Use config-driven extraction behavior.
- Carry forward element/file metadata when requested.
- Produce chunked or split outputs depending on configuration.

## Project Layout

- `src/`: Rust source for the main crate or application entrypoint.
- `Cargo.toml`: crate or workspace manifest and the first place to check for package structure.

## Setup And Requirements

- Rust toolchain.
- CFR XML source files.
- Optional `cfr-to-text.toml` configuration for repeatable runs.

## Build / Run / Test Commands

```bash
cargo build
cargo test
cargo run -- --config cfr-to-text.toml
```

## Notes, Limitations, Or Known Gaps

- The project is shaped around CFR XML specifically, not arbitrary legal-document extraction.
- Output policy is largely controlled through the TOML config.

## Next Steps Or Roadmap Hints

- Keep the emitted schemas stable if downstream indexing or analytics tooling will depend on them.
- Add more fixtures if CFR source variations become a maintenance issue.
