# Binary Inspector Implementation Plan

## Goal
Implement a Rust-first binary inspection core in `crates/bininspect` that produces normalized, deterministic JSON output suitable for CLI use now and WASM/UI integration later.

## Phase 1: Core Data Model + API
- Add a normalized output model:
  - `BinaryInfo`
  - `SectionInfo`
  - `ImportInfo`
  - `ExportInfo`
  - `SymbolInfo`
  - `Finding`
  - `CodeSignInfo` (Mach-O only)
  - `Hashes`
- Expose one coarse API:
  - `analyze_bytes(bytes: &[u8]) -> Result<AnalysisReport, Error>`
  - `analyze_to_json(bytes: &[u8], pretty: bool) -> Result<String, Error>`

## Phase 2: Format Detection + Parsing
- Detect:
  - Mach-O (including fat/universal)
  - ELF
  - PE
  - WASM
- Parse core fields for each format:
  - headers needed for arch/entrypoint/debug-strip hints
  - sections/segments with offsets/sizes/flags
  - imports/exports where practical
  - symbols where available

## Phase 3: Analysis
- Add bounded printable string extraction
- Compute Shannon entropy per section
- Add heuristic risk findings:
  - unsigned/ad-hoc code signature (Mach-O)
  - RWX executable+writable regions
  - high-entropy regions
  - suspicious imports
  - embedded URL/IP indicators
  - weird section naming
- Include file hashes (`sha256`, `sha1`) for external checks

## Phase 4: Mach-O Code Signature
- Detect `LC_CODE_SIGNATURE`
- Parse SuperBlob + CodeDirectory metadata
- Extract identifier, flags, optional entitlements text
- Compute `cdhash`
- Verify CodeDirectory page hashes against file contents
- Explicitly avoid certificate chain/notarization validation

## Phase 5: CLI + Tests
- CLI reads a file path and emits JSON report
- Unit tests for format detection/parsers
- Snapshot-style determinism tests for normalized JSON
- Run `cargo fmt`, `cargo clippy`, and `cargo test`

## Phase 6: WASM Wrapper
- Add `crates/bininspect-wasm` as a thin `wasm-bindgen` boundary over `bininspect`
- Expose coarse API:
  - `analyze(bytes) -> JsValue` (parsed JSON object)
  - `analyze_pretty(bytes) -> String` (pretty JSON)
  - `api_version() -> String`
- Keep boundary non-chatty (single call returns full analysis blob)
