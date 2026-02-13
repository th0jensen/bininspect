# Agent Instructions (Binary Inspector)

## Scope Control
- Implement **core + bininspect-bin + bininspect-wasm** first.
- **Do not build the bininspect-gpui app yet.** It must remain scaffold-only.

## Dependencies
Keep them minimal and justified.

Preferred:
- `anyhow` (or small custom error type; pick one)
- `serde` + `serde_json`
- `wasm-bindgen`

Avoid:
- Heavy binary parsing frameworks
- Large UI frameworks
- Unnecessary regex-heavy crates

Every dependency must be justified by necessity and performance impact.

## Performance Priorities
1. Web performance (WASM): minimal allocations, Worker-based execution, coarse API.
2. Bare-metal performance (CLI): fast parsing, minimal copying.

Guidelines:
- Prefer `&[u8]` + cursor readers.
- Avoid unnecessary `String` allocations.
- Keep hot paths small and predictable.
- Ensure stable ordering for deterministic tests.

## Code Quality
- Idiomatic Rust
- `rustfmt` clean
- Clippy-clean
- Minimal public API surface

## Testing
- Unit tests for detection and parsing
- Snapshot tests for normalized JSON
- No network or external tooling in tests

## Safety / Claims
- No “malware detection” claims.
- Risk findings must be clearly heuristic.
- Apple codesign: parse + verify CodeDirectory hashes only.
- No certificate chain validation or notarization in v1.

## Deliverables
- `plan.md` is where you should update and keep track of the implementation roadmap, currently it is empty.
- WASM API remains coarse (`analyze()` returning structured JSON).
