mod analysis;
mod detect;
pub mod model;
mod parsers;
mod util;

use anyhow::Result;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub use model::{
    AnalysisReport, BinaryFormat, BinaryInfo, CodeSignInfo, ExportInfo, Finding, Hashes,
    ImportInfo, SectionInfo, Severity, StringInfo, SymbolInfo,
};

pub const API_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn analyze_bytes(bytes: &[u8]) -> Result<AnalysisReport> {
    let mut parsed = parsers::parse(bytes)?;

    parsed.sections.sort_by_key(|s| s.offset);
    analysis::entropy::apply_section_entropy(bytes, &mut parsed.sections);

    let strings = analysis::strings::extract_strings(bytes, 4, 800, 256);
    let findings = analysis::risk::build_findings(
        parsed.format,
        &parsed.sections,
        &parsed.imports,
        &strings,
        parsed.codesign.as_ref(),
    );

    let hashes = compute_hashes(bytes);

    let binary = BinaryInfo {
        format: parsed.format,
        arch: parsed.arch,
        entrypoint: parsed.entrypoint,
        is_stripped: parsed.is_stripped,
        has_debug: parsed.has_debug,
        file_size: bytes.len(),
        magic: util::hex_lower(&bytes[..bytes.len().min(8)]),
    };

    Ok(AnalysisReport {
        binary,
        hashes,
        sections: parsed.sections,
        imports: parsed.imports,
        exports: parsed.exports,
        symbols: parsed.symbols,
        strings,
        findings,
        codesign: parsed.codesign,
    })
}

pub fn analyze_to_json(bytes: &[u8], pretty: bool) -> Result<String> {
    let report = analyze_bytes(bytes)?;
    if pretty {
        Ok(serde_json::to_string_pretty(&report)?)
    } else {
        Ok(serde_json::to_string(&report)?)
    }
}

fn compute_hashes(bytes: &[u8]) -> Hashes {
    let mut sha256 = Sha256::new();
    sha256.update(bytes);
    let sha256_hex = util::hex_lower(&sha256.finalize());

    let mut sha1 = Sha1::new();
    sha1.update(bytes);
    let sha1_hex = util::hex_lower(&sha1.finalize());

    Hashes {
        sha256: sha256_hex,
        sha1: sha1_hex,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{DetectedFormat, detect_format};
    use std::fs;

    #[test]
    fn detects_wasm_format() {
        let wasm = [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
        assert_eq!(detect_format(&wasm), DetectedFormat::Wasm);
    }

    #[test]
    fn analyzes_minimal_wasm_snapshot() {
        // 00asm + version + empty type/import/function/export/code sections
        let wasm = [
            0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00, // header
            0x01, 0x01, 0x00, // type section (0 types)
            0x03, 0x02, 0x01, 0x00, // function section (1 function, type 0)
            0x07, 0x08, 0x01, 0x04, b'm', b'a', b'i', b'n', 0x00, 0x00, // export main func 0
            0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B, // code section (1 empty body)
        ];

        let report = analyze_bytes(&wasm).expect("wasm analysis should succeed");
        let json =
            serde_json::to_string_pretty(&report).expect("json serialization should succeed");

        assert!(json.contains("\"format\": \"wasm\""));
        assert!(json.contains("\"arch\": \"wasm32\""));
        assert!(json.contains("\"symbol\": \"main\""));
    }

    #[test]
    fn detects_pe_format() {
        let mut pe = vec![0u8; 0x100];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3C] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");

        assert_eq!(detect_format(&pe), DetectedFormat::Pe);
    }

    #[test]
    fn parses_bmw_ecu_unknown_binary() {
        let mut unknown = vec![0xFFu8; 64 * 1024];
        let marker = b"BMW DME MEVD17 SWFL 1037502345 calibration";
        unknown[..marker.len()].copy_from_slice(marker);
        let report =
            analyze_bytes(&unknown).expect("BMW-style unknown input should be parsed as ECU");

        assert_eq!(report.binary.format, BinaryFormat::Unknown);
        assert!(!report.sections.is_empty());
        assert!(
            report
                .symbols
                .iter()
                .any(|sym| sym.name.contains("oem:bmw"))
        );
    }

    #[test]
    fn manufacturer_priority_prefers_bmw_then_ford_then_vw_then_mercedes() {
        let mut unknown = vec![0u8; 96 * 1024];
        let marker = b"BMW FORD VW MERCEDES ECU SWFL 12345678";
        unknown[..marker.len()].copy_from_slice(marker);
        let report = analyze_bytes(&unknown).expect("priority test input should parse");

        assert_eq!(report.binary.format, BinaryFormat::Unknown);
        assert!(report.binary.arch.contains("oem=bmw"));
        assert!(
            report
                .symbols
                .iter()
                .any(|sym| sym.name.contains("oem:bmw"))
        );
    }

    #[test]
    #[should_panic(expected = "bininspect safety rail: unknown binary parse failed")]
    fn panics_when_unknown_binary_parse_fails() {
        let non_ecu = b"hello world not an ecu dump";
        let _ = analyze_bytes(non_ecu);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn analyzes_own_macho_binary() {
        let exe = std::env::current_exe().expect("current test executable path");
        let bytes = fs::read(&exe).expect("read current test executable");
        let report = analyze_bytes(&bytes).expect("analyze current test executable");

        assert_eq!(report.binary.format, BinaryFormat::MachO);
        assert!(report.binary.file_size > 0);
        assert!(!report.sections.is_empty());
        assert!(!report.binary.arch.is_empty());
    }
}
