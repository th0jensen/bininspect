use anyhow::Result;

use crate::{
    detect::{DetectedFormat, detect_format},
    model::{BinaryFormat, CodeSignInfo, ExportInfo, ImportInfo, SectionInfo, SymbolInfo},
};

pub mod elf;
pub mod macho;
pub mod pe;
pub mod unknown;
pub mod wasm;

#[derive(Debug, Clone)]
pub struct ParsedBinary {
    pub format: BinaryFormat,
    pub arch: String,
    pub entrypoint: Option<u64>,
    pub is_stripped: bool,
    pub has_debug: bool,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub codesign: Option<CodeSignInfo>,
}

pub fn parse(bytes: &[u8]) -> Result<ParsedBinary> {
    match detect_format(bytes) {
        DetectedFormat::MachO | DetectedFormat::MachOFat => macho::parse_macho(bytes),
        DetectedFormat::Elf => elf::parse_elf(bytes),
        DetectedFormat::Pe => pe::parse_pe(bytes),
        DetectedFormat::Wasm => wasm::parse_wasm(bytes),
        DetectedFormat::Unknown => parse_unknown(bytes),
    }
}

fn parse_unknown(bytes: &[u8]) -> Result<ParsedBinary> {
    match unknown::parse_unknown(bytes) {
        Ok(parsed) => Ok(parsed),
        Err(err) => {
            eprintln!("bininspect error: failed to parse unknown binary format");
            eprintln!("  - {err}");
            panic!("bininspect safety rail: unknown binary parse failed");
        }
    }
}
