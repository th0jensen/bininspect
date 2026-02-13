use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    MachO,
    Elf,
    Pe,
    Wasm,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub arch: String,
    pub entrypoint: Option<u64>,
    pub is_stripped: bool,
    pub has_debug: bool,
    pub file_size: usize,
    pub magic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
pub struct SectionInfo {
    pub name: String,
    pub addr: Option<u64>,
    pub offset: u64,
    pub size: u64,
    pub flags: Vec<String>,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
pub struct ImportInfo {
    pub library: Option<String>,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
pub struct ExportInfo {
    pub symbol: String,
    pub addr: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
pub struct SymbolInfo {
    pub name: String,
    pub addr: Option<u64>,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
pub struct StringInfo {
    pub offset: u64,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub details: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
pub struct CodeSignInfo {
    pub present: bool,
    pub identifier: Option<String>,
    pub flags: Option<u32>,
    pub hash_type: Option<String>,
    pub page_size: Option<u32>,
    pub code_limit: Option<u64>,
    pub cdhash: Option<String>,
    pub has_cms_signature: bool,
    pub entitlements: Option<String>,
    pub code_directory_hashes_verified: Option<bool>,
    pub verified_pages: Option<u32>,
    pub total_pages: Option<u32>,
    pub mismatch_pages: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
pub struct Hashes {
    pub sha256: String,
    pub sha1: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-types", derive(tsify::Tsify))]
#[cfg_attr(feature = "ts-types", tsify(into_wasm_abi))]
pub struct AnalysisReport {
    pub binary: BinaryInfo,
    pub hashes: Hashes,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub strings: Vec<StringInfo>,
    pub findings: Vec<Finding>,
    pub codesign: Option<CodeSignInfo>,
}
