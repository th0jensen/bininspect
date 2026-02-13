// @generated file from wasmbuild -- do not edit
// deno-lint-ignore-file
// deno-fmt-ignore-file

export interface Finding {
  severity: Severity;
  title: string;
  details: string;
  evidence: string[];
}

export interface CodeSignInfo {
  present: boolean;
  identifier: string | undefined;
  flags: number | undefined;
  hash_type: string | undefined;
  page_size: number | undefined;
  code_limit: number | undefined;
  cdhash: string | undefined;
  has_cms_signature: boolean;
  entitlements: string | undefined;
  code_directory_hashes_verified: boolean | undefined;
  verified_pages: number | undefined;
  total_pages: number | undefined;
  mismatch_pages: number[];
}

export interface StringInfo {
  offset: number;
  value: string;
}

export interface Hashes {
  sha256: string;
  sha1: string;
}

export interface SectionInfo {
  name: string;
  addr: number | undefined;
  offset: number;
  size: number;
  flags: string[];
  entropy: number | undefined;
}

export interface SymbolInfo {
  name: string;
  addr: number | undefined;
  kind: string;
}

export interface ImportInfo {
  library: string | undefined;
  symbol: string;
}

export interface AnalysisReport {
  binary: BinaryInfo;
  hashes: Hashes;
  sections: SectionInfo[];
  imports: ImportInfo[];
  exports: ExportInfo[];
  symbols: SymbolInfo[];
  strings: StringInfo[];
  findings: Finding[];
  codesign: CodeSignInfo | undefined;
}

export interface ExportInfo {
  symbol: string;
  addr: number | undefined;
}

export type Severity = "info" | "low" | "medium" | "high";

export type BinaryFormat = "mach_o" | "elf" | "pe" | "wasm" | "unknown";

export interface BinaryInfo {
  format: BinaryFormat;
  arch: string;
  entrypoint: number | undefined;
  is_stripped: boolean;
  has_debug: boolean;
  file_size: number;
  magic: string;
}

export function analyze(bytes: Uint8Array): AnalysisReport;

export function analyze_pretty(bytes: Uint8Array): string;

export function api_version(): string;
