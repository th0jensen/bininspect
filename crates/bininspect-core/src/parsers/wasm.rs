use anyhow::{Result, bail};

use crate::model::{BinaryFormat, ExportInfo, ImportInfo, SectionInfo, SymbolInfo};
use crate::parsers::ParsedBinary;

pub fn parse_wasm(bytes: &[u8]) -> Result<ParsedBinary> {
    if bytes.len() < 8 || bytes[..4] != [0x00, b'a', b's', b'm'] {
        bail!("invalid WASM magic");
    }
    if bytes[4..8] != [0x01, 0x00, 0x00, 0x00] {
        bail!("unsupported WASM version");
    }

    let mut offset = 8usize;
    let mut sections = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut symbols = Vec::new();
    let mut entrypoint = None;

    let mut has_name_section = false;
    let mut has_debug_section = false;

    while offset < bytes.len() {
        let sec_start = offset;
        let sec_id = bytes[offset];
        offset += 1;

        let Some((sec_size, next)) = read_var_u32(bytes, offset) else {
            break;
        };
        offset = next;

        let payload_off = offset;
        let payload_end = payload_off.saturating_add(sec_size as usize);
        if payload_end > bytes.len() {
            break;
        }
        let payload = &bytes[payload_off..payload_end];

        let mut section_name = wasm_section_name(sec_id).to_string();
        if sec_id == 0 {
            if let Some((name, _consumed)) = read_wasm_name(payload, 0) {
                section_name = format!("custom:{name}");
                let lname = name.to_ascii_lowercase();
                if lname == "name" {
                    has_name_section = true;
                }
                if lname.contains("debug") || lname.contains("sourcemap") || lname == "name" {
                    has_debug_section = true;
                }
            }
        } else if sec_id == 2 {
            parse_import_section(payload, &mut imports, &mut symbols);
        } else if sec_id == 7 {
            parse_export_section(payload, &mut exports, &mut symbols);
        } else if sec_id == 8
            && let Some((idx, _)) = read_var_u32(payload, 0)
        {
            entrypoint = Some(idx as u64);
        }

        sections.push(SectionInfo {
            name: section_name,
            addr: None,
            offset: sec_start as u64,
            size: (payload_end - sec_start) as u64,
            flags: Vec::new(),
            entropy: None,
        });

        offset = payload_end;
    }

    imports.sort_by(|a, b| {
        a.symbol
            .cmp(&b.symbol)
            .then_with(|| a.library.cmp(&b.library))
    });
    imports.dedup_by(|a, b| a.symbol == b.symbol && a.library == b.library);

    exports.sort_by(|a, b| a.symbol.cmp(&b.symbol));
    exports.dedup_by(|a, b| a.symbol == b.symbol && a.addr == b.addr);

    symbols.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.kind.cmp(&b.kind)));
    symbols.dedup_by(|a, b| a.name == b.name && a.kind == b.kind && a.addr == b.addr);

    Ok(ParsedBinary {
        format: BinaryFormat::Wasm,
        arch: "wasm32".to_string(),
        entrypoint,
        is_stripped: !has_name_section,
        has_debug: has_debug_section,
        sections,
        imports,
        exports,
        symbols,
        codesign: None,
    })
}

fn parse_import_section(
    payload: &[u8],
    imports: &mut Vec<ImportInfo>,
    symbols: &mut Vec<SymbolInfo>,
) {
    let Some((count, mut off)) = read_var_u32(payload, 0) else {
        return;
    };

    for _ in 0..count {
        let Some((module, next)) = read_wasm_name(payload, off) else {
            break;
        };
        off = next;

        let Some((name, next)) = read_wasm_name(payload, off) else {
            break;
        };
        off = next;

        let Some(kind) = payload.get(off).copied() else {
            break;
        };
        off += 1;

        let import_kind = match kind {
            0 => {
                let Some((_typeidx, n)) = read_var_u32(payload, off) else {
                    break;
                };
                off = n;
                "func"
            }
            1 => {
                let Some(n) = skip_table_type(payload, off) else {
                    break;
                };
                off = n;
                "table"
            }
            2 => {
                let Some(n) = skip_limits(payload, off) else {
                    break;
                };
                off = n;
                "memory"
            }
            3 => {
                if off + 2 > payload.len() {
                    break;
                }
                off += 2;
                "global"
            }
            _ => "other",
        };

        imports.push(ImportInfo {
            library: Some(module.to_string()),
            symbol: name.to_string(),
        });

        symbols.push(SymbolInfo {
            name: format!("{module}::{name}"),
            addr: None,
            kind: format!("import_{import_kind}"),
        });

        if symbols.len() >= 20_000 {
            break;
        }
    }
}

fn parse_export_section(
    payload: &[u8],
    exports: &mut Vec<ExportInfo>,
    symbols: &mut Vec<SymbolInfo>,
) {
    let Some((count, mut off)) = read_var_u32(payload, 0) else {
        return;
    };

    for _ in 0..count {
        let Some((name, next)) = read_wasm_name(payload, off) else {
            break;
        };
        off = next;

        let Some(kind) = payload.get(off).copied() else {
            break;
        };
        off += 1;

        let Some((index, next)) = read_var_u32(payload, off) else {
            break;
        };
        off = next;

        let export_kind = match kind {
            0 => "func",
            1 => "table",
            2 => "memory",
            3 => "global",
            _ => "other",
        };

        exports.push(ExportInfo {
            symbol: name.to_string(),
            addr: Some(index as u64),
        });
        symbols.push(SymbolInfo {
            name: name.to_string(),
            addr: Some(index as u64),
            kind: format!("export_{export_kind}"),
        });

        if symbols.len() >= 20_000 {
            break;
        }
    }
}

fn skip_table_type(bytes: &[u8], offset: usize) -> Option<usize> {
    if offset >= bytes.len() {
        return None;
    }
    // reftype byte + limits
    let after_ref = offset + 1;
    skip_limits(bytes, after_ref)
}

fn skip_limits(bytes: &[u8], offset: usize) -> Option<usize> {
    let flags = *bytes.get(offset)?;
    let mut off = offset + 1;
    let (_, next) = read_var_u32(bytes, off)?;
    off = next;
    if flags & 0x01 != 0 {
        let (_, next2) = read_var_u32(bytes, off)?;
        off = next2;
    }
    Some(off)
}

fn read_wasm_name(bytes: &[u8], offset: usize) -> Option<(&str, usize)> {
    let (len, mut off) = read_var_u32(bytes, offset)?;
    let end = off.checked_add(len as usize)?;
    let data = bytes.get(off..end)?;
    let text = std::str::from_utf8(data).ok()?;
    off = end;
    Some((text, off))
}

fn read_var_u32(bytes: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0u32;
    let mut idx = offset;

    loop {
        let byte = *bytes.get(idx)?;
        idx += 1;

        result |= u32::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some((result, idx));
        }

        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
}

fn wasm_section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data_count",
        _ => "unknown",
    }
}
