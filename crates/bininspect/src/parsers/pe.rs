use anyhow::{Result, bail};

use crate::model::{BinaryFormat, ExportInfo, ImportInfo, SectionInfo, SymbolInfo};
use crate::parsers::ParsedBinary;
use crate::util::{Endian, fixed_cstr, null_terminated, read_u16, read_u32, read_u64, slice};

#[derive(Debug, Clone)]
struct PeSection {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
    characteristics: u32,
}

pub fn parse_pe(bytes: &[u8]) -> Result<ParsedBinary> {
    if bytes.len() < 0x40 || bytes[0..2] != [b'M', b'Z'] {
        bail!("invalid or truncated DOS header");
    }

    let pe_off = read_u32(bytes, 0x3C, Endian::Little).unwrap_or(0) as usize;
    if bytes.get(pe_off..pe_off.saturating_add(4)) != Some(b"PE\0\0") {
        bail!("missing PE signature");
    }

    let coff_off = pe_off + 4;
    let machine = read_u16(bytes, coff_off, Endian::Little).unwrap_or(0);
    let num_sections = read_u16(bytes, coff_off + 2, Endian::Little).unwrap_or(0) as usize;
    let ptr_symtab = read_u32(bytes, coff_off + 8, Endian::Little).unwrap_or(0) as usize;
    let num_symbols = read_u32(bytes, coff_off + 12, Endian::Little).unwrap_or(0) as usize;
    let size_opt_header = read_u16(bytes, coff_off + 16, Endian::Little).unwrap_or(0) as usize;
    let characteristics = read_u16(bytes, coff_off + 18, Endian::Little).unwrap_or(0);

    let opt_off = coff_off + 20;
    if opt_off + size_opt_header > bytes.len() {
        bail!("truncated PE optional header");
    }

    let opt_magic = read_u16(bytes, opt_off, Endian::Little).unwrap_or(0);
    let is_64 = match opt_magic {
        0x10B => false,
        0x20B => true,
        _ => bail!("unsupported PE optional header"),
    };

    let entrypoint = read_u32(bytes, opt_off + 16, Endian::Little).map(u64::from);

    let (num_dirs, dir_base) = if is_64 {
        (
            read_u32(bytes, opt_off + 108, Endian::Little).unwrap_or(0) as usize,
            opt_off + 112,
        )
    } else {
        (
            read_u32(bytes, opt_off + 92, Endian::Little).unwrap_or(0) as usize,
            opt_off + 96,
        )
    };

    let export_dir = read_data_directory(bytes, dir_base, num_dirs, 0);
    let import_dir = read_data_directory(bytes, dir_base, num_dirs, 1);
    let debug_dir = read_data_directory(bytes, dir_base, num_dirs, 6);

    let sections_off = opt_off + size_opt_header;
    let sections = parse_sections(bytes, sections_off, num_sections);

    let mut out_sections = Vec::with_capacity(sections.len());
    for s in &sections {
        out_sections.push(SectionInfo {
            name: s.name.clone(),
            addr: Some(u64::from(s.virtual_address)),
            offset: u64::from(s.raw_ptr),
            size: u64::from(s.raw_size.max(s.virtual_size)),
            flags: pe_flag_strings(s.characteristics),
            entropy: None,
        });
    }

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut symbols = Vec::new();

    if let Some((rva, _size)) = import_dir {
        parse_imports(bytes, &sections, rva, is_64, &mut imports);
    }

    if let Some((rva, _size)) = export_dir {
        parse_exports(bytes, &sections, rva, &mut exports);
    }

    parse_coff_symbols(bytes, ptr_symtab, num_symbols, &sections, &mut symbols);

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

    let has_debug = debug_dir.is_some_and(|(_, size)| size > 0);
    let is_stripped = num_symbols == 0 || (characteristics & 0x0200) != 0;

    Ok(ParsedBinary {
        format: BinaryFormat::Pe,
        arch: pe_machine_name(machine).to_string(),
        entrypoint,
        is_stripped,
        has_debug,
        sections: out_sections,
        imports,
        exports,
        symbols,
        codesign: None,
    })
}

fn parse_sections(bytes: &[u8], offset: usize, num_sections: usize) -> Vec<PeSection> {
    let mut out = Vec::new();
    for i in 0..num_sections {
        let off = offset.saturating_add(i.saturating_mul(40));
        if off + 40 > bytes.len() {
            break;
        }

        let name = fixed_cstr(slice(bytes, off, 8).unwrap_or_default());
        let virtual_size = read_u32(bytes, off + 8, Endian::Little).unwrap_or(0);
        let virtual_address = read_u32(bytes, off + 12, Endian::Little).unwrap_or(0);
        let raw_size = read_u32(bytes, off + 16, Endian::Little).unwrap_or(0);
        let raw_ptr = read_u32(bytes, off + 20, Endian::Little).unwrap_or(0);
        let characteristics = read_u32(bytes, off + 36, Endian::Little).unwrap_or(0);

        out.push(PeSection {
            name,
            virtual_address,
            virtual_size,
            raw_ptr,
            raw_size,
            characteristics,
        });
    }
    out
}

fn read_data_directory(
    bytes: &[u8],
    dir_base: usize,
    num_dirs: usize,
    idx: usize,
) -> Option<(u32, u32)> {
    if idx >= num_dirs {
        return None;
    }
    let off = dir_base + idx * 8;
    let rva = read_u32(bytes, off, Endian::Little)?;
    let size = read_u32(bytes, off + 4, Endian::Little)?;
    if rva == 0 || size == 0 {
        None
    } else {
        Some((rva, size))
    }
}

fn rva_to_offset(rva: u32, sections: &[PeSection]) -> Option<usize> {
    for sec in sections {
        let start = sec.virtual_address;
        let span = sec.virtual_size.max(sec.raw_size).max(1);
        let end = start.saturating_add(span);
        if rva >= start && rva < end {
            let delta = rva - start;
            return Some(sec.raw_ptr.saturating_add(delta) as usize);
        }
    }
    None
}

fn parse_imports(
    bytes: &[u8],
    sections: &[PeSection],
    import_rva: u32,
    is_64: bool,
    imports: &mut Vec<ImportInfo>,
) {
    let Some(mut desc_off) = rva_to_offset(import_rva, sections) else {
        return;
    };

    for _ in 0..4096 {
        if desc_off + 20 > bytes.len() {
            break;
        }

        let original_first_thunk = read_u32(bytes, desc_off, Endian::Little).unwrap_or(0);
        let name_rva = read_u32(bytes, desc_off + 12, Endian::Little).unwrap_or(0);
        let first_thunk = read_u32(bytes, desc_off + 16, Endian::Little).unwrap_or(0);

        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let library = rva_to_offset(name_rva, sections)
            .and_then(|off| null_terminated(bytes, off))
            .map(str::to_string);

        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };

        if let Some(mut thunk_off) = rva_to_offset(thunk_rva, sections) {
            let step = if is_64 { 8 } else { 4 };
            for _ in 0..16384 {
                if thunk_off + step > bytes.len() {
                    break;
                }

                let entry = if is_64 {
                    read_u64(bytes, thunk_off, Endian::Little).unwrap_or(0)
                } else {
                    read_u32(bytes, thunk_off, Endian::Little).unwrap_or(0) as u64
                };

                if entry == 0 {
                    break;
                }

                let by_ordinal = if is_64 {
                    (entry & 0x8000_0000_0000_0000) != 0
                } else {
                    (entry & 0x8000_0000) != 0
                };

                let symbol = if by_ordinal {
                    format!("ordinal_{}", entry & 0xFFFF)
                } else {
                    let hint_name_rva = entry as u32;
                    rva_to_offset(hint_name_rva, sections)
                        .and_then(|off| null_terminated(bytes, off + 2))
                        .unwrap_or("<unknown>")
                        .to_string()
                };

                imports.push(ImportInfo {
                    library: library.clone(),
                    symbol,
                });

                thunk_off += step;
            }
        }

        desc_off += 20;
    }
}

fn parse_exports(
    bytes: &[u8],
    sections: &[PeSection],
    export_rva: u32,
    exports: &mut Vec<ExportInfo>,
) {
    let Some(exp_off) = rva_to_offset(export_rva, sections) else {
        return;
    };
    if exp_off + 40 > bytes.len() {
        return;
    }

    let num_functions = read_u32(bytes, exp_off + 20, Endian::Little).unwrap_or(0);
    let num_names = read_u32(bytes, exp_off + 24, Endian::Little).unwrap_or(0);
    let addr_funcs = read_u32(bytes, exp_off + 28, Endian::Little).unwrap_or(0);
    let addr_names = read_u32(bytes, exp_off + 32, Endian::Little).unwrap_or(0);
    let addr_ordinals = read_u32(bytes, exp_off + 36, Endian::Little).unwrap_or(0);

    let Some(funcs_off) = rva_to_offset(addr_funcs, sections) else {
        return;
    };
    let Some(names_off) = rva_to_offset(addr_names, sections) else {
        return;
    };
    let Some(ord_off) = rva_to_offset(addr_ordinals, sections) else {
        return;
    };

    let max_names = num_names.min(20_000);
    for i in 0..max_names {
        let name_rva = read_u32(bytes, names_off + (i as usize) * 4, Endian::Little).unwrap_or(0);
        let Some(name_off) = rva_to_offset(name_rva, sections) else {
            continue;
        };
        let Some(name) = null_terminated(bytes, name_off) else {
            continue;
        };

        let ordinal_index =
            read_u16(bytes, ord_off + (i as usize) * 2, Endian::Little).unwrap_or(0) as u32;
        if ordinal_index >= num_functions {
            continue;
        }

        let func_rva = read_u32(
            bytes,
            funcs_off + (ordinal_index as usize) * 4,
            Endian::Little,
        )
        .unwrap_or(0);
        exports.push(ExportInfo {
            symbol: name.to_string(),
            addr: Some(func_rva as u64),
        });
    }
}

fn parse_coff_symbols(
    bytes: &[u8],
    ptr_symtab: usize,
    num_symbols: usize,
    sections: &[PeSection],
    symbols: &mut Vec<SymbolInfo>,
) {
    if ptr_symtab == 0 || num_symbols == 0 {
        return;
    }

    let string_table_off = ptr_symtab.saturating_add(num_symbols.saturating_mul(18));
    let string_table_len = read_u32(bytes, string_table_off, Endian::Little)
        .unwrap_or(0)
        .max(4) as usize;
    let strtab = bytes
        .get(string_table_off..string_table_off.saturating_add(string_table_len))
        .unwrap_or(&[]);

    let mut i = 0usize;
    while i < num_symbols && i < 40_000 {
        let off = ptr_symtab.saturating_add(i.saturating_mul(18));
        if off + 18 > bytes.len() {
            break;
        }

        let name = if read_u32(bytes, off, Endian::Little).unwrap_or(0) == 0 {
            let strx = read_u32(bytes, off + 4, Endian::Little).unwrap_or(0) as usize;
            if strx >= 4 && strx < strtab.len() {
                null_terminated(strtab, strx)
                    .unwrap_or("<unnamed>")
                    .to_string()
            } else {
                "<unnamed>".to_string()
            }
        } else {
            fixed_cstr(slice(bytes, off, 8).unwrap_or_default())
        };

        let value = read_u32(bytes, off + 8, Endian::Little).unwrap_or(0) as u64;
        let section_number = read_u16(bytes, off + 12, Endian::Little).unwrap_or(0) as i16;
        let storage_class = bytes.get(off + 16).copied().unwrap_or(0);
        let aux = bytes.get(off + 17).copied().unwrap_or(0) as usize;

        let addr = if section_number > 0 {
            let idx = (section_number as usize).saturating_sub(1);
            sections
                .get(idx)
                .map(|s| u64::from(s.virtual_address).saturating_add(value))
        } else {
            Some(value)
        };

        symbols.push(SymbolInfo {
            name,
            addr,
            kind: coff_symbol_kind(storage_class).to_string(),
        });

        i = i.saturating_add(1 + aux);
    }
}

fn coff_symbol_kind(storage_class: u8) -> &'static str {
    match storage_class {
        2 => "external",
        3 => "static",
        101 => "function",
        103 => "file",
        _ => "other",
    }
}

fn pe_machine_name(machine: u16) -> &'static str {
    match machine {
        0x014C => "x86",
        0x8664 => "x86_64",
        0x01C0 => "arm",
        0xAA64 => "arm64",
        0x0200 => "ia64",
        _ => "unknown",
    }
}

fn pe_flag_strings(characteristics: u32) -> Vec<String> {
    let mut out = Vec::new();
    if characteristics & 0x20 != 0 {
        out.push("code".to_string());
    }
    if characteristics & 0x40 != 0 {
        out.push("initialized_data".to_string());
    }
    if characteristics & 0x80 != 0 {
        out.push("uninitialized_data".to_string());
    }
    if characteristics & 0x2000_0000 != 0 {
        out.push("execute".to_string());
    }
    if characteristics & 0x4000_0000 != 0 {
        out.push("read".to_string());
    }
    if characteristics & 0x8000_0000 != 0 {
        out.push("write".to_string());
    }
    out.push(format!("pe:0x{characteristics:08x}"));
    out
}
