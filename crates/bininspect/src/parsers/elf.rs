use anyhow::{Result, bail};

use crate::model::{BinaryFormat, ExportInfo, ImportInfo, SectionInfo, SymbolInfo};
use crate::parsers::ParsedBinary;
use crate::util::{Endian, read_u16, read_u32, read_u64};

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;

const SHN_UNDEF: u16 = 0;
const DT_NEEDED: i64 = 1;

#[derive(Debug, Clone)]
struct ElfSection {
    name_idx: u32,
    name: String,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

pub fn parse_elf(bytes: &[u8]) -> Result<ParsedBinary> {
    if bytes.len() < 0x34 {
        bail!("truncated ELF header");
    }
    if bytes[..4] != [0x7F, b'E', b'L', b'F'] {
        bail!("invalid ELF magic");
    }

    let class = bytes[4];
    let endian = match bytes[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        _ => bail!("unsupported ELF endianness"),
    };

    let is_64 = match class {
        1 => false,
        2 => true,
        _ => bail!("unsupported ELF class"),
    };

    let e_machine = read_u16(bytes, 18, endian).unwrap_or(0);
    let entrypoint = if is_64 {
        read_u64(bytes, 24, endian)
    } else {
        read_u32(bytes, 24, endian).map(u64::from)
    };

    let shoff = if is_64 {
        read_u64(bytes, 40, endian).unwrap_or(0)
    } else {
        read_u32(bytes, 32, endian).unwrap_or(0) as u64
    };
    let shentsize = if is_64 {
        read_u16(bytes, 58, endian).unwrap_or(0)
    } else {
        read_u16(bytes, 46, endian).unwrap_or(0)
    } as usize;
    let shnum = if is_64 {
        read_u16(bytes, 60, endian).unwrap_or(0)
    } else {
        read_u16(bytes, 48, endian).unwrap_or(0)
    } as usize;
    let shstrndx = if is_64 {
        read_u16(bytes, 62, endian).unwrap_or(0)
    } else {
        read_u16(bytes, 50, endian).unwrap_or(0)
    } as usize;

    let sections_raw = parse_sections(bytes, shoff as usize, shentsize, shnum, is_64, endian)?;

    let shstrtab = if shstrndx < sections_raw.len() {
        let s = &sections_raw[shstrndx];
        section_slice(bytes, s)
    } else {
        None
    };

    let mut sections = sections_raw;
    for sec in &mut sections {
        sec.name = shstrtab
            .and_then(|tab| str_from_table(tab, sec.name_idx as usize))
            .unwrap_or_else(|| "<unnamed>".to_string());
    }

    let mut out_sections = Vec::with_capacity(sections.len());
    let mut has_debug = false;
    let mut has_symtab = false;
    for sec in &sections {
        if sec.sh_type == SHT_SYMTAB {
            has_symtab = true;
        }
        let lname = sec.name.to_ascii_lowercase();
        if lname.starts_with(".debug") || lname.starts_with(".zdebug") || lname.contains(".dwarf") {
            has_debug = true;
        }

        out_sections.push(SectionInfo {
            name: sec.name.clone(),
            addr: Some(sec.addr),
            offset: sec.offset,
            size: sec.size,
            flags: elf_flag_strings(sec.flags),
            entropy: None,
        });
    }

    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut symbols = Vec::new();

    parse_dynamic_needed(bytes, &sections, is_64, endian, &mut imports);
    parse_symbols(
        bytes,
        &sections,
        is_64,
        endian,
        &mut imports,
        &mut exports,
        &mut symbols,
    );

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
        format: BinaryFormat::Elf,
        arch: elf_machine_name(e_machine).to_string(),
        entrypoint,
        is_stripped: !has_symtab,
        has_debug,
        sections: out_sections,
        imports,
        exports,
        symbols,
        codesign: None,
    })
}

fn parse_sections(
    bytes: &[u8],
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    is_64: bool,
    endian: Endian,
) -> Result<Vec<ElfSection>> {
    if shentsize == 0 {
        return Ok(Vec::new());
    }

    let need = if is_64 { 64 } else { 40 };
    if shentsize < need {
        bail!("invalid ELF section header entry size");
    }

    let mut sections = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let off = shoff.saturating_add(i.saturating_mul(shentsize));
        if off + shentsize > bytes.len() {
            break;
        }

        let sec = if is_64 {
            ElfSection {
                name_idx: read_u32(bytes, off, endian).unwrap_or(0),
                name: String::new(),
                sh_type: read_u32(bytes, off + 4, endian).unwrap_or(0),
                flags: read_u64(bytes, off + 8, endian).unwrap_or(0),
                addr: read_u64(bytes, off + 16, endian).unwrap_or(0),
                offset: read_u64(bytes, off + 24, endian).unwrap_or(0),
                size: read_u64(bytes, off + 32, endian).unwrap_or(0),
                link: read_u32(bytes, off + 40, endian).unwrap_or(0),
                entsize: read_u64(bytes, off + 56, endian).unwrap_or(0),
            }
        } else {
            ElfSection {
                name_idx: read_u32(bytes, off, endian).unwrap_or(0),
                name: String::new(),
                sh_type: read_u32(bytes, off + 4, endian).unwrap_or(0),
                flags: read_u32(bytes, off + 8, endian).unwrap_or(0) as u64,
                addr: read_u32(bytes, off + 12, endian).unwrap_or(0) as u64,
                offset: read_u32(bytes, off + 16, endian).unwrap_or(0) as u64,
                size: read_u32(bytes, off + 20, endian).unwrap_or(0) as u64,
                link: read_u32(bytes, off + 24, endian).unwrap_or(0),
                entsize: read_u32(bytes, off + 36, endian).unwrap_or(0) as u64,
            }
        };

        sections.push(sec);
    }

    Ok(sections)
}

fn section_slice<'a>(bytes: &'a [u8], sec: &ElfSection) -> Option<&'a [u8]> {
    let off = sec.offset as usize;
    let size = sec.size as usize;
    bytes.get(off..off.saturating_add(size))
}

fn str_from_table(table: &[u8], idx: usize) -> Option<String> {
    if idx >= table.len() {
        return None;
    }
    let tail = &table[idx..];
    let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
    let name = std::str::from_utf8(&tail[..end]).ok()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn parse_symbols(
    bytes: &[u8],
    sections: &[ElfSection],
    is_64: bool,
    endian: Endian,
    imports: &mut Vec<ImportInfo>,
    exports: &mut Vec<ExportInfo>,
    symbols: &mut Vec<SymbolInfo>,
) {
    for sec in sections {
        if sec.sh_type != SHT_SYMTAB && sec.sh_type != SHT_DYNSYM {
            continue;
        }
        if sec.entsize == 0 {
            continue;
        }

        let Some(sym_data) = section_slice(bytes, sec) else {
            continue;
        };

        let strtab = sections.get(sec.link as usize).and_then(|s| {
            if s.sh_type == SHT_STRTAB {
                section_slice(bytes, s)
            } else {
                None
            }
        });
        let Some(strtab_data) = strtab else {
            continue;
        };

        let entsize = sec.entsize as usize;
        let min_size = if is_64 { 24 } else { 16 };
        if entsize < min_size {
            continue;
        }

        let mut count = sym_data.len() / entsize;
        if count > 25_000 {
            count = 25_000;
        }

        for i in 0..count {
            let base = i * entsize;
            if base + entsize > sym_data.len() {
                break;
            }

            let (name_idx, info, shndx, value) = if is_64 {
                (
                    read_u32(sym_data, base, endian).unwrap_or(0) as usize,
                    sym_data.get(base + 4).copied().unwrap_or(0),
                    read_u16(sym_data, base + 6, endian).unwrap_or(0),
                    read_u64(sym_data, base + 8, endian).unwrap_or(0),
                )
            } else {
                (
                    read_u32(sym_data, base, endian).unwrap_or(0) as usize,
                    sym_data.get(base + 12).copied().unwrap_or(0),
                    read_u16(sym_data, base + 14, endian).unwrap_or(0),
                    read_u32(sym_data, base + 4, endian).unwrap_or(0) as u64,
                )
            };

            let Some(name) = str_from_table(strtab_data, name_idx) else {
                continue;
            };

            let bind = info >> 4;
            let st_type = info & 0x0F;

            if shndx == SHN_UNDEF && bind > 0 {
                imports.push(ImportInfo {
                    library: None,
                    symbol: name.clone(),
                });
            } else if shndx != SHN_UNDEF && bind > 0 {
                exports.push(ExportInfo {
                    symbol: name.clone(),
                    addr: Some(value),
                });
            }

            symbols.push(SymbolInfo {
                name,
                addr: Some(value),
                kind: elf_symbol_kind(st_type).to_string(),
            });

            if symbols.len() >= 20_000 {
                return;
            }
        }
    }
}

fn parse_dynamic_needed(
    bytes: &[u8],
    sections: &[ElfSection],
    is_64: bool,
    endian: Endian,
    imports: &mut Vec<ImportInfo>,
) {
    for sec in sections {
        if sec.sh_type != SHT_DYNAMIC {
            continue;
        }

        let Some(dyn_data) = section_slice(bytes, sec) else {
            continue;
        };

        let strtab = sections.get(sec.link as usize).and_then(|s| {
            if s.sh_type == SHT_STRTAB {
                section_slice(bytes, s)
            } else {
                None
            }
        });
        let Some(strtab_data) = strtab else {
            continue;
        };

        let entsize = if sec.entsize == 0 {
            if is_64 { 16 } else { 8 }
        } else {
            sec.entsize as usize
        };

        let min_size = if is_64 { 16 } else { 8 };
        if entsize < min_size {
            continue;
        }

        let count = dyn_data.len() / entsize;
        for i in 0..count.min(8192) {
            let base = i * entsize;
            let (tag, val) = if is_64 {
                (
                    read_u64(dyn_data, base, endian).unwrap_or(0) as i64,
                    read_u64(dyn_data, base + 8, endian).unwrap_or(0),
                )
            } else {
                (
                    read_u32(dyn_data, base, endian).unwrap_or(0) as i32 as i64,
                    read_u32(dyn_data, base + 4, endian).unwrap_or(0) as u64,
                )
            };

            if tag == DT_NEEDED
                && let Some(lib) = str_from_table(strtab_data, val as usize)
            {
                imports.push(ImportInfo {
                    library: Some(lib),
                    symbol: "*".to_string(),
                });
            }
        }
    }
}

fn elf_machine_name(machine: u16) -> &'static str {
    match machine {
        3 => "x86",
        8 => "mips",
        40 => "arm",
        62 => "x86_64",
        183 => "aarch64",
        243 => "riscv",
        _ => "unknown",
    }
}

fn elf_flag_strings(flags: u64) -> Vec<String> {
    let mut out = Vec::new();
    if flags & 0x1 != 0 {
        out.push("write".to_string());
    }
    if flags & 0x2 != 0 {
        out.push("alloc".to_string());
    }
    if flags & 0x4 != 0 {
        out.push("execute".to_string());
    }
    out.push(format!("elf:0x{flags:x}"));
    out
}

fn elf_symbol_kind(kind: u8) -> &'static str {
    match kind {
        0 => "notype",
        1 => "object",
        2 => "func",
        3 => "section",
        4 => "file",
        5 => "common",
        6 => "tls",
        _ => "other",
    }
}
