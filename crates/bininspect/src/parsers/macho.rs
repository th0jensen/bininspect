use anyhow::{Result, bail};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::model::{BinaryFormat, CodeSignInfo, ExportInfo, ImportInfo, SectionInfo, SymbolInfo};
use crate::parsers::ParsedBinary;
use crate::util::{Endian, fixed_cstr, hex_lower, null_terminated, read_u32, read_u64, slice};

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
const LC_SEGMENT_64: u32 = 0x19;
const LC_REEXPORT_DYLIB: u32 = 0x1f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23;
const LC_MAIN: u32 = 0x28;
const LC_LOAD_DYLINKER: u32 = 0xe;
const LC_CODE_SIGNATURE: u32 = 0x1d;

const MH_MAGIC: &[u8; 4] = &[0xFE, 0xED, 0xFA, 0xCE];
const MH_CIGAM: &[u8; 4] = &[0xCE, 0xFA, 0xED, 0xFE];
const MH_MAGIC_64: &[u8; 4] = &[0xFE, 0xED, 0xFA, 0xCF];
const MH_CIGAM_64: &[u8; 4] = &[0xCF, 0xFA, 0xED, 0xFE];

const FAT_MAGIC: &[u8; 4] = &[0xCA, 0xFE, 0xBA, 0xBE];
const FAT_CIGAM: &[u8; 4] = &[0xBE, 0xBA, 0xFE, 0xCA];
const FAT_MAGIC_64: &[u8; 4] = &[0xCA, 0xFE, 0xBA, 0xBF];
const FAT_CIGAM_64: &[u8; 4] = &[0xBF, 0xBA, 0xFE, 0xCA];

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE0CC0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xFADE0C02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xFADE7171;
const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xFADE7172;

const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_ENTITLEMENTS: u32 = 5;
const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
const CSSLOT_CMS_SIGNATURE: u32 = 0x10000;

const N_STAB: u8 = 0xE0;
const N_TYPE: u8 = 0x0E;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x00;
const N_SECT: u8 = 0x0E;

#[derive(Debug, Clone, Copy)]
struct MachLayout {
    endian: Endian,
    is_64: bool,
}

#[derive(Debug, Clone, Copy)]
struct SymtabCmd {
    symoff: usize,
    nsyms: usize,
    stroff: usize,
    strsize: usize,
}

#[derive(Debug, Default)]
struct SymtabOutput {
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
    symbols: Vec<SymbolInfo>,
    has_debug: bool,
}

pub fn parse_macho(bytes: &[u8]) -> Result<ParsedBinary> {
    let (slice_bytes, fat_arches) = if is_fat_magic(bytes) {
        select_fat_slice(bytes)?
    } else {
        (bytes, None)
    };

    let mut parsed = parse_single_macho(slice_bytes)?;

    if let Some(arches) = fat_arches {
        parsed.arch = format!("universal ({arches}); primary {}", parsed.arch);
    }

    Ok(parsed)
}

fn parse_single_macho(bytes: &[u8]) -> Result<ParsedBinary> {
    let layout = macho_layout(bytes).ok_or_else(|| anyhow::anyhow!("invalid Mach-O magic"))?;
    let header_size = if layout.is_64 { 32 } else { 28 };

    if bytes.len() < header_size {
        bail!("truncated Mach-O header");
    }

    let cputype =
        read_u32(bytes, 4, layout.endian).ok_or_else(|| anyhow::anyhow!("missing cputype"))?;
    let ncmds = read_u32(bytes, 16, layout.endian)
        .ok_or_else(|| anyhow::anyhow!("missing ncmds"))? as usize;
    let mut cmd_off = header_size;

    let mut sections = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut symbols = Vec::new();
    let mut dylibs = Vec::new();
    let mut symtab_cmd = None;
    let mut entrypoint = None;
    let mut has_debug = false;
    let mut codesign_lc = None;

    for _ in 0..ncmds {
        if cmd_off + 8 > bytes.len() {
            break;
        }

        let cmd = read_u32(bytes, cmd_off, layout.endian).unwrap_or(0);
        let cmdsize = read_u32(bytes, cmd_off + 4, layout.endian).unwrap_or(0) as usize;
        if cmdsize < 8 || cmd_off + cmdsize > bytes.len() {
            break;
        }

        let base_cmd = cmd & 0x7FFF_FFFF;

        if (layout.is_64 && base_cmd == LC_SEGMENT_64) || (!layout.is_64 && base_cmd == LC_SEGMENT)
        {
            parse_segment(
                bytes,
                cmd_off,
                cmdsize,
                layout,
                &mut sections,
                &mut has_debug,
            );
        } else if base_cmd == LC_SYMTAB {
            symtab_cmd = parse_symtab_cmd(bytes, cmd_off, layout.endian);
        } else if base_cmd == LC_MAIN {
            entrypoint = read_u64(bytes, cmd_off + 8, layout.endian);
        } else if base_cmd == LC_UNIXTHREAD {
            // Thread-state parsing differs by CPU flavor; LC_MAIN is preferred when present.
        } else if matches!(
            base_cmd,
            LC_LOAD_DYLIB
                | LC_LOAD_WEAK_DYLIB
                | LC_REEXPORT_DYLIB
                | LC_LAZY_LOAD_DYLIB
                | LC_LOAD_UPWARD_DYLIB
                | LC_LOAD_DYLINKER
        ) {
            if let Some(name) = parse_load_name(bytes, cmd_off, cmdsize, layout.endian) {
                dylibs.push(name);
            }
        } else if base_cmd == LC_CODE_SIGNATURE {
            let dataoff = read_u32(bytes, cmd_off + 8, layout.endian).unwrap_or(0) as usize;
            let datasize = read_u32(bytes, cmd_off + 12, layout.endian).unwrap_or(0) as usize;
            codesign_lc = Some((dataoff, datasize));
        }

        cmd_off += cmdsize;
    }

    if let Some(symtab) = symtab_cmd {
        let mut sym = parse_symtab(bytes, symtab, layout);
        imports.append(&mut sym.imports);
        exports.append(&mut sym.exports);
        symbols.append(&mut sym.symbols);
        has_debug |= sym.has_debug;
    }

    let codesign = if let Some((off, size)) = codesign_lc {
        Some(parse_codesign(bytes, off, size))
    } else {
        Some(empty_codesign(false))
    };

    for section in &sections {
        let lower = section.name.to_ascii_lowercase();
        if lower.contains("debug") {
            has_debug = true;
        }
    }

    // Keep only deterministic, de-duplicated outputs.
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

    let is_stripped = symtab_cmd.is_none_or(|cmd| cmd.nsyms == 0);

    Ok(ParsedBinary {
        format: BinaryFormat::MachO,
        arch: cpu_type_name(cputype).to_string(),
        entrypoint,
        is_stripped,
        has_debug,
        sections,
        imports,
        exports,
        symbols,
        codesign,
    })
}

fn is_fat_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (bytes[0..4] == FAT_MAGIC[..]
            || bytes[0..4] == FAT_CIGAM[..]
            || bytes[0..4] == FAT_MAGIC_64[..]
            || bytes[0..4] == FAT_CIGAM_64[..])
}

fn select_fat_slice(bytes: &[u8]) -> Result<(&[u8], Option<String>)> {
    if bytes.len() < 8 {
        bail!("truncated fat Mach-O header");
    }

    let head = &bytes[..4];
    let (endian, is_64) = if head == FAT_MAGIC {
        (Endian::Big, false)
    } else if head == FAT_CIGAM {
        (Endian::Little, false)
    } else if head == FAT_MAGIC_64 {
        (Endian::Big, true)
    } else if head == FAT_CIGAM_64 {
        (Endian::Little, true)
    } else {
        bail!("invalid fat Mach-O magic");
    };

    let nfat_arch =
        read_u32(bytes, 4, endian).ok_or_else(|| anyhow::anyhow!("missing nfat_arch"))? as usize;
    let arch_size = if is_64 { 32 } else { 20 };
    let arch_table_end = 8usize
        .checked_add(nfat_arch.saturating_mul(arch_size))
        .ok_or_else(|| anyhow::anyhow!("fat header overflow"))?;
    if arch_table_end > bytes.len() {
        bail!("truncated fat architecture table");
    }

    let mut arch_labels = Vec::new();
    let mut selected = None;

    for idx in 0..nfat_arch {
        let base = 8 + idx * arch_size;
        let cputype = read_u32(bytes, base, endian).unwrap_or(0);
        let (offset, size) = if is_64 {
            let off = read_u64(bytes, base + 8, endian).unwrap_or(0);
            let len = read_u64(bytes, base + 16, endian).unwrap_or(0);
            (off as usize, len as usize)
        } else {
            let off = read_u32(bytes, base + 8, endian).unwrap_or(0);
            let len = read_u32(bytes, base + 12, endian).unwrap_or(0);
            (off as usize, len as usize)
        };

        arch_labels.push(cpu_type_name(cputype).to_string());

        if selected.is_none()
            && offset < bytes.len()
            && size > 4
            && offset + size <= bytes.len()
            && macho_layout(&bytes[offset..offset + size]).is_some()
        {
            selected = Some((offset, size));
        }
    }

    if selected.is_none() && nfat_arch > 0 {
        let base = 8;
        let (offset, size) = if is_64 {
            (
                read_u64(bytes, base + 8, endian).unwrap_or(0) as usize,
                read_u64(bytes, base + 16, endian).unwrap_or(0) as usize,
            )
        } else {
            (
                read_u32(bytes, base + 8, endian).unwrap_or(0) as usize,
                read_u32(bytes, base + 12, endian).unwrap_or(0) as usize,
            )
        };
        if offset < bytes.len() && offset + size <= bytes.len() {
            selected = Some((offset, size));
        }
    }

    let (offset, size) = selected.ok_or_else(|| {
        anyhow::anyhow!("fat Mach-O did not contain a readable architecture slice")
    })?;
    let slice = bytes
        .get(offset..offset + size)
        .ok_or_else(|| anyhow::anyhow!("selected fat slice out of bounds"))?;

    let summary = if arch_labels.is_empty() {
        None
    } else {
        Some(arch_labels.join(", "))
    };

    Ok((slice, summary))
}

fn macho_layout(bytes: &[u8]) -> Option<MachLayout> {
    if bytes.len() < 4 {
        return None;
    }

    let head = &bytes[..4];
    let layout = if head == MH_MAGIC {
        MachLayout {
            endian: Endian::Big,
            is_64: false,
        }
    } else if head == MH_CIGAM {
        MachLayout {
            endian: Endian::Little,
            is_64: false,
        }
    } else if head == MH_MAGIC_64 {
        MachLayout {
            endian: Endian::Big,
            is_64: true,
        }
    } else if head == MH_CIGAM_64 {
        MachLayout {
            endian: Endian::Little,
            is_64: true,
        }
    } else {
        return None;
    };

    Some(layout)
}

fn parse_segment(
    bytes: &[u8],
    cmd_off: usize,
    cmd_size: usize,
    layout: MachLayout,
    sections: &mut Vec<SectionInfo>,
    has_debug: &mut bool,
) {
    if layout.is_64 {
        if cmd_size < 72 {
            return;
        }

        let initprot = read_u32(bytes, cmd_off + 60, layout.endian).unwrap_or(0);
        let nsects = read_u32(bytes, cmd_off + 64, layout.endian).unwrap_or(0) as usize;
        let mut sec_off = cmd_off + 72;

        for _ in 0..nsects {
            if sec_off + 80 > cmd_off + cmd_size || sec_off + 80 > bytes.len() {
                break;
            }

            let sectname = fixed_cstr(slice(bytes, sec_off, 16).unwrap_or_default());
            let segname = fixed_cstr(slice(bytes, sec_off + 16, 16).unwrap_or_default());
            let addr = read_u64(bytes, sec_off + 32, layout.endian).unwrap_or(0);
            let size = read_u64(bytes, sec_off + 40, layout.endian).unwrap_or(0);
            let offset = read_u32(bytes, sec_off + 48, layout.endian).unwrap_or(0) as u64;
            let sec_flags = read_u32(bytes, sec_off + 64, layout.endian).unwrap_or(0);

            let name = format_section_name(&segname, &sectname);
            if name.to_ascii_lowercase().contains("debug") {
                *has_debug = true;
            }

            sections.push(SectionInfo {
                name,
                addr: Some(addr),
                offset,
                size,
                flags: macho_flag_strings(initprot, sec_flags),
                entropy: None,
            });

            sec_off += 80;
        }
    } else {
        if cmd_size < 56 {
            return;
        }

        let initprot = read_u32(bytes, cmd_off + 44, layout.endian).unwrap_or(0);
        let nsects = read_u32(bytes, cmd_off + 48, layout.endian).unwrap_or(0) as usize;
        let mut sec_off = cmd_off + 56;

        for _ in 0..nsects {
            if sec_off + 68 > cmd_off + cmd_size || sec_off + 68 > bytes.len() {
                break;
            }

            let sectname = fixed_cstr(slice(bytes, sec_off, 16).unwrap_or_default());
            let segname = fixed_cstr(slice(bytes, sec_off + 16, 16).unwrap_or_default());
            let addr = read_u32(bytes, sec_off + 32, layout.endian).unwrap_or(0) as u64;
            let size = read_u32(bytes, sec_off + 36, layout.endian).unwrap_or(0) as u64;
            let offset = read_u32(bytes, sec_off + 40, layout.endian).unwrap_or(0) as u64;
            let sec_flags = read_u32(bytes, sec_off + 56, layout.endian).unwrap_or(0);

            let name = format_section_name(&segname, &sectname);
            if name.to_ascii_lowercase().contains("debug") {
                *has_debug = true;
            }

            sections.push(SectionInfo {
                name,
                addr: Some(addr),
                offset,
                size,
                flags: macho_flag_strings(initprot, sec_flags),
                entropy: None,
            });

            sec_off += 68;
        }
    }
}

fn parse_load_name(
    bytes: &[u8],
    cmd_off: usize,
    cmd_size: usize,
    endian: Endian,
) -> Option<String> {
    let name_off = read_u32(bytes, cmd_off + 8, endian)? as usize;
    if name_off >= cmd_size {
        return None;
    }
    let name = null_terminated(bytes, cmd_off + name_off)?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn parse_symtab_cmd(bytes: &[u8], cmd_off: usize, endian: Endian) -> Option<SymtabCmd> {
    Some(SymtabCmd {
        symoff: read_u32(bytes, cmd_off + 8, endian)? as usize,
        nsyms: read_u32(bytes, cmd_off + 12, endian)? as usize,
        stroff: read_u32(bytes, cmd_off + 16, endian)? as usize,
        strsize: read_u32(bytes, cmd_off + 20, endian)? as usize,
    })
}

fn parse_symtab(bytes: &[u8], cmd: SymtabCmd, layout: MachLayout) -> SymtabOutput {
    let mut out = SymtabOutput::default();

    let strtab = match bytes.get(cmd.stroff..cmd.stroff.saturating_add(cmd.strsize)) {
        Some(data) => data,
        None => return out,
    };

    let entry_size = if layout.is_64 { 16 } else { 12 };
    for i in 0..cmd.nsyms {
        let entry_off = cmd.symoff.saturating_add(i.saturating_mul(entry_size));
        if entry_off + entry_size > bytes.len() {
            break;
        }

        let strx = read_u32(bytes, entry_off, layout.endian).unwrap_or(0) as usize;
        let n_type = bytes.get(entry_off + 4).copied().unwrap_or(0);
        let n_value = if layout.is_64 {
            read_u64(bytes, entry_off + 8, layout.endian).unwrap_or(0)
        } else {
            read_u32(bytes, entry_off + 8, layout.endian).unwrap_or(0) as u64
        };

        let name = read_strtab_name(strtab, strx).unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        let is_debug = (n_type & N_STAB) != 0;
        if is_debug {
            out.has_debug = true;
        }

        let n_basic = n_type & N_TYPE;
        let ext = (n_type & N_EXT) != 0;

        if ext && n_basic == N_UNDF {
            out.imports.push(ImportInfo {
                library: None,
                symbol: name.clone(),
            });
        } else if ext && n_basic == N_SECT {
            out.exports.push(ExportInfo {
                symbol: name.clone(),
                addr: Some(n_value),
            });
        }

        let kind = if is_debug {
            "debug"
        } else if n_basic == N_UNDF {
            "undefined"
        } else if n_basic == N_SECT {
            "section"
        } else {
            "other"
        };

        out.symbols.push(SymbolInfo {
            name,
            addr: Some(n_value),
            kind: kind.to_string(),
        });

        if out.symbols.len() >= 10_000 {
            break;
        }
    }

    out
}

fn read_strtab_name(strtab: &[u8], strx: usize) -> Option<String> {
    if strx == 0 || strx >= strtab.len() {
        return None;
    }
    let tail = &strtab[strx..];
    let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
    let name = std::str::from_utf8(&tail[..end]).ok()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn format_section_name(segname: &str, sectname: &str) -> String {
    match (segname.is_empty(), sectname.is_empty()) {
        (false, false) => format!("{segname}.{sectname}"),
        (false, true) => segname.to_string(),
        (true, false) => sectname.to_string(),
        (true, true) => "<unnamed>".to_string(),
    }
}

fn macho_flag_strings(initprot: u32, sec_flags: u32) -> Vec<String> {
    let mut out = Vec::new();
    if initprot & 0x1 != 0 {
        out.push("read".to_string());
    }
    if initprot & 0x2 != 0 {
        out.push("write".to_string());
    }
    if initprot & 0x4 != 0 {
        out.push("execute".to_string());
    }

    if sec_flags & 0x8000_0000 != 0 {
        out.push("pure_instructions".to_string());
    }
    if sec_flags & 0x0000_0400 != 0 {
        out.push("some_instructions".to_string());
    }
    out.push(format!("macho:0x{sec_flags:08x}"));
    out
}

fn parse_codesign(file: &[u8], offset: usize, size: usize) -> CodeSignInfo {
    let Some(blob) = file.get(offset..offset.saturating_add(size)) else {
        return empty_codesign(true);
    };

    if blob.len() < 8 {
        return empty_codesign(true);
    }

    let magic = read_u32(blob, 0, Endian::Big).unwrap_or(0);
    if magic == CSMAGIC_CODEDIRECTORY {
        let mut info = empty_codesign(true);
        parse_code_directory(blob, file, &mut info);
        return info;
    }

    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        return empty_codesign(true);
    }

    let mut info = empty_codesign(true);
    let sb_len = read_u32(blob, 4, Endian::Big).unwrap_or(blob.len() as u32) as usize;
    let superblob = &blob[..sb_len.min(blob.len())];
    let count = read_u32(superblob, 8, Endian::Big).unwrap_or(0) as usize;

    let mut code_directory: Option<&[u8]> = None;

    for i in 0..count {
        let idx_off = 12 + i * 8;
        if idx_off + 8 > superblob.len() {
            break;
        }

        let slot_type = read_u32(superblob, idx_off, Endian::Big).unwrap_or(0);
        let slot_off = read_u32(superblob, idx_off + 4, Endian::Big).unwrap_or(0) as usize;
        if slot_off + 8 > superblob.len() {
            continue;
        }

        let child_len = read_u32(superblob, slot_off + 4, Endian::Big).unwrap_or(0) as usize;
        let child_end =
            slot_off.saturating_add(child_len.min(superblob.len().saturating_sub(slot_off)));
        let Some(child) = superblob.get(slot_off..child_end) else {
            continue;
        };

        let child_magic = read_u32(child, 0, Endian::Big).unwrap_or(0);

        if slot_type == CSSLOT_CMS_SIGNATURE {
            info.has_cms_signature = true;
        }

        if slot_type == CSSLOT_ENTITLEMENTS || slot_type == CSSLOT_DER_ENTITLEMENTS {
            info.entitlements = parse_entitlements_blob(child);
        }

        if slot_type == CSSLOT_CODEDIRECTORY
            || (code_directory.is_none() && child_magic == CSMAGIC_CODEDIRECTORY)
        {
            code_directory = Some(child);
        }
    }

    if let Some(cd) = code_directory {
        parse_code_directory(cd, file, &mut info);
    }

    info
}

fn parse_entitlements_blob(blob: &[u8]) -> Option<String> {
    if blob.len() < 8 {
        return None;
    }
    let magic = read_u32(blob, 0, Endian::Big)?;
    if magic != CSMAGIC_EMBEDDED_ENTITLEMENTS && magic != CSMAGIC_EMBEDDED_DER_ENTITLEMENTS {
        return None;
    }

    if magic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS {
        return Some("<DER entitlements blob present>".to_string());
    }

    let len = read_u32(blob, 4, Endian::Big)? as usize;
    if len <= 8 || len > blob.len() {
        return None;
    }

    let payload = &blob[8..len];
    let text = std::str::from_utf8(payload).ok()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn parse_code_directory(code_dir_blob: &[u8], file: &[u8], info: &mut CodeSignInfo) {
    if code_dir_blob.len() < 44 {
        return;
    }

    let cd_len =
        read_u32(code_dir_blob, 4, Endian::Big).unwrap_or(code_dir_blob.len() as u32) as usize;
    let code_dir = &code_dir_blob[..cd_len.min(code_dir_blob.len())];

    let version = read_u32(code_dir, 8, Endian::Big).unwrap_or(0);
    let flags = read_u32(code_dir, 12, Endian::Big).unwrap_or(0);
    let hash_offset = read_u32(code_dir, 16, Endian::Big).unwrap_or(0) as usize;
    let ident_offset = read_u32(code_dir, 20, Endian::Big).unwrap_or(0) as usize;
    let n_special_slots = read_u32(code_dir, 24, Endian::Big).unwrap_or(0) as usize;
    let n_code_slots = read_u32(code_dir, 28, Endian::Big).unwrap_or(0) as usize;
    let mut code_limit = read_u32(code_dir, 32, Endian::Big).unwrap_or(0) as u64;
    let hash_size = code_dir.get(36).copied().unwrap_or(0) as usize;
    let hash_type = code_dir.get(37).copied().unwrap_or(0);
    let page_size_log = code_dir.get(39).copied().unwrap_or(0);

    if version >= 0x20400 {
        let limit64 = read_u64(code_dir, 56, Endian::Big).unwrap_or(0);
        if limit64 > 0 {
            code_limit = limit64;
        }
    }

    info.flags = Some(flags);
    info.code_limit = Some(code_limit);
    info.page_size = u32::checked_shl(1, page_size_log as u32);
    info.hash_type = Some(hash_type_name(hash_type).to_string());

    if ident_offset < code_dir.len() {
        info.identifier = null_terminated(code_dir, ident_offset).map(str::to_string);
    }

    if let Some(cd_digest) = compute_hash(hash_type, code_dir) {
        let end = cd_digest.len().min(20);
        info.cdhash = Some(hex_lower(&cd_digest[..end]));
    }

    if hash_size == 0 {
        return;
    }

    let page_size = 1usize.checked_shl(page_size_log as u32).unwrap_or(0);
    if page_size == 0 {
        return;
    }

    let mut verified = 0u32;
    let mut mismatches = Vec::new();
    let mut checked_any = false;

    for i in 0..n_code_slots {
        let slot_off = hash_offset.saturating_add((n_special_slots + i).saturating_mul(hash_size));
        if slot_off + hash_size > code_dir.len() {
            break;
        }

        let code_start = i.saturating_mul(page_size);
        if code_start as u64 >= code_limit {
            break;
        }

        let code_end = ((i + 1).saturating_mul(page_size))
            .min(code_limit as usize)
            .min(file.len());
        if code_end <= code_start || code_start >= file.len() {
            continue;
        }

        let expected = &code_dir[slot_off..slot_off + hash_size];
        let data = &file[code_start..code_end];
        let Some(actual_full) = compute_hash(hash_type, data) else {
            continue;
        };

        let cmp_len = hash_size.min(actual_full.len());
        checked_any = true;
        if expected[..cmp_len] == actual_full[..cmp_len] {
            verified += 1;
        } else if mismatches.len() < 32 {
            mismatches.push(i as u32);
        }
    }

    info.total_pages = Some(n_code_slots as u32);
    info.verified_pages = Some(verified);
    info.mismatch_pages = mismatches;
    if checked_any {
        info.code_directory_hashes_verified = Some(info.mismatch_pages.is_empty());
    }
}

fn hash_type_name(hash_type: u8) -> &'static str {
    match hash_type {
        1 => "sha1",
        2 => "sha256",
        3 => "sha256_truncated",
        4 => "sha384",
        5 => "sha512",
        _ => "unknown",
    }
}

fn compute_hash(hash_type: u8, data: &[u8]) -> Option<Vec<u8>> {
    let bytes = match hash_type {
        1 => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        2 | 3 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        4 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        5 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        _ => return None,
    };

    Some(bytes)
}

fn empty_codesign(present: bool) -> CodeSignInfo {
    CodeSignInfo {
        present,
        identifier: None,
        flags: None,
        hash_type: None,
        page_size: None,
        code_limit: None,
        cdhash: None,
        has_cms_signature: false,
        entitlements: None,
        code_directory_hashes_verified: None,
        verified_pages: None,
        total_pages: None,
        mismatch_pages: Vec::new(),
    }
}

fn cpu_type_name(cputype: u32) -> &'static str {
    match cputype {
        7 => "x86",
        12 => "arm",
        18 => "ppc",
        0x0100_0007 => "x86_64",
        0x0100_000C => "arm64",
        0x0200_000C => "arm64e",
        _ => "unknown",
    }
}
