#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    MachO,
    MachOFat,
    Elf,
    Pe,
    Wasm,
    Unknown,
}

pub fn detect_format(bytes: &[u8]) -> DetectedFormat {
    if bytes.len() < 4 {
        return DetectedFormat::Unknown;
    }

    match &bytes[..4] {
        [0xCF, 0xFA, 0xED, 0xFE]
        | [0xCE, 0xFA, 0xED, 0xFE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xFE, 0xED, 0xFA, 0xCE] => return DetectedFormat::MachO,
        [0xCA, 0xFE, 0xBA, 0xBE]
        | [0xBE, 0xBA, 0xFE, 0xCA]
        | [0xCA, 0xFE, 0xBA, 0xBF]
        | [0xBF, 0xBA, 0xFE, 0xCA] => return DetectedFormat::MachOFat,
        [0x7F, b'E', b'L', b'F'] => return DetectedFormat::Elf,
        [0x00, b'a', b's', b'm'] => {
            if bytes.len() >= 8 && bytes[4..8] == [0x01, 0x00, 0x00, 0x00] {
                return DetectedFormat::Wasm;
            }
        }
        [b'M', b'Z', ..] => {
            if bytes.len() >= 0x40 {
                let pe_off =
                    u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]])
                        as usize;
                if bytes
                    .get(pe_off..pe_off.saturating_add(4))
                    .is_some_and(|sig| sig == b"PE\0\0")
                {
                    return DetectedFormat::Pe;
                }
            }
        }
        _ => {}
    }

    DetectedFormat::Unknown
}
