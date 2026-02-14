use anyhow::{Result, bail};

use crate::model::{BinaryFormat, SectionInfo, SymbolInfo};

use super::ParsedBinary;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Manufacturer {
    Bmw,
    Ford,
    Vw,
    Mercedes,
    Unknown,
}

impl Manufacturer {
    fn as_str(self) -> &'static str {
        match self {
            Manufacturer::Bmw => "bmw",
            Manufacturer::Ford => "ford",
            Manufacturer::Vw => "vw",
            Manufacturer::Mercedes => "mercedes",
            Manufacturer::Unknown => "unknown",
        }
    }

    fn priority(self) -> usize {
        match self {
            Manufacturer::Bmw => 0,
            Manufacturer::Ford => 1,
            Manufacturer::Vw => 2,
            Manufacturer::Mercedes => 3,
            Manufacturer::Unknown => 4,
        }
    }
}

#[derive(Debug, Clone)]
struct Detection {
    manufacturer: Manufacturer,
    score: usize,
    confidence: u8,
    evidence: Vec<String>,
}

#[derive(Clone, Copy)]
struct Profile {
    manufacturer: Manufacturer,
    high_weight: &'static [&'static str],
    med_weight: &'static [&'static str],
    low_weight: &'static [&'static str],
}

const PROFILES: [Profile; 4] = [
    Profile {
        manufacturer: Manufacturer::Bmw,
        high_weight: &[
            "bmw", "mini", "mevd", "msd8", "msd81", "msv", "dde", "egs", "cafd", "swfl", "btld",
            "hwel", "f-series", "g-series",
        ],
        med_weight: &[
            "bosch", "mg1", "md1", "edc17c", "med17", "asam", "fxx", "gxx", "alpina",
        ],
        low_weight: &["xdrive", "m3", "m4", "x5", "x6", "b58", "n55", "n57"],
    },
    Profile {
        manufacturer: Manufacturer::Ford,
        high_weight: &[
            "ford",
            "fomoco",
            "lincoln",
            "mustang",
            "f150",
            "powerstroke",
            "ecoboost",
        ],
        med_weight: &[
            "sid",
            "pcm",
            "tcm",
            "delphi",
            "continental",
            "dcm",
            "transit",
            "ranger",
        ],
        low_weight: &["focus", "fiesta", "mondeo", "kuga", "explorer"],
    },
    Profile {
        manufacturer: Manufacturer::Vw,
        high_weight: &[
            "vw",
            "vag",
            "volkswagen",
            "audi",
            "skoda",
            "seat",
            "simos",
            "dsg",
            "dq250",
            "dq381",
        ],
        med_weight: &[
            "med17", "edc17", "cp14", "cp20", "cp34", "cp44", "mdg1", "ea888", "ea189", "ea288",
        ],
        low_weight: &["golf", "passat", "octavia", "leon", "rs3", "gti"],
    },
    Profile {
        manufacturer: Manufacturer::Mercedes,
        high_weight: &[
            "mercedes", "benz", "daimler", "amg", "sprinter", "cdi", "om651", "om642",
        ],
        med_weight: &[
            "crd", "med17", "edc17", "cpc", "me", "tcu", "7g", "9g", "delphi",
        ],
        low_weight: &["w204", "w205", "w212", "w213", "xentry"],
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegionKind {
    Padding,
    Ascii,
    Calibration,
    Code,
    Data,
}

impl RegionKind {
    fn label(self) -> &'static str {
        match self {
            RegionKind::Padding => "padding",
            RegionKind::Ascii => "ascii",
            RegionKind::Calibration => "cal",
            RegionKind::Code => "code",
            RegionKind::Data => "data",
        }
    }

    fn flags(self) -> Vec<String> {
        match self {
            RegionKind::Padding => vec!["padding".to_string()],
            RegionKind::Ascii => vec!["ascii_data".to_string()],
            RegionKind::Calibration => vec!["possible_calibration".to_string()],
            RegionKind::Code => vec!["possible_code".to_string()],
            RegionKind::Data => Vec::new(),
        }
    }
}

pub fn parse_unknown(bytes: &[u8]) -> Result<ParsedBinary> {
    if bytes.is_empty() {
        bail!("empty input");
    }

    let tokens = extract_ascii_tokens(bytes, 2, 8192);
    if !looks_like_ecu_or_obd(bytes, &tokens) {
        bail!("input does not look like an ECU/OBD binary");
    }

    let detection = detect_manufacturer(&tokens);
    let cpu = detect_cpu_family(bytes, &tokens, detection.manufacturer);
    let entrypoint = detect_entrypoint(bytes, cpu);
    let sections = build_sections(bytes);

    if sections.is_empty() {
        bail!("failed to segment ECU/OBD binary");
    }

    let mut symbols = Vec::new();
    add_detection_symbols(&detection, &mut symbols);
    add_ecu_family_symbols(&tokens, &mut symbols);
    add_obd_marker_symbols(&tokens, &mut symbols);
    add_calibration_id_symbols(&tokens, &mut symbols);
    add_dtc_symbols(&tokens, &mut symbols);
    add_vin_symbols(&tokens, &mut symbols);

    symbols.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.addr.cmp(&b.addr))
    });
    symbols.dedup_by(|a, b| a.name == b.name && a.kind == b.kind && a.addr == b.addr);

    Ok(ParsedBinary {
        format: BinaryFormat::Unknown,
        arch: format!(
            "ecu_obd/{cpu}; oem={}; confidence={}%%",
            detection.manufacturer.as_str(),
            detection.confidence
        ),
        entrypoint,
        is_stripped: true,
        has_debug: false,
        sections,
        imports: Vec::new(),
        exports: Vec::new(),
        symbols,
        codesign: None,
    })
}

fn looks_like_ecu_or_obd(bytes: &[u8], tokens: &[(usize, String)]) -> bool {
    if bytes.len() < 1024 {
        return false;
    }

    let padding = padding_ratio(bytes);
    let ascii = ascii_ratio(bytes);

    let token_markers = [
        "ecu",
        "obd",
        "uds",
        "can",
        "cal",
        "calibration",
        "swfl",
        "btld",
        "hwel",
        "asap2",
        "asam",
        "checksum",
        "flash",
        "bosch",
        "continental",
        "delphi",
        "denso",
        "edc",
        "med",
        "simos",
        "mg1",
        "md1",
    ];

    let lower_tokens: Vec<String> = tokens
        .iter()
        .map(|(_, token)| token.to_ascii_lowercase())
        .collect();

    let has_marker = token_markers
        .iter()
        .any(|marker| lower_tokens.iter().any(|token| token.contains(marker)));

    has_marker
        || (bytes.len() >= 16 * 1024 && padding >= 0.08)
        || (bytes.len() >= 64 * 1024 && ascii <= 0.90)
}

fn detect_manufacturer(tokens: &[(usize, String)]) -> Detection {
    let lower_tokens: Vec<String> = tokens
        .iter()
        .map(|(_, token)| token.to_ascii_lowercase())
        .collect();

    let mut scored: Vec<(Manufacturer, usize, Vec<String>)> = Vec::with_capacity(PROFILES.len());

    for profile in PROFILES {
        let mut score = 0usize;
        let mut evidence = Vec::new();

        for kw in profile.high_weight {
            if lower_tokens.iter().any(|t| t.contains(kw)) {
                score += 12;
                evidence.push((*kw).to_string());
            }
        }
        for kw in profile.med_weight {
            if lower_tokens.iter().any(|t| t.contains(kw)) {
                score += 5;
                evidence.push((*kw).to_string());
            }
        }
        for kw in profile.low_weight {
            if lower_tokens.iter().any(|t| t.contains(kw)) {
                score += 2;
                evidence.push((*kw).to_string());
            }
        }

        scored.push((profile.manufacturer, score, evidence));
    }

    scored.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| a.0.priority().cmp(&b.0.priority()))
    });

    let Some((winner, top_score, top_evidence)) = scored.first() else {
        return Detection {
            manufacturer: Manufacturer::Unknown,
            score: 0,
            confidence: 0,
            evidence: Vec::new(),
        };
    };

    if *top_score == 0 {
        return Detection {
            manufacturer: Manufacturer::Unknown,
            score: 0,
            confidence: 0,
            evidence: Vec::new(),
        };
    }

    let second = scored.get(1).map(|s| s.1).unwrap_or(0);
    let margin = top_score.saturating_sub(second);
    let mut confidence = (top_score.saturating_mul(3)).min(90) as u8;
    confidence = confidence
        .saturating_add((margin.min(10) * 2) as u8)
        .min(99);

    Detection {
        manufacturer: *winner,
        score: *top_score,
        confidence,
        evidence: top_evidence.iter().take(12).cloned().collect(),
    }
}

fn detect_cpu_family(
    bytes: &[u8],
    tokens: &[(usize, String)],
    manufacturer: Manufacturer,
) -> &'static str {
    let lower_tokens: Vec<String> = tokens
        .iter()
        .map(|(_, token)| token.to_ascii_lowercase())
        .collect();

    if lower_tokens.iter().any(|t| {
        t.contains("tricore")
            || t.contains("tc17")
            || t.contains("tc176")
            || t.contains("tc179")
            || t.contains("tc27")
            || t.contains("tc29")
    }) {
        return "tricore?";
    }

    if lower_tokens
        .iter()
        .any(|t| t.contains("ppc") || t.contains("powerpc"))
        || bytes.windows(4).any(|w| w == [0x7C, 0x08, 0x02, 0xA6])
    {
        return "ppc32/ppc64?";
    }

    if looks_like_arm_vector_table(bytes)
        || bytes.windows(4).any(|w| w == [0x2D, 0xE9, 0xF0, 0x41])
        || bytes.windows(4).any(|w| w == [0xFD, 0x7B, 0xBF, 0xA9])
    {
        return "arm32/arm64?";
    }

    if matches!(manufacturer, Manufacturer::Bmw | Manufacturer::Vw)
        && lower_tokens.iter().any(|t| {
            t.contains("edc17")
                || t.contains("med17")
                || t.contains("mg1")
                || t.contains("md1")
                || t.contains("mevd")
        })
    {
        return "tricore?";
    }

    "unknown_cpu"
}

fn detect_entrypoint(bytes: &[u8], cpu: &str) -> Option<u64> {
    if !cpu.starts_with("arm") || bytes.len() < 8 {
        return None;
    }

    let reset = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if reset == 0 || reset == u32::MAX {
        None
    } else {
        Some(u64::from(reset))
    }
}

fn looks_like_arm_vector_table(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }

    let sp = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let rv = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    (0x2000_0000..=0x4000_0000).contains(&sp) && rv != 0
}

fn build_sections(bytes: &[u8]) -> Vec<SectionInfo> {
    let window = window_size(bytes.len());
    if window == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut start = 0usize;
    let mut current = classify_window(&bytes[..bytes.len().min(window)]);
    let mut cursor = window;

    while cursor < bytes.len() {
        let end = bytes.len().min(cursor.saturating_add(window));
        let next = classify_window(&bytes[cursor..end]);
        if next != current {
            push_section(&mut out, start, cursor, current);
            start = cursor;
            current = next;
        }
        cursor = end;
    }

    push_section(&mut out, start, bytes.len(), current);
    out
}

fn window_size(len: usize) -> usize {
    const K64: usize = 64 * 1024;
    const K512: usize = 512 * 1024;

    if len == 0 {
        0
    } else if len <= K64 {
        2048
    } else if len <= K512 {
        4096
    } else {
        8192
    }
}

fn push_section(out: &mut Vec<SectionInfo>, start: usize, end: usize, kind: RegionKind) {
    if end <= start {
        return;
    }

    let idx = out.len();
    out.push(SectionInfo {
        name: format!("ecu_{}_{idx:03}", kind.label()),
        addr: None,
        offset: start as u64,
        size: (end - start) as u64,
        flags: kind.flags(),
        entropy: None,
    });
}

fn classify_window(window: &[u8]) -> RegionKind {
    let len = window.len().max(1) as f64;
    let pad_ratio = padding_ratio(window);
    let ascii = ascii_ratio(window);

    let mut smooth = 0usize;
    for pair in window.windows(2) {
        let a = pair[0] as i16;
        let b = pair[1] as i16;
        if (a - b).abs() <= 2 {
            smooth += 1;
        }
    }
    let smooth_ratio = if window.len() <= 1 {
        0.0
    } else {
        smooth as f64 / (window.len() - 1) as f64
    };

    let opcode_hits = window
        .iter()
        .filter(|b| {
            matches!(
                **b,
                0x55 | 0x48 | 0x89 | 0xE8 | 0xE9 | 0xC3 | 0x90 | 0xB5 | 0xBD | 0xA6 | 0x7C
            )
        })
        .count() as f64;
    let opcode_ratio = opcode_hits / len;

    if pad_ratio >= 0.90 {
        RegionKind::Padding
    } else if ascii >= 0.72 {
        RegionKind::Ascii
    } else if smooth_ratio >= 0.80 && ascii < 0.35 {
        RegionKind::Calibration
    } else if opcode_ratio >= 0.10 {
        RegionKind::Code
    } else {
        RegionKind::Data
    }
}

fn padding_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let count = bytes.iter().filter(|b| **b == 0 || **b == 0xFF).count();
    count as f64 / bytes.len() as f64
}

fn ascii_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let count = bytes
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    count as f64 / bytes.len() as f64
}

fn add_detection_symbols(det: &Detection, symbols: &mut Vec<SymbolInfo>) {
    symbols.push(SymbolInfo {
        name: format!("oem:{}", det.manufacturer.as_str()),
        addr: None,
        kind: format!("ecu_oem_score_{}", det.score),
    });

    symbols.push(SymbolInfo {
        name: format!("oem_confidence:{}", det.confidence),
        addr: None,
        kind: "ecu_oem_confidence".to_string(),
    });

    for ev in &det.evidence {
        symbols.push(SymbolInfo {
            name: format!("oem_evidence:{ev}"),
            addr: None,
            kind: "ecu_oem_evidence".to_string(),
        });
    }
}

fn add_ecu_family_symbols(tokens: &[(usize, String)], symbols: &mut Vec<SymbolInfo>) {
    const FAMILIES: &[&str] = &[
        "edc15", "edc16", "edc17", "med17", "mevd", "msd", "msv", "dde", "mg1", "md1", "simos",
        "dsg", "dq250", "dq381", "pcm", "tcm", "crd", "cpc",
    ];

    let mut seen = 0usize;
    for (offset, token) in tokens {
        if seen >= 96 {
            break;
        }
        let lower = token.to_ascii_lowercase();
        if FAMILIES.iter().any(|f| lower.contains(f)) {
            symbols.push(SymbolInfo {
                name: format!("ecu_family:{token}"),
                addr: Some(*offset as u64),
                kind: "ecu_family_hint".to_string(),
            });
            seen += 1;
        }
    }
}

fn add_obd_marker_symbols(tokens: &[(usize, String)], symbols: &mut Vec<SymbolInfo>) {
    const MARKERS: &[&str] = &["obd", "uds", "kwp", "can", "swfl", "btld", "hwel", "cafd"];

    let mut seen = 0usize;
    for (offset, token) in tokens {
        if seen >= 96 {
            break;
        }
        let lower = token.to_ascii_lowercase();
        if MARKERS.iter().any(|m| lower.contains(m)) {
            symbols.push(SymbolInfo {
                name: format!("obd_marker:{token}"),
                addr: Some(*offset as u64),
                kind: "obd_marker_hint".to_string(),
            });
            seen += 1;
        }
    }
}

fn add_calibration_id_symbols(tokens: &[(usize, String)], symbols: &mut Vec<SymbolInfo>) {
    let mut seen = 0usize;
    for (offset, token) in tokens {
        if seen >= 192 || !looks_like_cal_id(token) {
            continue;
        }
        symbols.push(SymbolInfo {
            name: format!("cal_id:{token}"),
            addr: Some(*offset as u64),
            kind: "ecu_calibration_id".to_string(),
        });
        seen += 1;
    }
}

fn looks_like_cal_id(token: &str) -> bool {
    let len = token.len();
    if !(6..=24).contains(&len) {
        return false;
    }

    let mut letters = 0usize;
    let mut digits = 0usize;
    for ch in token.chars() {
        if ch.is_ascii_alphabetic() {
            letters += 1;
        } else if ch.is_ascii_digit() {
            digits += 1;
        } else if !matches!(ch, '_' | '-' | '.') {
            return false;
        }
    }

    letters >= 1 && digits >= 3
}

fn add_dtc_symbols(tokens: &[(usize, String)], symbols: &mut Vec<SymbolInfo>) {
    let mut seen = 0usize;
    for (offset, token) in tokens {
        if seen >= 64 || !looks_like_dtc(token) {
            continue;
        }
        symbols.push(SymbolInfo {
            name: format!("dtc:{token}"),
            addr: Some(*offset as u64),
            kind: "obd_dtc_hint".to_string(),
        });
        seen += 1;
    }
}

fn looks_like_dtc(token: &str) -> bool {
    if token.len() != 5 {
        return false;
    }
    let bytes = token.as_bytes();
    matches!(
        bytes[0],
        b'P' | b'B' | b'C' | b'U' | b'p' | b'b' | b'c' | b'u'
    ) && bytes[1..].iter().all(u8::is_ascii_digit)
}

fn add_vin_symbols(tokens: &[(usize, String)], symbols: &mut Vec<SymbolInfo>) {
    let mut seen = 0usize;
    for (offset, token) in tokens {
        if seen >= 16 || !looks_like_vin(token) {
            continue;
        }
        symbols.push(SymbolInfo {
            name: format!("vin_hint:{token}"),
            addr: Some(*offset as u64),
            kind: "obd_vin_hint".to_string(),
        });
        seen += 1;
    }
}

fn looks_like_vin(token: &str) -> bool {
    if token.len() != 17 {
        return false;
    }
    token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() && !matches!(c, 'I' | 'O' | 'Q' | 'i' | 'o' | 'q'))
}

fn extract_ascii_tokens(bytes: &[u8], min_len: usize, max_tokens: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx < bytes.len() && out.len() < max_tokens {
        if !is_token_char(bytes[idx]) {
            idx += 1;
            continue;
        }

        let start = idx;
        while idx < bytes.len() && is_token_char(bytes[idx]) {
            idx += 1;
        }

        let len = idx - start;
        if len < min_len || len > 128 {
            continue;
        }

        out.push((
            start,
            String::from_utf8_lossy(&bytes[start..idx]).to_string(),
        ));
    }

    out
}

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'\\')
}
