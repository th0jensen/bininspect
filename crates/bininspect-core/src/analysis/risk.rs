use crate::model::{
    BinaryFormat, CodeSignInfo, Finding, ImportInfo, SectionInfo, Severity, StringInfo,
};

pub fn build_findings(
    format: BinaryFormat,
    sections: &[SectionInfo],
    imports: &[ImportInfo],
    strings: &[StringInfo],
    codesign: Option<&CodeSignInfo>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if format == BinaryFormat::MachO {
        add_codesign_findings(codesign, &mut findings);
    }

    add_rwx_findings(sections, &mut findings);
    add_entropy_findings(sections, &mut findings);
    add_import_findings(imports, &mut findings);
    add_string_indicator_findings(strings, &mut findings);
    add_weird_section_findings(sections, &mut findings);

    findings.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| a.title.cmp(&b.title))
    });

    findings
}

fn add_codesign_findings(codesign: Option<&CodeSignInfo>, findings: &mut Vec<Finding>) {
    let Some(cs) = codesign else {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "No code signature data".to_string(),
            details: "Mach-O file does not include a parsable LC_CODE_SIGNATURE blob.".to_string(),
            evidence: Vec::new(),
        });
        return;
    };

    if !cs.present {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "Unsigned Mach-O (no embedded signature blob)".to_string(),
            details: "No LC_CODE_SIGNATURE data was found; integrity and signer metadata are unavailable.".to_string(),
            evidence: Vec::new(),
        });
        return;
    }

    if !cs.has_cms_signature {
        findings.push(Finding {
            severity: Severity::Low,
            title: "Ad-hoc or detached signature".to_string(),
            details: "CodeDirectory exists but CMS signature slot is missing (common for ad-hoc signing).".to_string(),
            evidence: cs
                .identifier
                .as_ref()
                .map_or_else(Vec::new, |id| vec![format!("identifier={id}")]),
        });
    }

    if matches!(cs.code_directory_hashes_verified, Some(false)) {
        findings.push(Finding {
            severity: Severity::High,
            title: "CodeDirectory page hash mismatch".to_string(),
            details: "At least one signed page hash does not match file contents.".to_string(),
            evidence: cs
                .mismatch_pages
                .iter()
                .take(8)
                .map(|p| format!("page {p}"))
                .collect(),
        });
    }
}

fn add_rwx_findings(sections: &[SectionInfo], findings: &mut Vec<Finding>) {
    let rwx_sections: Vec<String> = sections
        .iter()
        .filter(|s| {
            let mut has_write = false;
            let mut has_exec = false;
            for flag in &s.flags {
                let f = flag.to_ascii_lowercase();
                if f.contains("write") {
                    has_write = true;
                }
                if f.contains("exec") {
                    has_exec = true;
                }
            }
            has_write && has_exec
        })
        .map(|s| s.name.clone())
        .take(10)
        .collect();

    if !rwx_sections.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            title: "Writable + executable section(s)".to_string(),
            details: "Sections that are both writable and executable can be abused for runtime code injection.".to_string(),
            evidence: rwx_sections,
        });
    }
}

fn add_entropy_findings(sections: &[SectionInfo], findings: &mut Vec<Finding>) {
    let mut high = Vec::new();
    let mut very_high = Vec::new();

    for s in sections {
        let Some(ent) = s.entropy else {
            continue;
        };
        if ent >= 7.7 {
            very_high.push(format!("{} ({ent:.3})", s.name));
        } else if ent >= 7.2 {
            high.push(format!("{} ({ent:.3})", s.name));
        }
    }

    if !very_high.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            title: "Very high entropy section(s)".to_string(),
            details: "Very high entropy can indicate packed, encrypted, or compressed payloads."
                .to_string(),
            evidence: very_high.into_iter().take(10).collect(),
        });
    }

    if !high.is_empty() {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "High entropy section(s)".to_string(),
            details: "Elevated entropy may indicate compressed or obfuscated data.".to_string(),
            evidence: high.into_iter().take(10).collect(),
        });
    }
}

fn add_import_findings(imports: &[ImportInfo], findings: &mut Vec<Finding>) {
    const SUSPICIOUS: &[&str] = &[
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "ntunmapviewofsection",
        "loadlibrary",
        "getprocaddress",
        "winexec",
        "createprocess",
        "shellexecute",
        "mprotect",
        "ptrace",
        "dlopen",
        "dlsym",
        "execve",
        "system",
        "fork",
    ];

    let mut hits = Vec::new();
    for imp in imports {
        let sym = imp.symbol.to_ascii_lowercase();
        if SUSPICIOUS.iter().any(|needle| sym.contains(needle)) {
            if let Some(lib) = &imp.library {
                hits.push(format!("{lib}!{}", imp.symbol));
            } else {
                hits.push(imp.symbol.clone());
            }
        }
        if hits.len() >= 16 {
            break;
        }
    }

    if !hits.is_empty() {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "Suspicious import patterns".to_string(),
            details: "Imports include APIs often seen in process injection, dynamic loading, or shell execution flows.".to_string(),
            evidence: hits,
        });
    }
}

fn add_string_indicator_findings(strings: &[StringInfo], findings: &mut Vec<Finding>) {
    let mut urls = Vec::new();
    let mut ips = Vec::new();

    for s in strings {
        let value = s.value.trim();
        if value.contains("http://") || value.contains("https://") {
            urls.push(value.to_string());
        }

        for token in value.split(|c: char| !c.is_ascii_alphanumeric() && c != '.') {
            if looks_like_ipv4(token) {
                ips.push(token.to_string());
            }
        }

        if urls.len() >= 10 && ips.len() >= 10 {
            break;
        }
    }

    if !urls.is_empty() {
        findings.push(Finding {
            severity: Severity::Low,
            title: "Embedded URL indicators".to_string(),
            details: "The binary contains URL-like strings that may indicate network behavior."
                .to_string(),
            evidence: urls.into_iter().take(10).collect(),
        });
    }

    if !ips.is_empty() {
        ips.sort();
        ips.dedup();
        findings.push(Finding {
            severity: Severity::Low,
            title: "Embedded IPv4 indicators".to_string(),
            details: "The binary contains IPv4-like string literals.".to_string(),
            evidence: ips.into_iter().take(10).collect(),
        });
    }
}

fn add_weird_section_findings(sections: &[SectionInfo], findings: &mut Vec<Finding>) {
    let mut weird = Vec::new();

    for s in sections {
        let name = s.name.trim();
        let lname = name.to_ascii_lowercase();

        let suspicious_label = lname.contains("upx")
            || lname.contains("packed")
            || lname.contains("vmp")
            || lname.contains("enigma")
            || lname.contains("crypt")
            || lname.contains("obfus");

        let odd_shape = name.len() > 28
            || name
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '$')));

        if suspicious_label || odd_shape {
            weird.push(name.to_string());
        }

        if weird.len() >= 10 {
            break;
        }
    }

    if !weird.is_empty() {
        findings.push(Finding {
            severity: Severity::Low,
            title: "Unusual section naming".to_string(),
            details: "One or more section names look uncommon for standard compiler/linker output."
                .to_string(),
            evidence: weird,
        });
    }
}

fn looks_like_ipv4(token: &str) -> bool {
    if token.is_empty() || token.len() > 15 {
        return false;
    }

    let mut parts = token.split('.');
    let mut count = 0;
    for part in parts.by_ref() {
        if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        let Ok(num) = part.parse::<u16>() else {
            return false;
        };
        if num > 255 {
            return false;
        }

        count += 1;
    }

    count == 4
}

fn severity_rank(sev: Severity) -> u8 {
    match sev {
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
    }
}
