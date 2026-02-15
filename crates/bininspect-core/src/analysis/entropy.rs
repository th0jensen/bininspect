use crate::model::SectionInfo;

pub fn apply_section_entropy(bytes: &[u8], sections: &mut [SectionInfo]) {
    for sec in sections {
        if sec.size == 0 {
            sec.entropy = Some(0.0);
            continue;
        }

        let start = sec.offset as usize;
        let requested = sec.size as usize;
        if start >= bytes.len() {
            sec.entropy = None;
            continue;
        }

        // Bound costly entropy computation for very large ranges.
        let cap = requested.min(4 * 1024 * 1024);
        let end = start.saturating_add(cap).min(bytes.len());
        if end <= start {
            sec.entropy = None;
            continue;
        }

        let ent = shannon_entropy(&bytes[start..end]);
        sec.entropy = Some((ent * 1000.0).round() / 1000.0);
    }
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for b in data {
        counts[*b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}
