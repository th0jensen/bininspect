use crate::model::StringInfo;

pub fn extract_strings(
    bytes: &[u8],
    min_len: usize,
    max_results: usize,
    max_len: usize,
) -> Vec<StringInfo> {
    let mut out = Vec::new();
    let mut start = None;

    for (idx, b) in bytes.iter().enumerate() {
        if is_printable(*b) {
            if start.is_none() {
                start = Some(idx);
            }
            continue;
        }

        if let Some(s) = start.take() {
            push_if_string(bytes, s, idx, min_len, max_len, max_results, &mut out);
            if out.len() >= max_results {
                return out;
            }
        }
    }

    if let Some(s) = start {
        push_if_string(
            bytes,
            s,
            bytes.len(),
            min_len,
            max_len,
            max_results,
            &mut out,
        );
    }

    out
}

fn push_if_string(
    bytes: &[u8],
    start: usize,
    end: usize,
    min_len: usize,
    max_len: usize,
    max_results: usize,
    out: &mut Vec<StringInfo>,
) {
    if out.len() >= max_results {
        return;
    }

    let len = end.saturating_sub(start);
    if len < min_len {
        return;
    }

    let capped_end = start.saturating_add(len.min(max_len));
    let Some(slice) = bytes.get(start..capped_end) else {
        return;
    };

    let text = String::from_utf8_lossy(slice).trim().to_string();
    if text.len() >= min_len {
        out.push(StringInfo {
            offset: start as u64,
            value: text,
        });
    }
}

fn is_printable(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e | b'\t')
}
