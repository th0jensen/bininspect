#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

pub fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> Option<u16> {
    let src = bytes.get(offset..offset.checked_add(2)?)?;
    let arr = [src[0], src[1]];
    Some(match endian {
        Endian::Little => u16::from_le_bytes(arr),
        Endian::Big => u16::from_be_bytes(arr),
    })
}

pub fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    let src = bytes.get(offset..offset.checked_add(4)?)?;
    let arr = [src[0], src[1], src[2], src[3]];
    Some(match endian {
        Endian::Little => u32::from_le_bytes(arr),
        Endian::Big => u32::from_be_bytes(arr),
    })
}

pub fn read_u64(bytes: &[u8], offset: usize, endian: Endian) -> Option<u64> {
    let src = bytes.get(offset..offset.checked_add(8)?)?;
    let arr = [
        src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
    ];
    Some(match endian {
        Endian::Little => u64::from_le_bytes(arr),
        Endian::Big => u64::from_be_bytes(arr),
    })
}

pub fn slice(bytes: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(size)?)
}

pub fn null_terminated(bytes: &[u8], offset: usize) -> Option<&str> {
    let tail = bytes.get(offset..)?;
    let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
    std::str::from_utf8(&tail[..end]).ok()
}

pub fn fixed_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
