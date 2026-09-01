//! Shared bitfield helpers (mirrors elfbrowser `executor_arm64/helpers.rs`).

#[inline]
pub fn bits(insn: u32, hi: u32, lo: u32) -> u32 {
    (insn >> lo) & ((1 << (hi - lo + 1)) - 1)
}

#[inline]
pub fn bit(insn: u32, pos: u32) -> u32 {
    (insn >> pos) & 1
}

#[inline]
pub fn sign_extend(val: u64, width: u32) -> i64 {
    let shift = 64 - width;
    ((val as i64) << shift) >> shift
}

/// Decode ARM bitmask immediate (logical imm encoding).
pub fn decode_bitmask(sf: bool, n: u32, imms: u32, immr: u32) -> Option<u64> {
    let len = if n == 1 {
        6
    } else {
        let mut len = 0u32;
        for i in (0..5).rev() {
            if ((imms >> i) & 1) == 0 {
                len = i;
                break;
            }
        }
        if len < 1 {
            return None;
        }
        len
    };
    let levels = (1u32 << len) - 1;
    if (imms & levels) == levels {
        return None;
    }
    let s = imms & levels;
    let r = immr & levels;
    let esize = 1u32 << len;
    let mut welem = (1u64 << (s + 1)) - 1;
    if r != 0 {
        let mask = if esize == 64 {
            u64::MAX
        } else {
            (1u64 << esize) - 1
        };
        welem = ((welem >> r) | (welem << (esize - r))) & mask;
    }
    let mut imm = 0u64;
    let mut e = 0u32;
    let width = if sf { 64 } else { 32 };
    while e < width {
        imm |= welem << e;
        e += esize;
    }
    if !sf {
        imm &= 0xFFFF_FFFF;
    }
    Some(imm)
}
