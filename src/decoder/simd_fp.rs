//! SIMD & FP decode (elfbrowser `simd_fp.rs` instruction families).
//! Capstone reference: https://github.com/capstone-engine/capstone/tree/next/arch/AArch64

use crate::enums::{Arrangement, Code, OpKind, Register};
use crate::helpers::{bit, bits};
use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;

use super::undef;

pub(super) fn decode(vaddr: u64, raw: u32) -> Instruction {
    // Advanced SIMD three same (vector)
    if bit(raw, 31) == 0 && bits(raw, 28, 24) == 0b01110 && bit(raw, 21) == 1 && bit(raw, 10) == 1 {
        return decode_three_same(vaddr, raw);
    }
    // Three-same-extra (FCMLA/FCADD/SQRDMLAH/BFDOT): bit21=0, bit15=1
    // Vector: bits[28:24]=01110; scalar: bit30=1 + bits[28:24]=11110
    if bit(raw, 31) == 0
        && bit(raw, 21) == 0
        && bit(raw, 15) == 1
        && bit(raw, 10) == 1
        && (bits(raw, 28, 24) == 0b01110
            || (bit(raw, 30) == 1 && bits(raw, 28, 24) == 0b11110))
    {
        return decode_complex_three_same(vaddr, raw);
    }
    // Advanced SIMD three different (SMULL/SMLAL/PMULL/…)
    if bit(raw, 31) == 0
        && bits(raw, 28, 24) == 0b01110
        && bit(raw, 21) == 1
        && bits(raw, 11, 10) == 0b00
    {
        return decode_three_diff(vaddr, raw);
    }
    // Crypto 3-reg SHA (SHA1C/SHA256H/…) — bits[11:10]=00 (don't steal DUP/MOV)
    if bit(raw, 31) == 0
        && bit(raw, 30) == 1
        && bits(raw, 28, 24) == 0b11110
        && bit(raw, 21) == 0
        && bits(raw, 11, 10) == 0b00
    {
        return decode_crypto_3reg(vaddr, raw);
    }
    // Advanced SIMD scalar two-reg misc (UQXTN, …): bit30=1, bits[28:24]=11110
    if bit(raw, 31) == 0 && bit(raw, 30) == 1 && bits(raw, 28, 24) == 0b11110 && bits(raw, 11, 10) == 0b10 {
        return decode_simd_scalar_two_misc(vaddr, raw);
    }
    // Modified immediate (MOVI/MVNI/…)
    if bit(raw, 31) == 0 && bits(raw, 28, 19) == 0b0111100000 && bit(raw, 10) == 1 {
        return decode_modified_imm(vaddr, raw);
    }
    // Copy (DUP/INS/SMOV/UMOV) — vector and scalar (MOV alias)
    if bit(raw, 31) == 0
        && ((bits(raw, 28, 21) == 0b01110000 && bit(raw, 15) == 0 && bit(raw, 10) == 1)
            || (bit(raw, 30) == 1 && bits(raw, 28, 21) == 0b11110000 && bit(raw, 10) == 1))
    {
        return decode_copy(vaddr, raw);
    }
    // Across lanes (before two-misc — shares bits[21:17]=11000 with FP16 misc)
    if bit(raw, 31) == 0
        && bits(raw, 28, 24) == 0b01110
        && bits(raw, 21, 17) == 0b11000
        && bits(raw, 11, 10) == 0b10
        && matches!(
            bits(raw, 16, 12),
            0b00011 | 0b01010 | 0b01100 | 0b01111 | 0b11010 | 0b11011
        )
    {
        return decode_across(vaddr, raw);
    }
    // Two-reg misc (FP16: 11000, crypto AES: 10100)
    if bit(raw, 31) == 0
        && bits(raw, 28, 24) == 0b01110
        && matches!(bits(raw, 21, 17), 0b10000 | 0b11000 | 0b10100)
        && bits(raw, 11, 10) == 0b10
    {
        return decode_two_misc(vaddr, raw);
    }
    // Shift by immediate (vector + scalar)
    if bit(raw, 31) == 0
        && (bits(raw, 28, 23) == 0b011110 || bits(raw, 28, 23) == 0b111110)
        && bit(raw, 10) == 1
    {
        let immh = bits(raw, 22, 19);
        if immh != 0 {
            return decode_shift_imm(vaddr, raw);
        }
    }
    // By-element (indexed element) — vector (0x0F/0x4F) + scalar (0x5F/0x7F)
    if bit(raw, 31) == 0
        && bit(raw, 10) == 0
        && (bits(raw, 28, 24) == 0b01111
            || (bit(raw, 30) == 1 && bits(raw, 28, 24) == 0b11111))
    {
        return decode_by_element(vaddr, raw);
    }
    // TBL/TBX
    if bit(raw, 31) == 0
        && bits(raw, 29, 24) == 0b001110
        && bit(raw, 21) == 0
        && bit(raw, 15) == 0
        && bits(raw, 11, 10) == 0b00
    {
        return decode_tbl(vaddr, raw);
    }
    // Permute ZIP/UZP/TRN
    if bit(raw, 31) == 0
        && bits(raw, 29, 24) == 0b001110
        && bit(raw, 21) == 0
        && bits(raw, 11, 10) == 0b10
    {
        return decode_permute(vaddr, raw);
    }
    // EXT
    if bit(raw, 31) == 0
        && bits(raw, 29, 24) == 0b101110
        && bit(raw, 21) == 0
        && bit(raw, 15) == 0
        && bit(raw, 10) == 0
    {
        return decode_ext(vaddr, raw);
    }

    // ── Scalar FP 3-source (FMADD/FMSUB/…) ──
    if (raw >> 24) & 0x7F == 0x1F {
        return decode_fp_3src(vaddr, raw);
    }

    // ── Scalar FP (encoding class 0001 1110 / 1001 1110) ──
    let top = raw >> 24;
    if top == 0x1E || top == 0x9E {
        if bit(raw, 21) == 0 {
            if bits(raw, 15, 10) == 0b000000 {
                return decode_fp_conversion(vaddr, raw);
            }
            // Fixed-point conversions (scale in bits[15:10])
            return decode_fp_conversion_fixed(vaddr, raw);
        }
        if bit(raw, 21) == 1 {
            match bits(raw, 11, 10) {
                0b10 => return decode_fp_2src(vaddr, raw),
                0b11 => return decode_fp_csel(vaddr, raw),
                0b01 => return decode_fp_ccmp(vaddr, raw),
                0b00 => {
                    if bits(raw, 14, 10) == 0b10000 {
                        return decode_fp_1src(vaddr, raw);
                    }
                    if bits(raw, 15, 10) == 0b001000 {
                        return decode_fp_compare(vaddr, raw);
                    }
                    if bits(raw, 12, 10) == 0b100 {
                        return decode_fp_imm(vaddr, raw);
                    }
                }
                _ => {}
            }
        }
    }

    // Legacy elfbrowser FP patterns (vector FP in AdvSIMD)
    if bits(raw, 30, 24) == 0b0011110 && bits(raw, 15, 10) == 0b000000 {
        return decode_fp_conversion(vaddr, raw);
    }
    if ((raw >> 24) & 0xFE == 0x5E && bit(raw, 22) == 1 && bits(raw, 12, 10) == 0b010)
        || ((raw >> 24) & 0xEE == 0x4E && bits(raw, 15, 12) >= 8 && bits(raw, 15, 12) <= 11)
    {
        return decode_fp_2src(vaddr, raw);
    }

    undef(vaddr, raw)
}

fn arrangement(q: u32, size: u32) -> Arrangement {
    match (q, size) {
        (0, 0) => Arrangement::B8,
        (1, 0) => Arrangement::B16,
        (0, 1) => Arrangement::H4,
        (1, 1) => Arrangement::H8,
        (0, 2) => Arrangement::S2,
        (1, 2) => Arrangement::S4,
        (0, 3) => Arrangement::D1,
        (1, 3) => Arrangement::D2,
        _ => Arrangement::None,
    }
}

fn decode_three_same(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let u = bit(raw, 29);
    let size = bits(raw, 23, 22);
    let rm = bits(raw, 20, 16);
    let opcode = bits(raw, 15, 11);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);

    let mnemonic = match (u, opcode, size) {
        // Logical (size selects AND/BIC/ORR/ORN / EOR/BSL/BIT/BIF)
        (0, 0b00011, 0b00) => Mnemonic::And,
        (0, 0b00011, 0b01) => Mnemonic::Bic,
        (0, 0b00011, 0b10) if rn == rm => Mnemonic::Mov,
        (0, 0b00011, 0b10) => Mnemonic::Orr,
        (0, 0b00011, 0b11) => Mnemonic::Orn,
        (1, 0b00011, 0b00) => Mnemonic::Eor,
        (1, 0b00011, 0b01) => Mnemonic::Bsl,
        (1, 0b00011, 0b10) => Mnemonic::Bit,
        (1, 0b00011, 0b11) => Mnemonic::Bif,
        // FP16 three-same (precede integer opcodes that share these fields)
        (0, 0b00010, 0b01) => Mnemonic::Fadd,
        (0, 0b00010, 0b11) => Mnemonic::Fsub,
        (1, 0b00010, 0b01) => Mnemonic::Faddp,
        (1, 0b00010, 0b11) => Mnemonic::Fabd,
        (0, 0b00000, 0b01) => Mnemonic::Fmaxnm,
        (0, 0b00000, 0b11) => Mnemonic::Fminnm,
        (0, 0b00110, 0b01) => Mnemonic::Fmax,
        (0, 0b00110, 0b11) => Mnemonic::Fmin,
        (0, 0b00100, 0b01) => Mnemonic::Fcmeq,
        (1, 0b00100, 0b01) => Mnemonic::Fcmge,
        (1, 0b00100, 0b11) => Mnemonic::Fcmgt,
        (1, 0b00111, 0b01) => Mnemonic::Fdiv,
        (0, 0b00001, 0b01) => Mnemonic::Fmla,
        (0, 0b00001, 0b11) => Mnemonic::Fmls,
        // Integer three-same
        (0, 0b10000, _) => Mnemonic::Add,
        (1, 0b10000, _) => Mnemonic::Sub,
        (0, 0b10010, _) => Mnemonic::Mla,
        (1, 0b10010, _) => Mnemonic::Mls,
        (0, 0b10011, _) => Mnemonic::Mul,
        (1, 0b00110, _) => Mnemonic::Cmhi,
        (1, 0b00111, _) => Mnemonic::Cmhs,
        (1, 0b10001, _) => Mnemonic::Cmeq,
        (0, 0b00110, _) => Mnemonic::Cmge,
        (0, 0b00111, _) => Mnemonic::Cmgt,
        (0, 0b01100, _) => Mnemonic::Smax,
        (0, 0b01101, _) => Mnemonic::Smin,
        (1, 0b01100, _) => Mnemonic::Umax,
        (1, 0b01101, _) => Mnemonic::Umin,
        (0, 0b01000, _) => Mnemonic::Sshl,
        (1, 0b01000, _) => Mnemonic::Ushl,
        (0, 0b10111, _) => Mnemonic::Addp,
        // FP32/FP64 three-same (size bit1 selects add↔sub / max↔min / mla↔mls)
        (0, 0b11001, s) if s & 2 == 0 => Mnemonic::Fmla,
        (0, 0b11001, _) => Mnemonic::Fmls,
        (0, 0b11010, s) if s & 2 == 0 => Mnemonic::Fadd,
        (0, 0b11010, _) => Mnemonic::Fsub,
        (1, 0b11010, s) if s & 2 == 0 => Mnemonic::Faddp,
        (1, 0b11010, _) => Mnemonic::Fabd,
        (0, 0b11011, _) => Mnemonic::Fmulx,
        (1, 0b11011, _) => Mnemonic::Fmul,
        (1, 0b11111, _) => Mnemonic::Fdiv,
        (0, 0b11100, _) => Mnemonic::Fcmeq,
        (1, 0b11100, _) => Mnemonic::Fcmge,
        (1, 0b11101, _) => Mnemonic::Fcmgt,
        (0, 0b11110, s) if s & 2 == 0 => Mnemonic::Fmax,
        (0, 0b11110, _) => Mnemonic::Fmin,
        (0, 0b11000, s) if s & 2 == 0 => Mnemonic::Fmaxnm,
        (0, 0b11000, _) => Mnemonic::Fminnm,
        (1, 0b01111, _) => Mnemonic::Fmulx,
        _ => Mnemonic::Undefined,
    };
    if mnemonic == Mnemonic::Undefined {
        return undef(vaddr, raw);
    }
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_three_same, mnemonic);
    i.arrangement = arrangement(q, size);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::v(rm);
    if mnemonic == Mnemonic::Mov {
        i.op_count = 2;
        i.op2_kind = OpKind::None;
    }
    i
}

fn decode_complex_three_same(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let u = bit(raw, 29);
    let size = bits(raw, 23, 22);
    let rm = bits(raw, 20, 16);
    let opcode = bits(raw, 15, 11);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mnemonic = match (u, opcode) {
        (_, 0b11000 | 0b11001 | 0b11010 | 0b11011) => Mnemonic::Fcmla,
        (_, 0b11100 | 0b11110) => Mnemonic::Fcadd,
        (1, 0b10000) => Mnemonic::Sqrdmlah,
        (1, 0b10001) => Mnemonic::Sqrdmlsh,
        (1, 0b11111) if size == 0b01 => Mnemonic::Bfdot,
        (0, 0b10010) => Mnemonic::Sdot,
        (1, 0b10010) => Mnemonic::Udot,
        (0, 0b10011) => Mnemonic::Usdot,
        (1, 0b11101) if size == 0b01 => Mnemonic::Bfmmla,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_three_same, mnemonic);
    i.arrangement = arrangement(q, size);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::v(rm);
    i
}

fn decode_modified_imm(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let op = bit(raw, 29);
    let cmode = bits(raw, 15, 12);
    let o2 = bit(raw, 11);
    let rd = bits(raw, 4, 0);
    let abc = bits(raw, 18, 16);
    let defgh = bits(raw, 9, 5);
    let imm8 = (abc << 5) | defgh;

    let mnemonic = match (op, cmode, o2) {
        // ORR / BIC: cmode = *xx1 (not 111x)
        (0, c, 0) if matches!(c, 0b0001 | 0b0011 | 0b0101 | 0b0111 | 0b1001 | 0b1011) => {
            Mnemonic::Orr
        }
        (1, c, 0) if matches!(c, 0b0001 | 0b0011 | 0b0101 | 0b0111 | 0b1001 | 0b1011) => {
            Mnemonic::Bic
        }
        (0, c, 0)
            if c & 0b1001 == 0b0000
                || c & 0b1001 == 0b0010
                || c & 0b1101 == 0b1000
                || c & 0b1110 == 0b1100 =>
        {
            Mnemonic::Movi
        }
        (1, c, 0) if c & 0b1001 == 0b0000 || c & 0b1001 == 0b0010 || c & 0b1101 == 0b1000 => {
            Mnemonic::Mvni
        }
        (0, 0b1110, 0) => Mnemonic::Movi,
        (0, 0b1111, 0) => Mnemonic::Fmov,
        (1, 0b1110, 0) => Mnemonic::Movi,
        (1, 0b1111, 0) => Mnemonic::Fmov,
        _ => Mnemonic::Movi,
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_modified_imm, mnemonic);
    i.arrangement = if q != 0 {
        Arrangement::B16
    } else {
        Arrangement::B8
    };
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Immediate;
    i.op1_imm = imm8 as u64;
    i
}

fn decode_copy(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let op = bit(raw, 29);
    let imm5 = bits(raw, 20, 16);
    let imm4 = bits(raw, 14, 11);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let scalar = bit(raw, 30) == 1 && bits(raw, 28, 21) == 0b11110000;

    // Capstone aliases many copy forms as `mov`.
    let (mnemonic, to_gpr) = match (op, imm4) {
        (0, 0b0000) if scalar => (Mnemonic::Mov, false),
        (0, 0b0000) => (Mnemonic::Dup, false),
        (0, 0b0001) => (Mnemonic::Dup, false), // general Dup element→vector
        (0, 0b0011) => (Mnemonic::Mov, false), // INS from GPR → mov
        (0, 0b0101) => (Mnemonic::Smov, true),
        (0, 0b0111) => (Mnemonic::Mov, true), // umov → mov
        (1, _) => (Mnemonic::Mov, false),     // ins element → mov
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_copy, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op1_kind = OpKind::Register;
    if to_gpr {
        i.op0_reg = Register::gpr(q != 0 || scalar, rd, false);
        i.op1_reg = Register::v(rn);
    } else if op == 0 && imm4 == 0b0011 {
        // INS (general) — mov Vd.T[i], Rn
        i.op0_reg = Register::v(rd);
        i.op1_reg = Register::gpr(true, rn, false);
    } else if op == 1 {
        i.op0_reg = Register::v(rd);
        i.op1_reg = Register::v(rn);
    } else {
        i.op0_reg = if scalar {
            let size = imm5.trailing_zeros().min(3);
            Register::fp_sized(1 << size, rd)
        } else {
            Register::v(rd)
        };
        i.op1_reg = Register::v(rn);
    }
    i.vector_index = imm5 as u8;
    let _ = imm4;
    i
}

fn decode_two_misc(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let u = bit(raw, 29);
    let size = bits(raw, 23, 22);
    let opcode = bits(raw, 16, 12);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let fp16 = bits(raw, 21, 17) == 0b11000;
    let crypto = bits(raw, 21, 17) == 0b10100;

    let mnemonic = if crypto {
        match (u, opcode) {
            (0, 0b00100) => Mnemonic::Aese,
            (0, 0b00101) => Mnemonic::Aesd,
            (0, 0b00110) => Mnemonic::Aesmc,
            (0, 0b00111) => Mnemonic::Aesimc,
            _ => return undef(vaddr, raw),
        }
    } else if fp16 {
        // Advanced SIMD two-register miscellaneous (half-precision)
        match (u, opcode) {
            (0, 0b01111) => Mnemonic::Fabs,
            (1, 0b01111) => Mnemonic::Fneg,
            (0, 0b11101) => Mnemonic::Frecpe,
            (1, 0b11101) => Mnemonic::Frsqrte,
            (0, 0b11000) => Mnemonic::Frintn,
            (0, 0b11001) => Mnemonic::Frintp,
            (0, 0b11010) => Mnemonic::Frintm,
            (0, 0b11011) => Mnemonic::Frintz,
            (1, 0b11000) => Mnemonic::Frinta,
            (1, 0b11001) => Mnemonic::Frintx,
            (1, 0b11011) => Mnemonic::Frinti,
            (1, 0b11111) => Mnemonic::Fsqrt,
            _ => return undef(vaddr, raw),
        }
    } else {
        match (u, opcode, size) {
            (0, 0b00000, _) => Mnemonic::Rev64,
            (0, 0b00001, _) => Mnemonic::Rev16,
            (0, 0b00010, _) => Mnemonic::Saddlp,
            (1, 0b00010, _) => Mnemonic::Uaddlp,
            (0, 0b00110, _) => Mnemonic::Sadalp,
            (1, 0b00110, _) => Mnemonic::Uadalp,
            (0, 0b00011, _) => Mnemonic::Suqadd,
            (1, 0b00011, _) => Mnemonic::Usqadd,
            (0, 0b00100, _) => Mnemonic::Cls,
            (1, 0b00100, _) => Mnemonic::Clz,
            (0, 0b00101, _) => Mnemonic::Cnt,
            (1, 0b00101, _) => Mnemonic::Mvn, // NOT → Capstone `mvn`
            (0, 0b10010, _) => {
                if q != 0 {
                    Mnemonic::Xtn2
                } else {
                    Mnemonic::Xtn
                }
            }
            (1, 0b10010, _) => {
                if q != 0 {
                    Mnemonic::Sqxtun2
                } else {
                    Mnemonic::Sqxtun
                }
            }
            (0, 0b00111, _) => Mnemonic::Rev32,
            (1, 0b10011, _) => {
                if q != 0 {
                    Mnemonic::Shll2
                } else {
                    Mnemonic::Shll
                }
            }
            (0, 0b01000, _) => Mnemonic::Cmgt, // #0
            (0, 0b01001, _) => Mnemonic::Cmeq, // #0
            (0, 0b01010, _) => Mnemonic::Cmlt, // #0
            (0, 0b01011, _) => Mnemonic::Abs,
            (1, 0b01000, _) => Mnemonic::Cmge, // #0
            (1, 0b01001, _) => Mnemonic::Cmle, // #0
            (1, 0b01010, _) => Mnemonic::Cmeq, // unused path
            (1, 0b01011, _) => Mnemonic::Neg,
            // Integer not — U=1 opcode 01010 is CMEQ #0 already; CMLT is U=0 01010
            // FP conversions / frint (size bit1 selects mode family)
            (0, 0b11010, s) if s & 2 == 0 => Mnemonic::Fcvtns,
            (1, 0b11010, s) if s & 2 == 0 => Mnemonic::Fcvtnu,
            (0, 0b11011, s) if s & 2 == 0 => Mnemonic::Fcvtms,
            (1, 0b11011, s) if s & 2 == 0 => Mnemonic::Fcvtmu,
            (0, 0b11010, _) => Mnemonic::Fcvtps,
            (1, 0b11010, _) => Mnemonic::Fcvtpu,
            (0, 0b11011, _) => Mnemonic::Fcvtzs,
            (1, 0b11011, _) => Mnemonic::Fcvtzu,
            (0, 0b11100, s) if s & 2 == 0 => Mnemonic::Fcvtas,
            (1, 0b11100, s) if s & 2 == 0 => Mnemonic::Fcvtau,
            (0, 0b11101, s) if s & 2 == 0 => Mnemonic::Scvtf,
            (1, 0b11101, s) if s & 2 == 0 => Mnemonic::Ucvtf,
            (0, 0b11101, _) => Mnemonic::Frecpe,
            (1, 0b11101, _) => Mnemonic::Frsqrte,
            // FP abs/neg/sqrt / frint
            (0, 0b01111, _) if size >= 2 => Mnemonic::Fabs,
            (1, 0b01111, _) if size >= 2 => Mnemonic::Fneg,
            (1, 0b11111, _) if size >= 2 => Mnemonic::Fsqrt,
            (0, 0b10110, _) if size >= 2 => Mnemonic::Fabs,
            (0, 0b10111, _) if size >= 2 => Mnemonic::Fneg,
            (1, 0b10111, _) if size >= 2 => Mnemonic::Fsqrt,
            (0, 0b11000, _) if size >= 2 => Mnemonic::Frintn,
            (0, 0b11001, _) if size >= 2 => Mnemonic::Frintp,
            (1, 0b11000, _) if size >= 2 => Mnemonic::Frinta,
            (1, 0b11001, _) if size >= 2 => Mnemonic::Frintx,
            // FRINT32/64 (vector) — size<=1; FSQRT uses size>=2 with opcode 11111
            (0, 0b11110, _) if size <= 1 => Mnemonic::Frint32z,
            (1, 0b11110, _) if size <= 1 => Mnemonic::Frint32x,
            (0, 0b11111, _) if size <= 1 => Mnemonic::Frint64z,
            (1, 0b11111, _) if size <= 1 => Mnemonic::Frint64x,
            (1, 0b11111, _) if size >= 2 => Mnemonic::Fsqrt,
            (0, 0b11111, _) => Mnemonic::Fsqrt,
            _ => return undef(vaddr, raw),
        }
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_two_misc, mnemonic);
    i.arrangement = if fp16 {
        if q != 0 {
            Arrangement::H8
        } else {
            Arrangement::H4
        }
    } else if crypto {
        Arrangement::B16
    } else {
        arrangement(q, size)
    };
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i
}

fn decode_across(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let u = bit(raw, 29);
    let size = bits(raw, 23, 22);
    let opcode = bits(raw, 16, 12);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mnemonic = match (u, opcode) {
        (0, 0b00011) => Mnemonic::Saddlv,
        (1, 0b00011) => Mnemonic::Uaddlv,
        (0, 0b11011) => Mnemonic::Addv, // Capstone/LLVM opcode (ARM PDF lists 01011)
        (0, 0b01010) => Mnemonic::Smaxv,
        (1, 0b01010) => Mnemonic::Umaxv,
        (0, 0b11010) => Mnemonic::Sminv,
        (1, 0b11010) => Mnemonic::Uminv,
        (0, 0b01100) => Mnemonic::Fmaxnmv,
        (1, 0b01100) => Mnemonic::Fminnmv,
        (0, 0b01111) => Mnemonic::Fmaxv,
        (1, 0b01111) => Mnemonic::Fminv,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_across, mnemonic);
    i.arrangement = arrangement(q, size);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i
}

fn decode_shift_imm(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let u = bit(raw, 29);
    let immh = bits(raw, 22, 19);
    let immb = bits(raw, 18, 16);
    let opcode = bits(raw, 15, 11);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mnemonic = match (u, opcode) {
        (0, 0b00000) => Mnemonic::Sshr,
        (1, 0b00000) => Mnemonic::Ushr,
        (0, 0b00010) => Mnemonic::Ssra,
        (1, 0b00010) => Mnemonic::Usra,
        (0, 0b00100) => Mnemonic::Srshr,
        (1, 0b00100) => Mnemonic::Urshr,
        (0, 0b00110) => Mnemonic::Srsra,
        (1, 0b00110) => Mnemonic::Ursra,
        (1, 0b01000) => Mnemonic::Sri,
        (0, 0b01010) => Mnemonic::Shl,
        (1, 0b01010) => Mnemonic::Sli,
        (1, 0b01100) => Mnemonic::Sqshlu,
        (0, 0b01110) => Mnemonic::Sqshl,
        (1, 0b01110) => Mnemonic::Uqshl,
        // Narrow / widen — note 10000 is SHRN/SQSHRUN, 10100 is SSHLL/USHLL
        (0, 0b10000) => {
            if q != 0 {
                Mnemonic::Shrn2
            } else {
                Mnemonic::Shrn
            }
        }
        (1, 0b10000) => {
            if q != 0 {
                Mnemonic::Sqshrun2
            } else {
                Mnemonic::Sqshrun
            }
        }
        (0, 0b10001) => {
            if q != 0 {
                Mnemonic::Rshrn2
            } else {
                Mnemonic::Rshrn
            }
        }
        (1, 0b10001) => {
            if q != 0 {
                Mnemonic::Sqrshrun2
            } else {
                Mnemonic::Sqrshrun
            }
        }
        (0, 0b10010) => {
            if q != 0 {
                Mnemonic::Sqshrn2
            } else {
                Mnemonic::Sqshrn
            }
        }
        (1, 0b10010) => {
            if q != 0 {
                Mnemonic::Uqshrn2
            } else {
                Mnemonic::Uqshrn
            }
        }
        (0, 0b10011) => {
            if q != 0 {
                Mnemonic::Sqrshrn2
            } else {
                Mnemonic::Sqrshrn
            }
        }
        (1, 0b10011) => {
            if q != 0 {
                Mnemonic::Uqrshrn2
            } else {
                Mnemonic::Uqrshrn
            }
        }
        (0, 0b10100) => {
            if q != 0 {
                Mnemonic::Sshll2
            } else {
                Mnemonic::Sshll
            }
        }
        (1, 0b10100) => {
            if q != 0 {
                Mnemonic::Ushll2
            } else {
                Mnemonic::Ushll
            }
        }
        // Scalar/vector FP convert by fixed-point immediate
        (0, 0b11100) => Mnemonic::Scvtf,
        (1, 0b11100) => Mnemonic::Ucvtf,
        (0, 0b11111) => Mnemonic::Fcvtzs,
        (1, 0b11111) => Mnemonic::Fcvtzu,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_shift_imm, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i.op2_kind = OpKind::Immediate;
    i.op2_imm = ((immh << 3) | immb) as u64;
    i.arrangement = arrangement(q, immh.trailing_zeros().min(3));
    i
}

fn decode_tbl(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let rm = bits(raw, 20, 16);
    let len = bits(raw, 14, 13);
    let op = bit(raw, 12);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mut i = Instruction::with_meta(
        vaddr,
        raw,
        Code::Simd_tbl,
        if op == 0 { Mnemonic::Tbl } else { Mnemonic::Tbx },
    );
    i.arrangement = if q != 0 {
        Arrangement::B16
    } else {
        Arrangement::B8
    };
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::v(rm);
    i.op3_imm = (len + 1) as u64; // register list length
    let _ = len;
    i
}

fn decode_permute(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let size = bits(raw, 23, 22);
    let rm = bits(raw, 20, 16);
    let opcode = bits(raw, 14, 12);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mnemonic = match opcode {
        0b001 => Mnemonic::Uzp1,
        0b010 => Mnemonic::Trn1,
        0b011 => Mnemonic::Zip1,
        0b101 => Mnemonic::Uzp2,
        0b110 => Mnemonic::Trn2,
        0b111 => Mnemonic::Zip2,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_permute, mnemonic);
    i.arrangement = arrangement(q, size);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::v(rm);
    i
}

fn decode_ext(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let rm = bits(raw, 20, 16);
    let imm4 = bits(raw, 14, 11);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_ext, Mnemonic::Ext);
    i.arrangement = if q != 0 {
        Arrangement::B16
    } else {
        Arrangement::B8
    };
    i.op_count = 4;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::v(rm);
    i.op3_kind = OpKind::Immediate;
    i.op3_imm = imm4 as u64;
    i
}

fn decode_fp_2src(vaddr: u64, raw: u32) -> Instruction {
    let ftype = bits(raw, 23, 22);
    let rm = bits(raw, 20, 16);
    let opcode = bits(raw, 15, 12);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mnemonic = match opcode {
        0b0000 => Mnemonic::Fmul,
        0b0001 => Mnemonic::Fdiv,
        0b0010 => Mnemonic::Fadd,
        0b0011 => Mnemonic::Fsub,
        0b0100 => Mnemonic::Fmax,
        0b0101 => Mnemonic::Fmin,
        0b0110 => Mnemonic::Fmaxnm,
        0b0111 => Mnemonic::Fminnm,
        0b1000 => Mnemonic::Fnmul,
        _ => return undef(vaddr, raw),
    };
    let bytes = match ftype {
        0b00 => 4u32,
        0b01 => 8,
        0b11 => 2,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Fp_data_2src, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::fp_sized(bytes, rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::fp_sized(bytes, rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::fp_sized(bytes, rm);
    i
}

fn decode_fp_1src(vaddr: u64, raw: u32) -> Instruction {
    let ftype = bits(raw, 23, 22);
    let opcode = bits(raw, 20, 15);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let bytes = match ftype {
        0b00 => 4u32,
        0b01 => 8,
        0b11 => 2,
        _ => return undef(vaddr, raw),
    };
    // opcode in bits[20:15] for FP 1-source
    let opc = bits(raw, 20, 15);
    let mnemonic = match opc {
        0b000000 => Mnemonic::Fmov,
        0b000001 => Mnemonic::Fabs,
        0b000010 => Mnemonic::Fneg,
        0b000011 => Mnemonic::Fsqrt,
        0b000100 | 0b000101 | 0b000111 => Mnemonic::Fcvt, // type conversions
        0b001000 => Mnemonic::Frintn,
        0b001001 => Mnemonic::Frintp,
        0b001010 => Mnemonic::Frintm,
        0b001011 => Mnemonic::Frintz,
        0b001100 => Mnemonic::Frinta,
        0b001110 => Mnemonic::Frintx,
        0b001111 => Mnemonic::Frinti,
        0b010000 => Mnemonic::Frint32z,
        0b010001 => Mnemonic::Frint32x,
        0b010010 => Mnemonic::Frint64z,
        0b010011 => Mnemonic::Frint64x,
        _ => return undef(vaddr, raw),
    };
    let _ = opcode;
    let mut i = Instruction::with_meta(vaddr, raw, Code::Fp_1src, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::fp_sized(bytes, rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::fp_sized(bytes, rn);
    i
}

fn decode_fp_3src(vaddr: u64, raw: u32) -> Instruction {
    let ftype = bits(raw, 23, 22);
    let o1 = bit(raw, 21);
    let o0 = bit(raw, 15);
    let rm = bits(raw, 20, 16);
    let ra = bits(raw, 14, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mnemonic = match (o1, o0) {
        (0, 0) => Mnemonic::Fmadd,
        (0, 1) => Mnemonic::Fmsub,
        (1, 0) => Mnemonic::Fnmadd,
        _ => Mnemonic::Fnmsub,
    };
    let bytes = match ftype {
        0b00 => 4u32,
        0b01 => 8,
        0b11 => 2,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Fp_data_2src, mnemonic);
    i.op_count = 4;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::fp_sized(bytes, rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::fp_sized(bytes, rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::fp_sized(bytes, rm);
    i.op3_kind = OpKind::Register;
    i.op3_reg = Register::fp_sized(bytes, ra);
    i
}

fn decode_crypto_3reg(vaddr: u64, raw: u32) -> Instruction {
    // Capstone/LLVM: bits[15:12] select SHA op; bits[11:10] must be 00 for 3-reg forms
    // (avoids aliasing scalar MOV/DUP which have bit10=1).
    if bits(raw, 11, 10) != 0b00 {
        return undef(vaddr, raw);
    }
    let size = bits(raw, 23, 22);
    let rm = bits(raw, 20, 16);
    let opcode = bits(raw, 15, 12);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    if size != 0b00 {
        return undef(vaddr, raw);
    }
    let mnemonic = match opcode {
        0b0000 => Mnemonic::Sha1c,
        0b0001 => Mnemonic::Sha1p,
        0b0010 => Mnemonic::Sha1m,
        0b0011 => Mnemonic::Sha1su0,
        0b0100 => Mnemonic::Sha256h,
        0b0101 => Mnemonic::Sha256h2,
        0b0110 => Mnemonic::Sha256su1,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_three_same, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::v(rm);
    i
}

fn decode_three_diff(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let u = bit(raw, 29);
    let size = bits(raw, 23, 22);
    let rm = bits(raw, 20, 16);
    let opcode = bits(raw, 15, 12);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mnemonic = match (u, opcode) {
        (0, 0b0000) => {
            if q != 0 {
                Mnemonic::Saddl2
            } else {
                Mnemonic::Saddl
            }
        }
        (1, 0b0000) => {
            if q != 0 {
                Mnemonic::Uaddl2
            } else {
                Mnemonic::Uaddl
            }
        }
        (0, 0b1000) => {
            if q != 0 {
                Mnemonic::Smlal2
            } else {
                Mnemonic::Smlal
            }
        }
        (1, 0b1000) => {
            if q != 0 {
                Mnemonic::Umlal2
            } else {
                Mnemonic::Umlal
            }
        }
        (0, 0b1001) => {
            if q != 0 {
                Mnemonic::Sqdmlal2
            } else {
                Mnemonic::Sqdmlal
            }
        }
        (0, 0b1010) => {
            if q != 0 {
                Mnemonic::Smlsl2
            } else {
                Mnemonic::Smlsl
            }
        }
        (1, 0b1010) => {
            if q != 0 {
                Mnemonic::Umlsl2
            } else {
                Mnemonic::Umlsl
            }
        }
        (0, 0b1011) => {
            if q != 0 {
                Mnemonic::Sqdmlsl2
            } else {
                Mnemonic::Sqdmlsl
            }
        }
        (0, 0b1100) => {
            if q != 0 {
                Mnemonic::Smull2
            } else {
                Mnemonic::Smull
            }
        }
        (1, 0b1100) => {
            if q != 0 {
                Mnemonic::Umull2
            } else {
                Mnemonic::Umull
            }
        }
        (0, 0b1101) => {
            if q != 0 {
                Mnemonic::Sqdmull2
            } else {
                Mnemonic::Sqdmull
            }
        }
        (_, 0b1110) => {
            if q != 0 {
                Mnemonic::Pmull2
            } else {
                Mnemonic::Pmull
            }
        }
        (0, 0b0100) => {
            if q != 0 {
                Mnemonic::Addhn2
            } else {
                Mnemonic::Addhn
            }
        }
        (1, 0b0100) => {
            if q != 0 {
                Mnemonic::Raddhn2
            } else {
                Mnemonic::Raddhn
            }
        }
        (0, 0b0010) => {
            if q != 0 {
                Mnemonic::Ssubl2
            } else {
                Mnemonic::Ssubl
            }
        }
        (1, 0b0010) => {
            if q != 0 {
                Mnemonic::Usubl2
            } else {
                Mnemonic::Usubl
            }
        }
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_three_diff, mnemonic);
    i.arrangement = arrangement(q, size);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::v(rm);
    i
}

fn decode_by_element(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let u = bit(raw, 29);
    let size = bits(raw, 23, 22);
    let l = bit(raw, 21);
    let m = bit(raw, 20);
    let rm = bits(raw, 19, 16);
    let opcode = bits(raw, 15, 12);
    let h = bit(raw, 11);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mnemonic = match (u, opcode) {
        (0, 0b0001) => Mnemonic::Fmla,
        (0, 0b0101) => Mnemonic::Fmls,
        (0, 0b1001) => Mnemonic::Fmul,
        (1, 0b1001) => Mnemonic::Fmulx,
        (1, 0b0001) => Mnemonic::Fcmla,
        (1, 0b0101) => Mnemonic::Fcmla,
        (0, 0b0010) => {
            if q != 0 {
                Mnemonic::Smlal2
            } else {
                Mnemonic::Smlal
            }
        }
        (1, 0b0010) => {
            if q != 0 {
                Mnemonic::Umlal2
            } else {
                Mnemonic::Umlal
            }
        }
        (0, 0b0011) => {
            if q != 0 {
                Mnemonic::Sqdmlal2
            } else {
                Mnemonic::Sqdmlal
            }
        }
        (0, 0b0110) => {
            if q != 0 {
                Mnemonic::Smlsl2
            } else {
                Mnemonic::Smlsl
            }
        }
        (0, 0b0111) => {
            if q != 0 {
                Mnemonic::Sqdmlsl2
            } else {
                Mnemonic::Sqdmlsl
            }
        }
        (0, 0b1010) => {
            if q != 0 {
                Mnemonic::Smull2
            } else {
                Mnemonic::Smull
            }
        }
        (1, 0b1010) => {
            if q != 0 {
                Mnemonic::Umull2
            } else {
                Mnemonic::Umull
            }
        }
        (0, 0b1011) => {
            if q != 0 {
                Mnemonic::Sqdmull2
            } else {
                Mnemonic::Sqdmull
            }
        }
        (0, 0b1100) => Mnemonic::Sqdmulh,
        (0, 0b1101) => Mnemonic::Sqrdmulh,
        (1, 0b1101) => Mnemonic::Sqrdmlah,
        (1, 0b1111) => Mnemonic::Sqrdmlsh,
        (0, 0b1000) => Mnemonic::Mul,
        (0, 0b0100) => Mnemonic::Mla,
        (1, 0b0100) => Mnemonic::Mls,
        (1, 0b0000) => Mnemonic::Mla,
        (0, 0b1110) => Mnemonic::Sdot,
        (1, 0b1110) => Mnemonic::Udot,
        (0, 0b1111) if size == 0b00 => Mnemonic::Sudot,
        (0, 0b1111) if size == 0b01 => Mnemonic::Bfdot,
        (0, 0b1111) if size == 0b10 => Mnemonic::Usdot,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_by_element, mnemonic);
    i.arrangement = arrangement(q, size);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::v(rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::v(rm | (m << 4));
    i.vector_index = ((h << 2) | (l << 1) | (size & 1)) as u8; // approximate
    i
}

fn decode_fp_conversion_fixed(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31);
    let ftype = bits(raw, 23, 22);
    let opcode = bits(raw, 18, 16);
    let scale = bits(raw, 15, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let bytes = match ftype {
        0b00 => 4u32,
        0b01 => 8,
        0b11 => 2,
        _ => return undef(vaddr, raw),
    };
    let mnemonic = match opcode {
        0b000 => Mnemonic::Fcvtzs,
        0b001 => Mnemonic::Fcvtzu,
        0b010 => Mnemonic::Scvtf,
        0b011 => Mnemonic::Ucvtf,
        _ => return undef(vaddr, raw),
    };
    let to_fp = matches!(mnemonic, Mnemonic::Scvtf | Mnemonic::Ucvtf);
    let mut i = Instruction::with_meta(vaddr, raw, Code::Fp_conversion, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op1_kind = OpKind::Register;
    i.op2_kind = OpKind::Immediate;
    i.op2_imm = scale as u64;
    if to_fp {
        i.op0_reg = Register::fp_sized(bytes, rd);
        i.op1_reg = Register::gpr(sf != 0, rn, false);
    } else {
        i.op0_reg = Register::gpr(sf != 0, rd, false);
        i.op1_reg = Register::fp_sized(bytes, rn);
    }
    i
}

fn decode_simd_scalar_two_misc(vaddr: u64, raw: u32) -> Instruction {
    let u = bit(raw, 29);
    let size = bits(raw, 23, 22);
    let opcode = bits(raw, 16, 12);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    // SHA1H / SHA1SU1 / SHA256SU0 (two-register crypto)
    if bits(raw, 21, 16) == 0b101000 && bits(raw, 11, 10) == 0b10 {
        let mnemonic = match opcode {
            0b00000 => Mnemonic::Sha1h,
            0b00001 => Mnemonic::Sha1su1,
            0b00010 => Mnemonic::Sha256su0,
            _ => return undef(vaddr, raw),
        };
        let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_two_misc, mnemonic);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::v(rd);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::v(rn);
        return i;
    }
    let mnemonic = match (u, opcode) {
        (1, 0b10100) => Mnemonic::Uqxtn,
        (0, 0b10100) => Mnemonic::Sqxtn,
        (0, 0b10101) => Mnemonic::Sqxtun,
        (1, 0b01000) => Mnemonic::Cmge, // #0
        (0, 0b01000) => Mnemonic::Cmgt,
        (0, 0b01001) => Mnemonic::Cmeq,
        (0, 0b01011) => Mnemonic::Cmlt,
        (1, 0b01001) => Mnemonic::Cmle,
        (0, 0b01010) => Mnemonic::Abs,
        (1, 0b01011) => Mnemonic::Neg,
        (0, 0b11101) => Mnemonic::Fcvtns,
        (0, 0b11011) => Mnemonic::Fcvtzs,
        (1, 0b11011) => Mnemonic::Fcvtzu,
        (0, 0b11100) => Mnemonic::Fcvtas,
        (1, 0b11100) => Mnemonic::Fcvtau,
        (0, 0b11110) => Mnemonic::Scvtf,
        (1, 0b11110) => Mnemonic::Ucvtf,
        _ => return undef(vaddr, raw),
    };
    let bytes = 1u32 << size;
    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_two_misc, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::fp_sized(bytes.min(8), rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::fp_sized((bytes * 2).min(16), rn);
    i
}


fn decode_fp_conversion(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31);
    let ftype = bits(raw, 23, 22);
    let rmode = bits(raw, 20, 19);
    let opcode = bits(raw, 18, 16);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let bytes = match ftype {
        0b00 => 4u32,
        0b01 => 8,
        0b11 => 2,
        _ => return undef(vaddr, raw),
    };
    let mnemonic = match (rmode, opcode) {
        (0b00, 0b000) => Mnemonic::Fcvtns,
        (0b00, 0b001) => Mnemonic::Fcvtnu,
        (0b01, 0b000) => Mnemonic::Fcvtps,
        (0b01, 0b001) => Mnemonic::Fcvtpu,
        (0b10, 0b000) => Mnemonic::Fcvtms,
        (0b10, 0b001) => Mnemonic::Fcvtmu,
        (0b11, 0b000) => Mnemonic::Fcvtzs,
        (0b11, 0b001) => Mnemonic::Fcvtzu,
        (0b00, 0b010) => Mnemonic::Scvtf,
        (0b00, 0b011) => Mnemonic::Ucvtf,
        (0b00, 0b100) | (0b01, 0b100) | (0b10, 0b100) | (0b11, 0b100) => Mnemonic::Fcvtas,
        (0b00, 0b101) | (0b01, 0b101) | (0b10, 0b101) | (0b11, 0b101) => Mnemonic::Fcvtau,
        (0b00, 0b110) => Mnemonic::Fmov,
        (0b00, 0b111) => Mnemonic::Fmov,
        (0b01, 0b110) => Mnemonic::Fmov, // top/bottom half of 128-bit
        (0b01, 0b111) => Mnemonic::Fmov,
        _ => return undef(vaddr, raw),
    };
    let to_int = matches!(
        mnemonic,
        Mnemonic::Fcvtns
            | Mnemonic::Fcvtnu
            | Mnemonic::Fcvtps
            | Mnemonic::Fcvtpu
            | Mnemonic::Fcvtms
            | Mnemonic::Fcvtmu
            | Mnemonic::Fcvtas
            | Mnemonic::Fcvtau
            | Mnemonic::Fcvtzs
            | Mnemonic::Fcvtzu
    ) || (mnemonic == Mnemonic::Fmov && (opcode == 0b110));
    let mut i = Instruction::with_meta(vaddr, raw, Code::Fp_conversion, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op1_kind = OpKind::Register;
    if to_int {
        i.op0_reg = Register::gpr(sf != 0, rd, false);
        i.op1_reg = Register::fp_sized(bytes, rn);
    } else if mnemonic == Mnemonic::Fmov && opcode == 0b111 {
        i.op0_reg = Register::fp_sized(bytes, rd);
        i.op1_reg = Register::gpr(sf != 0, rn, false);
    } else {
        i.op0_reg = Register::fp_sized(bytes, rd);
        i.op1_reg = Register::gpr(sf != 0, rn, false);
    }
    i
}

fn decode_fp_compare(vaddr: u64, raw: u32) -> Instruction {
    let ftype = bits(raw, 23, 22);
    let rn = bits(raw, 9, 5);
    let rm = bits(raw, 20, 16);
    let opcode2 = bits(raw, 4, 0);
    let bytes = match ftype {
        0b00 => 4u32,
        0b01 => 8,
        0b11 => 2,
        _ => return undef(vaddr, raw),
    };
    let mnemonic = if (opcode2 & 0b10000) != 0 {
        Mnemonic::Fcmpe
    } else {
        Mnemonic::Fcmp
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Fp_compare, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::fp_sized(bytes, rn);
    if (opcode2 & 0b01000) != 0 {
        i.op1_kind = OpKind::Immediate;
        i.op1_imm = 0;
    } else {
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::fp_sized(bytes, rm);
    }
    i
}

fn decode_fp_ccmp(vaddr: u64, raw: u32) -> Instruction {
    let ftype = bits(raw, 23, 22);
    let rm = bits(raw, 20, 16);
    let cond = crate::enums::Condition::from_u32(bits(raw, 15, 12));
    let rn = bits(raw, 9, 5);
    let nzcv = bits(raw, 3, 0);
    let op = bit(raw, 4);
    let bytes = match ftype {
        0b00 => 4u32,
        0b01 => 8,
        0b11 => 2,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(
        vaddr,
        raw,
        Code::Fp_compare,
        if op != 0 {
            Mnemonic::Fccmpe
        } else {
            Mnemonic::Fccmp
        },
    );
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::fp_sized(bytes, rn);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::fp_sized(bytes, rm);
    i.op2_kind = OpKind::Immediate;
    i.op2_imm = nzcv as u64;
    i.condition = cond;
    i
}

fn decode_fp_csel(vaddr: u64, raw: u32) -> Instruction {
    let ftype = bits(raw, 23, 22);
    let rm = bits(raw, 20, 16);
    let cond = crate::enums::Condition::from_u32(bits(raw, 15, 12));
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let bytes = match ftype {
        0b00 => 4u32,
        0b01 => 8,
        0b11 => 2,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Fp_data_2src, Mnemonic::Fcsel);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::fp_sized(bytes, rd);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::fp_sized(bytes, rn);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::fp_sized(bytes, rm);
    i.condition = cond;
    i
}


fn decode_fp_imm(vaddr: u64, raw: u32) -> Instruction {
    let ftype = bits(raw, 23, 22);
    let imm8 = bits(raw, 20, 13);
    let rd = bits(raw, 4, 0);
    let bytes = match ftype {
        0b00 => 4u32,
        0b01 => 8,
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Fp_imm, Mnemonic::Fmov);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::fp_sized(bytes, rd);
    i.op1_kind = OpKind::Immediate;
    i.op1_imm = imm8 as u64;
    i
}
