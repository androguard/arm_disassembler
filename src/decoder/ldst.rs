//! Load/store (elfbrowser `ldst.rs` — GPR + SIMD/FP + exclusive).

use crate::enums::{Arrangement, Code, ExtendKind, MemMode, OpKind, Register};
use crate::helpers::{bit, bits, sign_extend};
use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;

use super::undef;

pub(super) fn decode(vaddr: u64, raw: u32) -> Instruction {
    // MTE tag stores STG/ST2G/STZG/STZ2G (bit21=1 distinguishes from LDAPUR X)
    if bits(raw, 31, 24) == 0b11011001 && bit(raw, 21) == 1 {
        return decode_mte_stg(vaddr, raw);
    }
    // MTE STGP (store only; bit22=0). bit22=1 is LDPSW in the same op0 space.
    if (bits(raw, 31, 25) == 0b0110100 || bits(raw, 31, 24) == 0b01101011) && bit(raw, 22) == 0 {
        return decode_stgp(vaddr, raw);
    }
    // RCW* (FEAT_THE) in unscaled-ordered space with bit21=1
    if bits(raw, 29, 24) == 0b011001 && bit(raw, 21) == 1 {
        return decode_rcw(vaddr, raw);
    }
    // STILP (opc=00) / LDIAPP (opc=01) — not STLR(opc=10)/LDAPR(opc=11)
    if bits(raw, 29, 24) == 0b011001
        && bit(raw, 21) == 0
        && bits(raw, 11, 10) == 0b10
        && matches!(bits(raw, 23, 22), 0b00 | 0b01)
    {
        return decode_stilp_ldiapp(vaddr, raw);
    }
    if (bits(raw, 29, 24) == 0b011001 && bit(raw, 21) == 0 && bits(raw, 11, 10) == 0b00)
        || (bits(raw, 29, 24) == 0b011101 && bit(raw, 21) == 0 && bits(raw, 11, 10) == 0b10)
    {
        return decode_ldapur_stlur(vaddr, raw);
    }
    // Advanced SIMD load/store multiple structures (LD1/ST1…LD4/ST4)
    if bit(raw, 31) == 0 && bits(raw, 29, 24) == 0b001100 {
        return decode_simd_ldst_multi(vaddr, raw);
    }
    // Advanced SIMD load/store single structure (+ replicate LD1R…LD4R)
    if bit(raw, 31) == 0 && bits(raw, 29, 24) == 0b001101 {
        return decode_simd_ldst_single(vaddr, raw);
    }
    // SIMD/FP register pair
    if bits(raw, 29, 27) == 0b101 && bit(raw, 26) == 1 {
        return decode_pair(vaddr, raw, true);
    }
    // GPR register pair
    if bits(raw, 29, 27) == 0b101 && bit(raw, 26) == 0 {
        return decode_pair(vaddr, raw, false);
    }
    // Unsigned immediate (GPR + SIMD)
    if bits(raw, 29, 27) == 0b111 && bit(raw, 24) == 1 {
        return decode_unsigned(vaddr, raw);
    }
    // SIMD register offset
    if bits(raw, 29, 27) == 0b111 && bit(raw, 26) == 1 && bit(raw, 24) == 0 && bit(raw, 21) == 1 {
        return decode_reg_offset(vaddr, raw, true);
    }
    // SIMD pre/post/unscaled
    if bits(raw, 29, 27) == 0b111 && bit(raw, 26) == 1 && bit(raw, 24) == 0 && bit(raw, 21) == 0 {
        return decode_imm_prepost(vaddr, raw, true);
    }
    // LDRAA / LDRAB (PAC authenticated load)
    if bits(raw, 31, 24) & 0b11111100 == 0b11111000
        && bit(raw, 21) == 1
        && bit(raw, 10) == 1
    {
        return decode_ldra(vaddr, raw);
    }
    // Atomic memory ops (SWP/LDADD/…): bit21=1, bits[11:10]=00
    if bits(raw, 29, 27) == 0b111
        && bit(raw, 26) == 0
        && bit(raw, 24) == 0
        && bit(raw, 21) == 1
        && bits(raw, 11, 10) == 0b00
    {
        return decode_atomic(vaddr, raw);
    }
    // GPR pre/post/unscaled
    if bits(raw, 29, 27) == 0b111 && bit(raw, 26) == 0 && bit(raw, 24) == 0 && bit(raw, 21) == 0 {
        return decode_imm_prepost(vaddr, raw, false);
    }
    // GPR register offset
    if bits(raw, 29, 27) == 0b111 && bit(raw, 26) == 0 && bit(raw, 24) == 0 && bit(raw, 21) == 1 {
        return decode_reg_offset(vaddr, raw, false);
    }
    // Literal SIMD
    if bits(raw, 29, 27) == 0b011 && bit(raw, 26) == 1 {
        return decode_literal(vaddr, raw, true);
    }
    // Literal GPR
    if bits(raw, 29, 27) == 0b011 && bit(raw, 26) == 0 {
        return decode_literal(vaddr, raw, false);
    }
    // Exclusive / ordered
    if bits(raw, 29, 24) == 0b001000 {
        return decode_exclusive(vaddr, raw);
    }
    undef(vaddr, raw)
}

fn decode_pair(vaddr: u64, raw: u32, simd: bool) -> Instruction {
    let opc = bits(raw, 31, 30);
    let is_load = bit(raw, 22) != 0;
    let mode = bits(raw, 24, 23);
    let imm7 = bits(raw, 21, 15);
    let rt2 = bits(raw, 14, 10);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);

    let (scale, sf, signed) = if simd {
        let scale = match opc {
            0b00 => 2u32,
            0b01 => 3,
            0b10 => 4,
            _ => return undef(vaddr, raw),
        };
        (scale, false, false)
    } else {
        match opc {
            0b00 => (2u32, false, false),
            0b01 => (2, true, true), // LDPSW
            0b10 => (3, true, false),
            _ => return undef(vaddr, raw),
        }
    };

    let offset = (sign_extend((imm7 as u64) << scale, 7 + scale)) as i32;
    let mem_mode = match mode {
        0b00 => MemMode::Offset, // LDNP/STNP
        0b01 => MemMode::PostIndex,
        0b11 => MemMode::PreIndex,
        0b10 => MemMode::Offset,
        _ => return undef(vaddr, raw),
    };

    let (code, mnemonic) = if mode == 0b00 {
        if simd {
            (
                if is_load { Code::Ldp_fp } else { Code::Stp_fp },
                if is_load { Mnemonic::Ldnp } else { Mnemonic::Stnp },
            )
        } else if signed && is_load {
            (Code::Ldpsw, Mnemonic::Ldpsw)
        } else {
            (
                if is_load { Code::Ldp } else { Code::Stp },
                if is_load { Mnemonic::Ldnp } else { Mnemonic::Stnp },
            )
        }
    } else if simd {
        (
            if is_load { Code::Ldp_fp } else { Code::Stp_fp },
            if is_load { Mnemonic::Ldp } else { Mnemonic::Stp },
        )
    } else if signed && is_load {
        (Code::Ldpsw, Mnemonic::Ldpsw)
    } else {
        (
            if is_load { Code::Ldp } else { Code::Stp },
            if is_load { Mnemonic::Ldp } else { Mnemonic::Stp },
        )
    };

    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op1_kind = OpKind::Register;
    if simd {
        let bytes = 1u32 << scale;
        i.op0_reg = Register::fp_sized(bytes, rt);
        i.op1_reg = Register::fp_sized(bytes, rt2);
    } else {
        i.op0_reg = Register::gpr(sf || signed, rt, false);
        i.op1_reg = Register::gpr(sf || signed, rt2, false);
    }
    i.op2_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.memory_offset = offset;
    i.mem_mode = mem_mode;
    i
}

fn decode_unsigned(vaddr: u64, raw: u32) -> Instruction {
    let size = bits(raw, 31, 30);
    let v = bit(raw, 26);
    let opc = bits(raw, 23, 22);
    let imm12 = bits(raw, 21, 10) as u64;
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);

    if v != 0 {
        let scale = if opc & 0b10 != 0 { 4u32 } else { size };
        let offset = (imm12 << scale) as i32;
        let is_load = opc & 1 == 1;
        let bytes = 1u32 << scale;
        let mut i = Instruction::with_meta(
            vaddr,
            raw,
            if is_load {
                Code::Ldr_fp_uimm
            } else {
                Code::Str_fp_uimm
            },
            if is_load { Mnemonic::Ldr } else { Mnemonic::Str },
        );
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::fp_sized(bytes, rt);
        i.op1_kind = OpKind::Memory;
        i.memory_base = Register::gpr(true, rn, true);
        i.memory_offset = offset;
        i.mem_mode = MemMode::Offset;
        return i;
    }

    let scale = size;
    let offset = (imm12 << scale) as i32;
    let (code, mnemonic, sf) = match (size, opc) {
        (0, 0b00) => (Code::Strb_uimm, Mnemonic::Strb, false),
        (0, 0b01) => (Code::Ldrb_uimm, Mnemonic::Ldrb, false),
        (0, 0b10) => (Code::Ldrsb_uimm, Mnemonic::Ldrsb, true),
        (0, 0b11) => (Code::Ldrsb_uimm, Mnemonic::Ldrsb, false),
        (1, 0b00) => (Code::Strh_uimm, Mnemonic::Strh, false),
        (1, 0b01) => (Code::Ldrh_uimm, Mnemonic::Ldrh, false),
        (1, 0b10) => (Code::Ldrsh_uimm, Mnemonic::Ldrsh, true),
        (1, 0b11) => (Code::Ldrsh_uimm, Mnemonic::Ldrsh, false),
        (2, 0b00) => (Code::Str_uimm, Mnemonic::Str, false),
        (2, 0b01) => (Code::Ldr_uimm, Mnemonic::Ldr, false),
        (2, 0b10) => (Code::Ldrsw_uimm, Mnemonic::Ldrsw, true),
        (3, 0b00) => (Code::Str_uimm, Mnemonic::Str, true),
        (3, 0b01) => (Code::Ldr_uimm, Mnemonic::Ldr, true),
        (3, 0b10) | (3, 0b11) => (Code::Ldr_uimm, Mnemonic::Prfm, true),
        _ => return undef(vaddr, raw),
    };
    if mnemonic == Mnemonic::Prfm {
        let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
        i.op_count = 2;
        i.op0_kind = OpKind::Immediate;
        i.op0_imm = rt as u64; // prfop
        i.op1_kind = OpKind::Memory;
        i.memory_base = Register::gpr(true, rn, true);
        i.memory_offset = offset;
        i.mem_mode = MemMode::Offset;
        return i;
    }
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rt, false);
    i.op1_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.memory_offset = offset;
    i.mem_mode = MemMode::Offset;
    i
}

fn decode_imm_prepost(vaddr: u64, raw: u32, simd: bool) -> Instruction {
    let size = bits(raw, 31, 30);
    let opc = bits(raw, 23, 22);
    let imm9 = bits(raw, 20, 12);
    let mode = bits(raw, 11, 10);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    let offset = sign_extend(imm9 as u64, 9) as i32;
    let mem_mode = match mode {
        0b00 => MemMode::Offset, // LDUR/STUR
        0b01 => MemMode::PostIndex,
        0b11 => MemMode::PreIndex,
        _ => return undef(vaddr, raw),
    };
    let is_load = opc & 1 == 1;

    if simd {
        let scale = if opc & 0b10 != 0 { 4u32 } else { size };
        let bytes = 1u32 << scale;
        let mut i = Instruction::with_meta(
            vaddr,
            raw,
            if is_load {
                Code::Ldr_imm
            } else {
                Code::Str_imm
            },
            if mode == 0 {
                if is_load {
                    Mnemonic::Ldur
                } else {
                    Mnemonic::Stur
                }
            } else if is_load {
                Mnemonic::Ldr
            } else {
                Mnemonic::Str
            },
        );
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::fp_sized(bytes, rt);
        i.op1_kind = OpKind::Memory;
        i.memory_base = Register::gpr(true, rn, true);
        i.memory_offset = offset;
        i.mem_mode = mem_mode;
        return i;
    }

    let sf = size == 3 || (opc >= 0b10 && size < 3);
    let mnemonic = if mode == 0 {
        if is_load {
            Mnemonic::Ldur
        } else {
            Mnemonic::Stur
        }
    } else {
        match (size, opc) {
            (0, 0b00) => Mnemonic::Strb,
            (0, 0b01) => Mnemonic::Ldrb,
            (0, 0b10) | (0, 0b11) => Mnemonic::Ldrsb,
            (1, 0b00) => Mnemonic::Strh,
            (1, 0b01) => Mnemonic::Ldrh,
            (1, 0b10) | (1, 0b11) => Mnemonic::Ldrsh,
            (2, 0b10) => Mnemonic::Ldrsw,
            (_, 0b00) => Mnemonic::Str,
            _ => Mnemonic::Ldr,
        }
    };
    let mut i = Instruction::with_meta(
        vaddr,
        raw,
        if is_load {
            Code::Ldr_imm
        } else {
            Code::Str_imm
        },
        mnemonic,
    );
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf || size == 3, rt, false);
    i.op1_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.memory_offset = offset;
    i.mem_mode = mem_mode;
    i
}

fn decode_reg_offset(vaddr: u64, raw: u32, simd: bool) -> Instruction {
    let size = bits(raw, 31, 30);
    let opc = bits(raw, 23, 22);
    let rm = bits(raw, 20, 16);
    let option = bits(raw, 15, 13);
    let s = bit(raw, 12);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    let is_load = opc & 1 == 1;
    let scale = if simd && opc & 0b10 != 0 {
        4u32
    } else {
        size
    };

    let mut i = Instruction::with_meta(
        vaddr,
        raw,
        if is_load {
            Code::Ldr_reg
        } else {
            Code::Str_reg
        },
        if is_load { Mnemonic::Ldr } else { Mnemonic::Str },
    );
    if !simd {
        i.mnemonic = match (size, opc) {
            (0, 0b00) => Mnemonic::Strb,
            (0, 0b01) => Mnemonic::Ldrb,
            (0, 0b10) | (0, 0b11) => Mnemonic::Ldrsb,
            (1, 0b00) => Mnemonic::Strh,
            (1, 0b01) => Mnemonic::Ldrh,
            (1, 0b10) | (1, 0b11) => Mnemonic::Ldrsh,
            (2, 0b10) => Mnemonic::Ldrsw,
            (_, 0b00) => Mnemonic::Str,
            _ => Mnemonic::Ldr,
        };
    }
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    if simd {
        i.op0_reg = Register::fp_sized(1 << scale, rt);
    } else {
        let sf = size == 3 || opc >= 0b10;
        i.op0_reg = Register::gpr(sf, rt, false);
    }
    i.op1_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.memory_index = Register::x(rm);
    i.extend_kind = ExtendKind::from_u32(option);
    i.memory_index_shift = if s != 0 { scale as u8 } else { 0 };
    i.mem_mode = MemMode::Register;
    i
}

fn decode_literal(vaddr: u64, raw: u32, simd: bool) -> Instruction {
    let opc = bits(raw, 31, 30);
    let imm19 = bits(raw, 23, 5) as u64;
    let rt = bits(raw, 4, 0);
    let target = (vaddr as i64).wrapping_add(sign_extend(imm19 << 2, 21)) as u64;

    if simd {
        let bytes = match opc {
            0 => 4u32,
            1 => 8,
            2 => 16,
            _ => return undef(vaddr, raw),
        };
        let mut i = Instruction::with_meta(vaddr, raw, Code::Ldr_fp_lit, Mnemonic::Ldr);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::fp_sized(bytes, rt);
        i.op1_kind = OpKind::NearBranch;
        i.op1_imm = target;
        i.near_branch_target = target;
        i.mem_mode = MemMode::Literal;
        return i;
    }

    let (code, mnemonic, sf) = match opc {
        0b00 => (Code::Ldr_lit, Mnemonic::Ldr, false),
        0b01 => (Code::Ldr_lit, Mnemonic::Ldr, true),
        0b10 => (Code::Ldrsw_lit, Mnemonic::Ldrsw, true),
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rt, false);
    i.op1_kind = OpKind::NearBranch;
    i.op1_imm = target;
    i.near_branch_target = target;
    i.mem_mode = MemMode::Literal;
    i
}

fn decode_exclusive(vaddr: u64, raw: u32) -> Instruction {
    let size = bits(raw, 31, 30);
    let ordered = bit(raw, 15); // rough
    let l = bit(raw, 22);
    let o0 = bit(raw, 23);
    let rs = bits(raw, 20, 16);
    let rt2 = bits(raw, 14, 10);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    let sf = size == 3;
    let pair = bit(raw, 21) != 0;

    // CAS / CASP: bit21=1, Rt2=11111; bit23=0 → CASP, bit23=1 → CAS; bit15=release
    if pair && rt2 == 0b11111 {
        let rel = bit(raw, 15);
        let mnemonic = if o0 == 0 {
            match (l, rel) {
                (0, 0) => Mnemonic::Casp,
                (0, 1) => Mnemonic::Caspl,
                (1, 0) => Mnemonic::Caspa,
                _ => Mnemonic::Caspal,
            }
        } else {
            match (size, l, rel) {
                (0, 0, 0) => Mnemonic::Casb,
                (0, 0, 1) => Mnemonic::Caslb,
                (0, 1, 0) => Mnemonic::Casab,
                (0, 1, 1) => Mnemonic::Casalb,
                (1, 0, 0) => Mnemonic::Cash,
                (1, 0, 1) => Mnemonic::Caslh,
                (1, 1, 0) => Mnemonic::Casah,
                (1, 1, 1) => Mnemonic::Casalh,
                (_, 0, 0) => Mnemonic::Cas,
                (_, 0, 1) => Mnemonic::Casl,
                (_, 1, 0) => Mnemonic::Casa,
                _ => Mnemonic::Casal,
            }
        };
        let cas_sf = if o0 == 0 { size >= 1 } else { size >= 3 };
        let mut i = Instruction::with_meta(vaddr, raw, Code::Ldxr, mnemonic);
        i.op_count = 3;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(cas_sf, rs, false);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(cas_sf, rt, false);
        i.op2_kind = OpKind::Memory;
        i.memory_base = Register::gpr(true, rn, true);
        i.mem_mode = MemMode::Offset;
        let _ = ordered;
        return i;
    }

    let (code, mnemonic) = if l != 0 {
        match (size, pair, o0) {
            (_, true, _) => (Code::Ldxrp, Mnemonic::Ldxp),
            (0, _, 1) => (Code::Ldarb, Mnemonic::Ldarb),
            (1, _, 1) => (Code::Ldarh, Mnemonic::Ldarh),
            (_, _, 1) => (Code::Ldar, Mnemonic::Ldar),
            (0, _, _) => (Code::Ldxrb, Mnemonic::Ldxrb),
            (1, _, _) => (Code::Ldxrh, Mnemonic::Ldxrh),
            _ => (Code::Ldxr, Mnemonic::Ldxr),
        }
    } else {
        match (size, pair, o0) {
            (_, true, _) => (Code::Stxrp, Mnemonic::Stxp),
            (0, _, 1) => (Code::Stlrb, Mnemonic::Stlrb),
            (1, _, 1) => (Code::Stlrh, Mnemonic::Stlrh),
            (_, _, 1) => (Code::Stlr, Mnemonic::Stlr),
            (0, _, _) => (Code::Stxrb, Mnemonic::Stxrb),
            (1, _, _) => (Code::Stxrh, Mnemonic::Stxrh),
            _ => (Code::Stxr, Mnemonic::Stxr),
        }
    };
    let _ = ordered;

    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    if l != 0 {
        i.op_count = if pair { 3 } else { 2 };
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rt, false);
        if pair {
            i.op1_kind = OpKind::Register;
            i.op1_reg = Register::gpr(sf, rt2, false);
            i.op2_kind = OpKind::Memory;
        } else {
            i.op1_kind = OpKind::Memory;
        }
    } else if matches!(
        mnemonic,
        Mnemonic::Stlr | Mnemonic::Stlrb | Mnemonic::Stlrh
    ) {
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rt, false);
        i.op1_kind = OpKind::Memory;
    } else {
        i.op_count = if pair { 4 } else { 3 };
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::w(rs); // status
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rt, false);
        if pair {
            i.op2_kind = OpKind::Register;
            i.op2_reg = Register::gpr(sf, rt2, false);
            i.op3_kind = OpKind::Memory;
        } else {
            i.op2_kind = OpKind::Memory;
        }
    }
    i.memory_base = Register::gpr(true, rn, true);
    i.mem_mode = MemMode::Offset;
    i
}

fn simd_arrangement(q: u32, size: u32) -> Arrangement {
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

/// AdvSIMD load/store multiple structures (LD1/ST1 … LD4/ST4).
fn decode_simd_ldst_multi(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let l = bit(raw, 22);
    let rm = bits(raw, 20, 16);
    let opcode = bits(raw, 15, 12);
    let size = bits(raw, 11, 10);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    let post = bit(raw, 23) != 0;

    let (mnemonic, regs) = match (l, opcode) {
        (1, 0b0000) => (Mnemonic::Ld4, 4u8),
        (0, 0b0000) => (Mnemonic::St4, 4),
        (1, 0b0010) => (Mnemonic::Ld1, 4),
        (0, 0b0010) => (Mnemonic::St1, 4),
        (1, 0b0100) => (Mnemonic::Ld3, 3),
        (0, 0b0100) => (Mnemonic::St3, 3),
        (1, 0b0110) => (Mnemonic::Ld1, 3),
        (0, 0b0110) => (Mnemonic::St1, 3),
        (1, 0b0111) => (Mnemonic::Ld1, 1),
        (0, 0b0111) => (Mnemonic::St1, 1),
        (1, 0b1000) => (Mnemonic::Ld2, 2),
        (0, 0b1000) => (Mnemonic::St2, 2),
        (1, 0b1010) => (Mnemonic::Ld1, 2),
        (0, 0b1010) => (Mnemonic::St1, 2),
        _ => return undef(vaddr, raw),
    };

    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_ldst_multi, mnemonic);
    i.arrangement = simd_arrangement(q, size);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rt);
    i.op0_imm = regs as u64; // register-list length
    i.op1_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    if post {
        if rm == 0b11111 {
            let elem_bytes = 1u32 << size;
            let q_bytes = if q != 0 { 16u32 } else { 8 };
            // Total bytes transferred ≈ regs * q_bytes (structure size)
            i.memory_offset = (regs as i32) * (q_bytes as i32);
            let _ = elem_bytes;
            i.mem_mode = MemMode::PostIndex;
        } else {
            i.memory_index = Register::gpr(true, rm, false);
            i.mem_mode = MemMode::PostIndex;
        }
    } else {
        i.mem_mode = MemMode::Offset;
    }
    i
}

/// AdvSIMD load/store single structure (+ LD*R replicate).
fn decode_simd_ldst_single(vaddr: u64, raw: u32) -> Instruction {
    let q = bit(raw, 30);
    let l = bit(raw, 22);
    let r = bit(raw, 21);
    let rm = bits(raw, 20, 16);
    let opcode = bits(raw, 15, 13);
    let s = bit(raw, 12);
    let size = bits(raw, 11, 10);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    let post = bit(raw, 23) != 0;

    // LDAP1 / STL1 (FEAT_LRCPC3): opcode=100, S=0, size=01, Rm=00001
    if opcode == 0b100 && s == 0 && size == 0b01 && r == 0 && rm == 0b00001 && !post {
        let mnemonic = if l != 0 {
            Mnemonic::Ldap1
        } else {
            Mnemonic::Stl1
        };
        let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_ldst_single, mnemonic);
        i.arrangement = Arrangement::D2;
        i.vector_index = q as u8;
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::v(rt);
        i.op0_imm = 1;
        i.op1_kind = OpKind::Memory;
        i.memory_base = Register::gpr(true, rn, true);
        i.mem_mode = MemMode::Offset;
        return i;
    }

    // Replicate forms: opcode 110 → LD1R/LD2R; opcode 111 → LD3R/LD4R (L must be 1).
    let (mnemonic, regs, replicate) = if opcode == 0b110 {
        if l == 0 {
            return undef(vaddr, raw);
        }
        if r == 0 {
            (Mnemonic::Ld1r, 1u8, true)
        } else {
            (Mnemonic::Ld2r, 2u8, true)
        }
    } else if opcode == 0b111 {
        if l == 0 {
            return undef(vaddr, raw);
        }
        if r == 0 {
            (Mnemonic::Ld3r, 3u8, true)
        } else {
            (Mnemonic::Ld4r, 4u8, true)
        }
    } else {
        // Single-element LD/ST N.
        // Capstone/LLVM structure count: n = 1 + 2*(opcode&1) + R
        // (differs from some ARM summary tables that swap the middle pair).
        let n = (1 + 2 * (opcode & 1) + r) as u8;
        let m = match (l, n) {
            (1, 1) => Mnemonic::Ld1,
            (1, 2) => Mnemonic::Ld2,
            (1, 3) => Mnemonic::Ld3,
            (1, 4) => Mnemonic::Ld4,
            (0, 1) => Mnemonic::St1,
            (0, 2) => Mnemonic::St2,
            (0, 3) => Mnemonic::St3,
            (0, 4) => Mnemonic::St4,
            _ => return undef(vaddr, raw),
        };
        // Valid opcode groups: 000/001 (.B), 010/011 (.H), 100/101 (.S/.D)
        if opcode > 0b101 {
            return undef(vaddr, raw);
        }
        (m, n, false)
    };

    // Element size / arrangement for replicate uses Q+size like multi.
    // Single-element uses size field per opcode group.
    let arr = if replicate {
        simd_arrangement(q, size)
    } else {
        match opcode {
            0b000 | 0b001 => Arrangement::B16, // index into .B — formatter may refine
            0b010 | 0b011 => {
                if q != 0 {
                    Arrangement::H8
                } else {
                    Arrangement::H4
                }
            }
            0b100 | 0b101 if size & 1 == 0 => {
                if q != 0 {
                    Arrangement::S4
                } else {
                    Arrangement::S2
                }
            }
            0b100 | 0b101 => {
                if q != 0 {
                    Arrangement::D2
                } else {
                    Arrangement::D1
                }
            }
            _ => simd_arrangement(q, size),
        }
    };

    // Vector index for single-element forms
    let index = match opcode {
        0b000 | 0b001 => ((q << 3) | (s << 2) | size) as u8, // .B
        0b010 | 0b011 => ((q << 2) | (s << 1) | (size >> 1)) as u8, // .H
        0b100 | 0b101 if size & 1 == 0 => ((q << 1) | s) as u8, // .S
        0b100 | 0b101 => q as u8,                               // .D
        _ => 0,
    };

    let mut i = Instruction::with_meta(vaddr, raw, Code::Simd_ldst_single, mnemonic);
    i.arrangement = arr;
    i.vector_index = if replicate { 0 } else { index };
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::v(rt);
    i.op0_imm = regs as u64;
    i.op1_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    if post {
        if rm == 0b11111 {
            let scale = if replicate {
                1u32 << size
            } else {
                match opcode {
                    0b000 | 0b001 => 1,
                    0b010 | 0b011 => 2,
                    _ if size & 1 == 0 => 4,
                    _ => 8,
                }
            };
            i.memory_offset = (regs as i32) * (scale as i32);
            i.mem_mode = MemMode::PostIndex;
        } else {
            i.memory_index = Register::gpr(true, rm, false);
            i.mem_mode = MemMode::PostIndex;
        }
    } else {
        i.mem_mode = MemMode::Offset;
    }
    i
}





fn decode_rcw(vaddr: u64, raw: u32) -> Instruction {
    let size = bits(raw, 31, 30);
    let soft = size & 1 != 0; // RCWS*
    let a = bit(raw, 23);
    let r = bit(raw, 22);
    let rs = bits(raw, 20, 16);
    let o3 = bit(raw, 15);
    let opc = bits(raw, 14, 12);
    let rt2_bits = bits(raw, 11, 10);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);

    // CAS / CASP: bits[11:10]=10/11, o3=0, opc=0
    let mnemonic = if o3 == 0 && opc == 0 && matches!(rt2_bits, 0b10 | 0b11) {
        let pair = rt2_bits == 0b11;
        match (soft, pair, a, r) {
            (false, false, 0, 0) => Mnemonic::Rcwcas,
            (false, false, 1, 0) => Mnemonic::Rcwcasa,
            (false, false, 1, 1) => Mnemonic::Rcwcasal,
            (false, false, 0, 1) => Mnemonic::Rcwcasl,
            (false, true, 0, 0) => Mnemonic::Rcwcasp,
            (false, true, 1, 0) => Mnemonic::Rcwcaspa,
            (false, true, 1, 1) => Mnemonic::Rcwcaspal,
            (false, true, 0, 1) => Mnemonic::Rcwcaspl,
            (true, false, 0, 0) => Mnemonic::Rcwscas,
            (true, false, 1, 0) => Mnemonic::Rcwscasa,
            (true, false, 1, 1) => Mnemonic::Rcwscasal,
            (true, false, 0, 1) => Mnemonic::Rcwscasl,
            (true, true, 0, 0) => Mnemonic::Rcwscasp,
            (true, true, 1, 0) => Mnemonic::Rcwscaspa,
            (true, true, 1, 1) => Mnemonic::Rcwscaspal,
            (true, true, 0, 1) => Mnemonic::Rcwscaspl,
            _ => Mnemonic::Rcwcas,
        }
    } else if o3 != 0 && rt2_bits == 0b00 {
        // CLR/SET/SWP (+ pair via encoding space — Capstone pair forms also hit here
        // when routed from 011001; pair distinguished by bits[29:27]!=111)
        let pair = bits(raw, 29, 27) != 0b111;
        match (opc, soft, pair, a, r) {
            // CLR opc=1
            (0b001, false, false, 0, 0) => Mnemonic::Rcwclr,
            (0b001, false, false, 1, 0) => Mnemonic::Rcwclra,
            (0b001, false, false, 1, 1) => Mnemonic::Rcwclral,
            (0b001, false, false, 0, 1) => Mnemonic::Rcwclrl,
            (0b001, false, true, 0, 0) => Mnemonic::Rcwclrp,
            (0b001, false, true, 1, 0) => Mnemonic::Rcwclrpa,
            (0b001, false, true, 1, 1) => Mnemonic::Rcwclrpal,
            (0b001, false, true, 0, 1) => Mnemonic::Rcwclrpl,
            (0b001, true, false, 0, 0) => Mnemonic::Rcwsclr,
            (0b001, true, false, 1, 0) => Mnemonic::Rcwsclra,
            (0b001, true, false, 1, 1) => Mnemonic::Rcwsclral,
            (0b001, true, false, 0, 1) => Mnemonic::Rcwsclrl,
            (0b001, true, true, 0, 0) => Mnemonic::Rcwsclrp,
            (0b001, true, true, 1, 0) => Mnemonic::Rcwsclrpa,
            (0b001, true, true, 1, 1) => Mnemonic::Rcwsclrpal,
            (0b001, true, true, 0, 1) => Mnemonic::Rcwsclrpl,
            // SWP opc=2
            (0b010, false, false, 0, 0) => Mnemonic::Rcwswp,
            (0b010, false, false, 1, 0) => Mnemonic::Rcwswpa,
            (0b010, false, false, 1, 1) => Mnemonic::Rcwswpal,
            (0b010, false, false, 0, 1) => Mnemonic::Rcwswpl,
            (0b010, false, true, 0, 0) => Mnemonic::Rcwswpp,
            (0b010, false, true, 1, 0) => Mnemonic::Rcwswppa,
            (0b010, false, true, 1, 1) => Mnemonic::Rcwswppal,
            (0b010, false, true, 0, 1) => Mnemonic::Rcwswppl,
            (0b010, true, false, 0, 0) => Mnemonic::Rcwsswp,
            (0b010, true, false, 1, 0) => Mnemonic::Rcwsswpa,
            (0b010, true, false, 1, 1) => Mnemonic::Rcwsswpal,
            (0b010, true, false, 0, 1) => Mnemonic::Rcwsswpl,
            (0b010, true, true, 0, 0) => Mnemonic::Rcwsswpp,
            (0b010, true, true, 1, 0) => Mnemonic::Rcwsswppa,
            (0b010, true, true, 1, 1) => Mnemonic::Rcwsswppal,
            (0b010, true, true, 0, 1) => Mnemonic::Rcwsswppl,
            // SET opc=3
            (0b011, false, false, 0, 0) => Mnemonic::Rcwset,
            (0b011, false, false, 1, 0) => Mnemonic::Rcwseta,
            (0b011, false, false, 1, 1) => Mnemonic::Rcwsetal,
            (0b011, false, false, 0, 1) => Mnemonic::Rcwsetl,
            (0b011, false, true, 0, 0) => Mnemonic::Rcwsetp,
            (0b011, false, true, 1, 0) => Mnemonic::Rcwsetpa,
            (0b011, false, true, 1, 1) => Mnemonic::Rcwsetpal,
            (0b011, false, true, 0, 1) => Mnemonic::Rcwsetpl,
            (0b011, true, false, 0, 0) => Mnemonic::Rcwsset,
            (0b011, true, false, 1, 0) => Mnemonic::Rcwsseta,
            (0b011, true, false, 1, 1) => Mnemonic::Rcwssetal,
            (0b011, true, false, 0, 1) => Mnemonic::Rcwssetl,
            (0b011, true, true, 0, 0) => Mnemonic::Rcwssetp,
            (0b011, true, true, 1, 0) => Mnemonic::Rcwssetpa,
            (0b011, true, true, 1, 1) => Mnemonic::Rcwssetpal,
            (0b011, true, true, 0, 1) => Mnemonic::Rcwssetpl,
            _ => return undef(vaddr, raw),
        }
    } else {
        return undef(vaddr, raw);
    };

    let mut i = Instruction::with_meta(vaddr, raw, Code::Ldxr, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::x(rs);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::x(rt);
    i.op2_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.mem_mode = MemMode::Offset;
    i
}

fn decode_stilp_ldiapp(vaddr: u64, raw: u32) -> Instruction {
    let size = bits(raw, 31, 30);
    let opc = bits(raw, 23, 22);
    let imm9 = bits(raw, 20, 12);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    // Rt2 is encoded in bits[20:16] overlapping imm for some forms — Capstone uses
    // a pair of GPRs; approximate Rt2 from bits[20:16] when present in post/pre forms.
    let rt2 = bits(raw, 20, 16);
    let offset = sign_extend(imm9 as u64, 9) as i32;
    // mode via bits of opc / post indexing: Capstone stilp pre (#imm)! and offset
    let mnemonic = if opc & 1 != 0 {
        Mnemonic::Ldiapp
    } else {
        Mnemonic::Stilp
    };
    let sf = size >= 3;
    let mut i = Instruction::with_meta(vaddr, raw, Code::Ldp, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf || size == 2, rt, false);
    i.op1_kind = OpKind::Register;
    // For stilp/ldiapp Capstone: Wt1, Wt2 — second reg often from imm high bits
    // Encoding (FEAT_LRCPC3): Rt2 in bits[20:16] for the pair
    i.op1_reg = Register::gpr(sf || size == 2, rt2, false);
    if size < 3 {
        i.op0_reg = Register::gpr(false, rt, false);
        i.op1_reg = Register::gpr(false, rt2, false);
    }
    i.op2_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.memory_offset = offset;
    // bit23 distinguishes some writeback — treat opc bit1 / signed
    i.mem_mode = if bit(raw, 11) != 0 {
        MemMode::PreIndex
    } else if bits(raw, 23, 22) == 0b01 || (opc == 0b01 && offset != 0) {
        MemMode::PostIndex
    } else {
        MemMode::Offset
    };
    i
}

fn decode_atomic(vaddr: u64, raw: u32) -> Instruction {
    let size = bits(raw, 31, 30);
    let a = bit(raw, 23);
    let r = bit(raw, 22);
    let rs = bits(raw, 20, 16);
    let o3 = bit(raw, 15);
    let opc = bits(raw, 14, 12);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    let sf = size == 3;
    let store = rt == 31 && o3 == 0; // Capstone ST* aliases when Rt=XZR

    // RCW/RCWS (non-pair) share this encoding with size=0/1, o3=1, opc=1/2/3
    if size <= 1 && o3 != 0 && matches!(opc, 0b001 | 0b010 | 0b011) {
        return decode_rcw(vaddr, raw);
    }

    // LD64B / ST64B / ST64BV*: Rs=XZR, o3=1, opc≠000 (000 is LDAPR alias of SWP)
    if rs == 31 && o3 != 0 {
        if let Some(mnemonic) = match opc {
            0b001 => Some(Mnemonic::St64b),
            0b010 => Some(Mnemonic::St64bv),
            0b011 => Some(Mnemonic::St64bv0),
            0b101 => Some(Mnemonic::Ld64b),
            _ => None,
        } {
            let mut i = Instruction::with_meta(vaddr, raw, Code::Ldxr, mnemonic);
            i.op_count = 2;
            i.op0_kind = OpKind::Register;
            i.op0_reg = Register::x(rt);
            i.op1_kind = OpKind::Memory;
            i.memory_base = Register::gpr(true, rn, true);
            i.mem_mode = MemMode::Offset;
            let _ = (a, r, store, sf);
            return i;
        }
    }
    let mnemonic = if o3 != 0 {
        // SWP* — Rs=XZR + acquire aliases to LDAPR (Capstone)
        if rs == 31 && opc == 0 {
            Mnemonic::Ldapr
        } else {
            match (size, a, r) {
                (0, 0, 0) => Mnemonic::Swpb,
                (0, 1, 0) => Mnemonic::Swpab,
                (0, 1, 1) => Mnemonic::Swpalb,
                (0, 0, 1) => Mnemonic::Swplb,
                (1, 0, 0) => Mnemonic::Swph,
                (1, 1, 0) => Mnemonic::Swpah,
                (1, 1, 1) => Mnemonic::Swpalh,
                (1, 0, 1) => Mnemonic::Swplh,
                (_, 0, 0) => Mnemonic::Swp,
                (_, 1, 0) => Mnemonic::Swpa,
                (_, 0, 1) => Mnemonic::Swpl,
                _ => Mnemonic::Swpal,
            }
        }
    } else {
        let base = match opc {
            0b000 => {
                if store {
                    Mnemonic::Stadd
                } else {
                    Mnemonic::Ldadd
                }
            }
            0b001 => {
                if store {
                    Mnemonic::Stclr
                } else {
                    Mnemonic::Ldclr
                }
            }
            0b010 => {
                if store {
                    Mnemonic::Steor
                } else {
                    Mnemonic::Ldeor
                }
            }
            0b011 => {
                if store {
                    Mnemonic::Stset
                } else {
                    Mnemonic::Ldset
                }
            }
            0b100 => {
                if store {
                    Mnemonic::Stsmax
                } else {
                    Mnemonic::Ldsmax
                }
            }
            0b101 => {
                if store {
                    Mnemonic::Stsmin
                } else {
                    Mnemonic::Ldsmin
                }
            }
            0b110 => {
                if store {
                    Mnemonic::Stumax
                } else {
                    Mnemonic::Ldumax
                }
            }
            _ => {
                if store {
                    Mnemonic::Stumin
                } else {
                    Mnemonic::Ldumin
                }
            }
        };
        // Apply acquire/release suffixes for the common Capstone forms
        match (base, a, r) {
            (Mnemonic::Ldadd, 1, 0) => Mnemonic::Ldadda,
            (Mnemonic::Ldadd, 0, 1) => Mnemonic::Ldaddl,
            (Mnemonic::Ldadd, 1, 1) => Mnemonic::Ldaddal,
            (Mnemonic::Ldclr, 0, 1) => Mnemonic::Ldclrl,
            (Mnemonic::Ldclr, 1, 0) => Mnemonic::Ldclra,
            (Mnemonic::Ldclr, 1, 1) => Mnemonic::Ldclral,
            (Mnemonic::Ldeor, 0, 1) => Mnemonic::Ldeorl,
            (Mnemonic::Ldeor, 1, 0) => Mnemonic::Ldeora,
            (Mnemonic::Ldeor, 1, 1) => Mnemonic::Ldeoral,
            (Mnemonic::Ldset, 0, 1) => Mnemonic::Ldsetl,
            (Mnemonic::Ldset, 1, 0) => Mnemonic::Ldseta,
            (Mnemonic::Ldset, 1, 1) => Mnemonic::Ldsetal,
            (Mnemonic::Ldsmax, 1, 0) => Mnemonic::Ldsmaxa,
            (Mnemonic::Ldsmax, 0, 1) => Mnemonic::Ldsmaxl,
            (Mnemonic::Ldsmax, 1, 1) => Mnemonic::Ldsmaxal,
            (Mnemonic::Ldsmin, 1, 0) => Mnemonic::Ldsmina,
            (Mnemonic::Ldsmin, 0, 1) => Mnemonic::Ldsminl,
            (Mnemonic::Ldsmin, 1, 1) => Mnemonic::Ldsminal,
            (Mnemonic::Ldumax, 1, 0) => Mnemonic::Ldumaxa,
            (Mnemonic::Ldumax, 0, 1) => Mnemonic::Ldumaxl,
            (Mnemonic::Ldumax, 1, 1) => Mnemonic::Ldumaxal,
            (Mnemonic::Ldumin, 1, 0) => Mnemonic::Ldumina,
            (Mnemonic::Ldumin, 0, 1) => Mnemonic::Lduminl,
            (Mnemonic::Ldumin, 1, 1) => Mnemonic::Lduminal,
            (Mnemonic::Stset, 0, 1) => Mnemonic::Stsetl,
            (Mnemonic::Steor, 0, 1) => Mnemonic::Steorl,
            (Mnemonic::Stsmin, 0, 1) => Mnemonic::Stsminl,
            (Mnemonic::Stsmax, 0, 1) => Mnemonic::Stsmaxl,
            _ => base,
        }
    };

    let mut i = Instruction::with_meta(vaddr, raw, Code::Str_imm, mnemonic);
    if mnemonic == Mnemonic::Ldapr {
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(size >= 3, rt, false);
        if size < 3 {
            i.op0_reg = Register::gpr(false, rt, false);
        }
        i.op1_kind = OpKind::Memory;
    } else if store {
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf || size == 2, rs, false);
        i.op1_kind = OpKind::Memory;
    } else {
        i.op_count = 3;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf || size == 2, rs, false);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf || size == 2, rt, false);
        i.op2_kind = OpKind::Memory;
    }
    // size 0/1 are W for byte/half; Capstone still uses w/x based on size>=2
    if size < 2 {
        i.op0_reg = Register::gpr(false, rs, false);
        if !store {
            i.op1_reg = Register::gpr(false, rt, false);
        }
    } else if size == 2 {
        i.op0_reg = Register::gpr(false, rs, false);
        if !store {
            i.op1_reg = Register::gpr(false, rt, false);
        }
    }
    i.memory_base = Register::gpr(true, rn, true);
    i.mem_mode = MemMode::Offset;
    i
}

fn decode_ldra(vaddr: u64, raw: u32) -> Instruction {
    let m = bit(raw, 23);
    let s = bit(raw, 22);
    let imm9 = bits(raw, 20, 12);
    let w = bit(raw, 11);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    let offset = (sign_extend(imm9 as u64, 9) as i32) << 3;
    let mnemonic = if m != 0 { Mnemonic::Ldrab } else { Mnemonic::Ldraa };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Ldr_imm, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(true, rt, false);
    i.op1_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.memory_offset = offset;
    i.mem_mode = if w != 0 { MemMode::PreIndex } else { MemMode::Offset };
    let _ = s;
    i
}

fn decode_mte_stg(vaddr: u64, raw: u32) -> Instruction {
    let opc = bits(raw, 23, 22);
    let imm9 = bits(raw, 20, 12);
    let mode = bits(raw, 11, 10);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    // bits[11:10]==00: STZGM / LDG / STGM / LDGM
    let mnemonic = if mode == 0b00 {
        match opc {
            0b00 => Mnemonic::Stzgm,
            0b01 => Mnemonic::Ldg,
            0b10 => Mnemonic::Stgm,
            _ => Mnemonic::Ldgm,
        }
    } else {
        match opc {
            0b00 => Mnemonic::Stg,
            0b01 => Mnemonic::Stzg,
            0b10 => Mnemonic::St2g,
            _ => Mnemonic::Stz2g,
        }
    };
    let offset = (sign_extend(imm9 as u64, 9) as i32) << 4;
    let mem_mode = match mode {
        0b01 => MemMode::PostIndex,
        0b11 => MemMode::PreIndex,
        _ => MemMode::Offset, // 00 / 10 signed offset forms
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Str_imm, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(true, rt, true);
    i.op1_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.memory_offset = offset;
    i.mem_mode = mem_mode;
    i
}

fn decode_stgp(vaddr: u64, raw: u32) -> Instruction {
    let imm7 = bits(raw, 21, 15);
    let rt2 = bits(raw, 14, 10);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    let mode = bits(raw, 24, 23);
    let offset = (sign_extend(imm7 as u64, 7) as i32) << 4;
    let mem_mode = match mode {
        0b01 => MemMode::PostIndex,
        0b11 => MemMode::PreIndex,
        _ => MemMode::Offset,
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Stp, Mnemonic::Stgp);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(true, rt, false);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(true, rt2, false);
    i.op2_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.memory_offset = offset;
    i.mem_mode = mem_mode;
    i
}

fn decode_ldapur_stlur(vaddr: u64, raw: u32) -> Instruction {
    let size = bits(raw, 31, 30);
    let v = bit(raw, 26);
    let opc = bits(raw, 23, 22);
    let imm9 = bits(raw, 20, 12);
    let rn = bits(raw, 9, 5);
    let rt = bits(raw, 4, 0);
    let offset = sign_extend(imm9 as u64, 9) as i32;

    if v != 0 {
        // SIMD/FP LDAPUR / STLUR — Capstone mnemonic is ldapur/stlur (not *b/*h)
        let bytes = match (size, opc) {
            (0, 0b00) | (0, 0b01) => 1u32, // B
            (1, 0b00) | (1, 0b01) => 2,     // H
            (2, 0b00) | (2, 0b01) => 4,     // S
            (3, 0b00) | (3, 0b01) => 8,     // D
            (0, 0b11) | (0, 0b10) => 16,    // Q (opc 10/11)
            _ => return undef(vaddr, raw),
        };
        let mnemonic = if opc & 1 == 0 {
            Mnemonic::Stlur
        } else {
            Mnemonic::Ldapur
        };
        let mut i = Instruction::with_meta(vaddr, raw, Code::Ldr_imm, mnemonic);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::fp_sized(bytes, rt);
        i.op1_kind = OpKind::Memory;
        i.memory_base = Register::gpr(true, rn, true);
        i.memory_offset = offset;
        i.mem_mode = MemMode::Offset;
        return i;
    }

    let (mnemonic, sf) = match (size, opc) {
        (0, 0b00) => (Mnemonic::Stlurb, false),
        (0, 0b01) => (Mnemonic::Ldapurb, false),
        (0, 0b10) => (Mnemonic::Ldapursb, true),
        (0, 0b11) => (Mnemonic::Ldapursb, false),
        (1, 0b00) => (Mnemonic::Stlurh, false),
        (1, 0b01) => (Mnemonic::Ldapurh, false),
        (1, 0b10) => (Mnemonic::Ldapursh, true),
        (1, 0b11) => (Mnemonic::Ldapursh, false),
        (2, 0b00) => (Mnemonic::Stlur, false),
        (2, 0b01) => (Mnemonic::Ldapur, false),
        (2, 0b10) => (Mnemonic::Ldapursw, true),
        (3, 0b00) => (Mnemonic::Stlur, true),
        (3, 0b01) => (Mnemonic::Ldapur, true),
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Ldr_imm, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rt, false);
    i.op1_kind = OpKind::Memory;
    i.memory_base = Register::gpr(true, rn, true);
    i.memory_offset = offset;
    i.mem_mode = MemMode::Offset;
    i
}
