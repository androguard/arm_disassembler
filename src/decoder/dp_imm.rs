//! Data-processing — immediate (elfbrowser `dp_imm.rs` coverage).

use crate::enums::{Code, OpKind, Register, ShiftKind};
use crate::helpers::{bit, bits, decode_bitmask, sign_extend};
use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;

use super::undef;

pub(super) fn decode(vaddr: u64, raw: u32) -> Instruction {
    match bits(raw, 25, 23) {
        0b000 | 0b001 => decode_pc_rel(vaddr, raw),
        0b010 | 0b011 => decode_add_sub_imm(vaddr, raw),
        0b100 => decode_logic_imm(vaddr, raw),
        0b101 => decode_mov_wide(vaddr, raw),
        0b110 => decode_bitfield(vaddr, raw),
        0b111 => decode_extract(vaddr, raw),
        _ => undef(vaddr, raw),
    }
}

fn decode_pc_rel(vaddr: u64, raw: u32) -> Instruction {
    let op = bit(raw, 31);
    let immlo = bits(raw, 30, 29) as u64;
    let immhi = bits(raw, 23, 5) as u64;
    let rd = bits(raw, 4, 0);
    let imm = sign_extend((immhi << 2) | immlo, 21);
    let (code, mnemonic, target) = if op == 0 {
        (Code::Adr, Mnemonic::Adr, (vaddr as i64).wrapping_add(imm) as u64)
    } else {
        (
            Code::Adrp,
            Mnemonic::Adrp,
            ((vaddr as i64) & !0xFFF).wrapping_add(imm << 12) as u64,
        )
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(true, rd, false);
    i.op1_kind = OpKind::Immediate;
    i.op1_imm = target;
    i.near_branch_target = target;
    i
}

fn decode_add_sub_imm(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let op = bit(raw, 30);
    let s = bit(raw, 29);
    // SMAX/UMAX/SMIN/UMIN (immediate): bit23=1, bits[22:21]=10
    if bit(raw, 23) != 0 && bits(raw, 22, 21) == 0b10 && op == 0 && s == 0 {
        let mnemonic = match bits(raw, 19, 18) {
            0b00 => Mnemonic::Smax,
            0b01 => Mnemonic::Umax,
            0b10 => Mnemonic::Smin,
            _ => Mnemonic::Umin,
        };
        let imm = bits(raw, 15, 10) as u64;
        let rn = bits(raw, 9, 5);
        let rd = bits(raw, 4, 0);
        let mut i = Instruction::with_meta(vaddr, raw, Code::Add_imm, mnemonic);
        i.op_count = 3;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rd, false);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rn, false);
        i.op2_kind = OpKind::Immediate;
        i.op2_imm = imm;
        return i;
    }
    // ADDG/SUBG (MTE): bit23=1 and bits[15:14]=00 (not min/max imm)
    if bit(raw, 23) != 0 && bits(raw, 15, 14) == 0 {
        let uimm6 = bits(raw, 21, 16);
        let uimm4 = bits(raw, 13, 10);
        let rn = bits(raw, 9, 5);
        let rd = bits(raw, 4, 0);
        let mnemonic = if op == 0 {
            Mnemonic::Addg
        } else {
            Mnemonic::Subg
        };
        let mut i = Instruction::with_meta(vaddr, raw, Code::Add_imm, mnemonic);
        i.op_count = 4;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(true, rd, true);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(true, rn, true);
        i.op2_kind = OpKind::Immediate;
        i.op2_imm = (uimm6 as u64) << 4; // tag offset scale
        i.op3_kind = OpKind::Immediate;
        i.op3_imm = uimm4 as u64;
        let _ = s;
        return i;
    }
    let sh = bit(raw, 22);
    let imm12 = bits(raw, 21, 10) as u64;
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let imm = if sh != 0 { imm12 << 12 } else { imm12 };

    if op == 0 && s == 0 && imm == 0 && (rd == 31 || rn == 31) {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Add_imm, Mnemonic::Mov);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rd, true);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rn, true);
        return i;
    }
    if op == 1 && s == 1 && rd == 31 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Subs_imm, Mnemonic::Cmp);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rn, true);
        i.op1_kind = OpKind::Immediate;
        i.op1_imm = imm;
        return i;
    }
    if op == 0 && s == 1 && rd == 31 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Adds_imm, Mnemonic::Cmn);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rn, true);
        i.op1_kind = OpKind::Immediate;
        i.op1_imm = imm;
        return i;
    }

    let (code, mnemonic) = match (op, s) {
        (0, 0) => (Code::Add_imm, Mnemonic::Add),
        (0, 1) => (Code::Adds_imm, Mnemonic::Adds),
        (1, 0) => (Code::Sub_imm, Mnemonic::Sub),
        _ => (Code::Subs_imm, Mnemonic::Subs),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, true);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(sf, rn, true);
    i.op2_kind = OpKind::Immediate;
    i.op2_imm = imm;
    i
}

fn decode_logic_imm(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let opc = bits(raw, 30, 29);
    let n = bit(raw, 22);
    let immr = bits(raw, 21, 16);
    let imms = bits(raw, 15, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let Some(imm) = decode_bitmask(sf, n, imms, immr) else {
        return undef(vaddr, raw);
    };

    // Capstone MC prefers ORR over MOV for bitmask ORR with Rn=ZR.
    if opc == 0b11 && rd == 31 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Ands_imm, Mnemonic::Tst);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rn, false);
        i.op1_kind = OpKind::Immediate;
        i.op1_imm = imm;
        return i;
    }

    let (code, mnemonic) = match opc {
        0b00 => (Code::And_imm, Mnemonic::And),
        0b01 => (Code::Orr_imm, Mnemonic::Orr),
        0b10 => (Code::Eor_imm, Mnemonic::Eor),
        _ => (Code::Ands_imm, Mnemonic::Ands),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, true);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(sf, rn, false);
    i.op2_kind = OpKind::Immediate;
    i.op2_imm = imm;
    i
}

fn decode_mov_wide(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let opc = bits(raw, 30, 29);
    let hw = bits(raw, 22, 21);
    let imm16 = bits(raw, 20, 5);
    let rd = bits(raw, 4, 0);
    if !sf && hw > 1 {
        return undef(vaddr, raw);
    }
    let (code, mut mnemonic) = match opc {
        0b00 => (Code::Movn, Mnemonic::Movn),
        0b10 => (Code::Movz, Mnemonic::Movz),
        0b11 => (Code::Movk, Mnemonic::Movk),
        _ => return undef(vaddr, raw),
    };
    // Capstone/ARM prefer MOV alias for MOVZ/MOVN when representable as a single mov.
    let full_imm = (imm16 as u64) << (hw * 16);
    if mnemonic == Mnemonic::Movz {
        mnemonic = Mnemonic::Mov;
    } else if mnemonic == Mnemonic::Movn {
        // MOV alias of MOVN: imm = ~ (imm16 << hw*16)
        mnemonic = Mnemonic::Mov;
    }
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, false);
    i.op1_kind = OpKind::Immediate;
    if code == Code::Movn && mnemonic == Mnemonic::Mov {
        let mask = if sf { u64::MAX } else { 0xFFFF_FFFF };
        i.op1_imm = (!full_imm) & mask;
    } else if mnemonic == Mnemonic::Mov {
        i.op1_imm = full_imm;
    } else {
        i.op1_imm = imm16 as u64;
        if hw != 0 {
            i.shift_kind = ShiftKind::Lsl;
            i.shift_amount = (hw * 16) as u8;
        }
    }
    i
}

fn decode_bitfield(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let opc = bits(raw, 30, 29);
    let immr = bits(raw, 21, 16);
    let imms = bits(raw, 15, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let width = if sf { 64u32 } else { 32 };

    let (code, base) = match opc {
        0b00 => (Code::Sbfm, Mnemonic::Sbfm),
        0b01 => (Code::Bfm, Mnemonic::Bfm),
        0b10 => (Code::Ubfm, Mnemonic::Ubfm),
        _ => return undef(vaddr, raw),
    };

    let mnemonic = match base {
        Mnemonic::Ubfm if imms != width - 1 && immr == imms + 1 => Mnemonic::Lsl,
        Mnemonic::Ubfm if imms == width - 1 => Mnemonic::Lsr,
        Mnemonic::Sbfm if imms == width - 1 => Mnemonic::Asr,
        other => other,
    };

    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, false);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(sf, rn, false);
    if matches!(mnemonic, Mnemonic::Lsl | Mnemonic::Lsr | Mnemonic::Asr) {
        i.op_count = 3;
        i.op2_kind = OpKind::Immediate;
        i.op2_imm = match mnemonic {
            Mnemonic::Lsl => ((width - immr) % width) as u64,
            _ => immr as u64,
        };
    } else {
        i.op_count = 4;
        i.op2_kind = OpKind::Immediate;
        i.op2_imm = immr as u64;
        i.op3_kind = OpKind::Immediate;
        i.op3_imm = imms as u64;
    }
    i
}

fn decode_extract(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let rm = bits(raw, 20, 16);
    let imms = bits(raw, 15, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let mnemonic = if rn == rm { Mnemonic::Ror } else { Mnemonic::Extr };
    let mut i = Instruction::with_meta(vaddr, raw, Code::Extr, mnemonic);
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, false);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(sf, rn, false);
    if rn == rm {
        i.op_count = 3;
        i.op2_kind = OpKind::Immediate;
        i.op2_imm = imms as u64;
    } else {
        i.op_count = 4;
        i.op2_kind = OpKind::Register;
        i.op2_reg = Register::gpr(sf, rm, false);
        i.op3_kind = OpKind::Immediate;
        i.op3_imm = imms as u64;
    }
    i
}
