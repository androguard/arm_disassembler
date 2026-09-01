//! Data-processing — register (elfbrowser `dp_reg.rs` full coverage).

use crate::enums::{Code, Condition, ExtendKind, OpKind, Register, ShiftKind};
use crate::helpers::{bit, bits};
use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;

use super::undef;

pub(super) fn decode(vaddr: u64, raw: u32) -> Instruction {
    if bits(raw, 28, 24) == 0b01010 {
        return decode_logic_shifted(vaddr, raw);
    }
    if bits(raw, 28, 24) == 0b01011 && bit(raw, 21) == 0 {
        return decode_add_sub_shifted(vaddr, raw);
    }
    if bits(raw, 28, 24) == 0b01011 && bit(raw, 21) == 1 {
        return decode_add_sub_extended(vaddr, raw);
    }
    // ADC / SBC
    if bits(raw, 28, 21) == 0b11010000 {
        return decode_adc_sbc(vaddr, raw);
    }
    if bits(raw, 28, 21) == 0b11010010 {
        return decode_ccmp(vaddr, raw);
    }
    if bits(raw, 28, 21) == 0b11010100 {
        return decode_csel(vaddr, raw);
    }
    // Data-processing 1-source: bit30=1, bits[28:21]=11010110
    // Data-processing 2-source: bit30=0, bits[28:21]=11010110
    if bits(raw, 28, 21) == 0b11010110 {
        if bit(raw, 30) == 1 {
            return decode_dp_1src(vaddr, raw);
        }
        return decode_dp_2src(vaddr, raw);
    }
    if bits(raw, 28, 24) == 0b11011 {
        return decode_dp_3src(vaddr, raw);
    }
    undef(vaddr, raw)
}

fn decode_logic_shifted(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let opc = bits(raw, 30, 29);
    let shift = ShiftKind::from_u32(bits(raw, 23, 22));
    let n = bit(raw, 21);
    let rm = bits(raw, 20, 16);
    let imm6 = bits(raw, 15, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);

    if opc == 0b01 && n == 0 && rn == 31 && shift == ShiftKind::Lsl && imm6 == 0 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Orr_shift, Mnemonic::Mov);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rd, false);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rm, false);
        return i;
    }
    if opc == 0b01 && n == 1 && rn == 31 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Orn_shift, Mnemonic::Mvn);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rd, false);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rm, false);
        i.shift_kind = if imm6 != 0 { shift } else { ShiftKind::None };
        i.shift_amount = imm6 as u8;
        return i;
    }
    if opc == 0b11 && n == 0 && rd == 31 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Ands_shift, Mnemonic::Tst);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rn, false);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rm, false);
        i.shift_kind = if imm6 != 0 { shift } else { ShiftKind::None };
        i.shift_amount = imm6 as u8;
        return i;
    }

    let (code, mnemonic) = match (opc, n) {
        (0b00, 0) => (Code::And_shift, Mnemonic::And),
        (0b00, 1) => (Code::Bic_shift, Mnemonic::Bic),
        (0b01, 0) => (Code::Orr_shift, Mnemonic::Orr),
        (0b01, 1) => (Code::Orn_shift, Mnemonic::Orn),
        (0b10, 0) => (Code::Eor_shift, Mnemonic::Eor),
        (0b10, 1) => (Code::Eon_shift, Mnemonic::Eon),
        (0b11, 0) => (Code::Ands_shift, Mnemonic::Ands),
        (0b11, 1) => (Code::Bics_shift, Mnemonic::Bics),
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, false);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(sf, rn, false);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::gpr(sf, rm, false);
    i.shift_kind = if imm6 != 0 { shift } else { ShiftKind::None };
    i.shift_amount = imm6 as u8;
    i
}

fn decode_add_sub_shifted(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let op = bit(raw, 30);
    let s = bit(raw, 29);
    let shift = ShiftKind::from_u32(bits(raw, 23, 22));
    let rm = bits(raw, 20, 16);
    let imm6 = bits(raw, 15, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);

    if op == 1 && s == 1 && rd == 31 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Subs_shift, Mnemonic::Cmp);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rn, false);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rm, false);
        i.shift_kind = if imm6 != 0 { shift } else { ShiftKind::None };
        i.shift_amount = imm6 as u8;
        return i;
    }
    if op == 1 && s == 0 && rn == 31 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Sub_shift, Mnemonic::Neg);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rd, false);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rm, false);
        i.shift_kind = if imm6 != 0 { shift } else { ShiftKind::None };
        i.shift_amount = imm6 as u8;
        return i;
    }
    if op == 1 && s == 1 && rn == 31 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Subs_shift, Mnemonic::Negs);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rd, false);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rm, false);
        return i;
    }

    let (code, mnemonic) = match (op, s) {
        (0, 0) => (Code::Add_shift, Mnemonic::Add),
        (0, 1) => (Code::Adds_shift, Mnemonic::Adds),
        (1, 0) => (Code::Sub_shift, Mnemonic::Sub),
        _ => (Code::Subs_shift, Mnemonic::Subs),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, false);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(sf, rn, false);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::gpr(sf, rm, false);
    i.shift_kind = if imm6 != 0 { shift } else { ShiftKind::None };
    i.shift_amount = imm6 as u8;
    i
}

fn decode_add_sub_extended(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let op = bit(raw, 30);
    let s = bit(raw, 29);
    let rm = bits(raw, 20, 16);
    let option = bits(raw, 15, 13);
    let imm3 = bits(raw, 12, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);

    // CMP / CMN (extended register) aliases
    if s == 1 && rd == 31 {
        let mut i = Instruction::with_meta(
            vaddr,
            raw,
            if op == 1 {
                Code::Subs_ext
            } else {
                Code::Adds_ext
            },
            if op == 1 {
                Mnemonic::Cmp
            } else {
                Mnemonic::Cmn
            },
        );
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::gpr(sf, rn, true);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(option == 3 || option == 7 || sf, rm, false);
        i.extend_kind = ExtendKind::from_u32(option);
        i.extend_amount = imm3 as u8;
        return i;
    }

    let (code, mnemonic) = match (op, s) {
        (0, 0) => (Code::Add_ext, Mnemonic::Add),
        (0, 1) => (Code::Adds_ext, Mnemonic::Adds),
        (1, 0) => (Code::Sub_ext, Mnemonic::Sub),
        _ => (Code::Subs_ext, Mnemonic::Subs),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, true);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(sf, rn, true);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::gpr(sf || option == 3 || option == 7, rm, false);
    i.extend_kind = ExtendKind::from_u32(option);
    i.extend_amount = imm3 as u8;
    i
}

fn decode_adc_sbc(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let op = bit(raw, 30);
    let s = bit(raw, 29);
    let rm = bits(raw, 20, 16);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let (code, mnemonic) = match (op, s) {
        (0, 0) => (Code::Adc, Mnemonic::Adc),
        (0, 1) => (Code::Adcs, Mnemonic::Adcs),
        (1, 0) => (Code::Sbc, Mnemonic::Sbc),
        _ => (Code::Sbcs, Mnemonic::Sbcs),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, false);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(sf, rn, false);
    i.op2_kind = OpKind::Register;
    i.op2_reg = Register::gpr(sf, rm, false);
    i
}

fn decode_ccmp(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let op = bit(raw, 30); // 0=CCMN 1=CCMP
    let rn = bits(raw, 9, 5);
    let nzcv = bits(raw, 3, 0);
    let cond = Condition::from_u32(bits(raw, 15, 12));
    let is_imm = bit(raw, 11) != 0;
    let (code, mnemonic) = match (op, is_imm) {
        (1, false) => (Code::Ccmp_reg, Mnemonic::Ccmp),
        (1, true) => (Code::Ccmp_imm, Mnemonic::Ccmp),
        (0, false) => (Code::Ccmn_reg, Mnemonic::Ccmn),
        _ => (Code::Ccmn_imm, Mnemonic::Ccmn),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rn, false);
    if is_imm {
        i.op1_kind = OpKind::Immediate;
        i.op1_imm = bits(raw, 20, 16) as u64;
    } else {
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, bits(raw, 20, 16), false);
    }
    i.op2_kind = OpKind::Immediate;
    i.op2_imm = nzcv as u64;
    i.condition = cond;
    i
}

fn decode_csel(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let op = bit(raw, 30);
    let op2 = bit(raw, 10);
    let rm = bits(raw, 20, 16);
    let cond = Condition::from_u32(bits(raw, 15, 12));
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);

    // Aliases: CSET, CSETM, CINC, CINV, CNEG
    let (code, mnemonic, alias_ops) = match (op, op2, rn, rm) {
        (0, 1, 31, 31) => (Code::Csinc, Mnemonic::Cset, 1u8),
        (1, 0, 31, 31) => (Code::Csinv, Mnemonic::Csetm, 1),
        (0, 1, r, s) if r == s => (Code::Csinc, Mnemonic::Cinc, 2),
        (1, 0, r, s) if r == s => (Code::Csinv, Mnemonic::Cinv, 2),
        (1, 1, r, s) if r == s => (Code::Csneg, Mnemonic::Cneg, 2),
        (0, 0, _, _) => (Code::Csel, Mnemonic::Csel, 3),
        (0, 1, _, _) => (Code::Csinc, Mnemonic::Csinc, 3),
        (1, 0, _, _) => (Code::Csinv, Mnemonic::Csinv, 3),
        (1, 1, _, _) => (Code::Csneg, Mnemonic::Csneg, 3),
        _ => return undef(vaddr, raw),
    };

    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.condition = cond;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, false);
    match alias_ops {
        1 => {
            i.op_count = 1;
        }
        2 => {
            i.op_count = 2;
            i.op1_kind = OpKind::Register;
            i.op1_reg = Register::gpr(sf, rn, false);
        }
        _ => {
            i.op_count = 3;
            i.op1_kind = OpKind::Register;
            i.op1_reg = Register::gpr(sf, rn, false);
            i.op2_kind = OpKind::Register;
            i.op2_reg = Register::gpr(sf, rm, false);
        }
    }
    i
}

fn decode_dp_2src(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let opcode = bits(raw, 15, 10);
    let rm = bits(raw, 20, 16);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let (code, mnemonic) = match opcode {
        0b000010 => (Code::Udiv, Mnemonic::Udiv),
        0b000011 => (Code::Sdiv, Mnemonic::Sdiv),
        0b001000 => (Code::Lslv, Mnemonic::Lsl),
        0b001001 => (Code::Lsrv, Mnemonic::Lsr),
        0b001010 => (Code::Asrv, Mnemonic::Asr),
        0b001011 => (Code::Rorv, Mnemonic::Ror),
        // CRC32*
        0b010000 => (Code::Udiv, Mnemonic::Crc32b), // reuse Code slot loosely
        0b010001 => (Code::Udiv, Mnemonic::Crc32h),
        0b010010 => (Code::Udiv, Mnemonic::Crc32w),
        0b010011 => (Code::Udiv, Mnemonic::Crc32x),
        0b010100 => (Code::Udiv, Mnemonic::Crc32cb),
        0b010101 => (Code::Udiv, Mnemonic::Crc32ch),
        0b010110 => (Code::Udiv, Mnemonic::Crc32cw),
        0b010111 => (Code::Udiv, Mnemonic::Crc32cx),
        // MTE / min-max (register)
        0b000000 => {
            // SUBP / SUBPS (S bit)
            if bit(raw, 29) != 0 {
                (Code::Udiv, Mnemonic::Subps)
            } else {
                (Code::Udiv, Mnemonic::Subp)
            }
        }
        0b000100 => (Code::Udiv, Mnemonic::Irg),
        0b000101 => (Code::Udiv, Mnemonic::Gmi),
        0b011000 => (Code::Udiv, Mnemonic::Smax),
        0b011001 => (Code::Udiv, Mnemonic::Umax),
        0b011010 => (Code::Udiv, Mnemonic::Smin),
        0b011011 => (Code::Udiv, Mnemonic::Umin),
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    // CRC32* destination is always W
    let dest_sf = sf && !matches!(
        mnemonic,
        Mnemonic::Crc32b
            | Mnemonic::Crc32h
            | Mnemonic::Crc32w
            | Mnemonic::Crc32x
            | Mnemonic::Crc32cb
            | Mnemonic::Crc32ch
            | Mnemonic::Crc32cw
            | Mnemonic::Crc32cx
    );
    i.op0_reg = Register::gpr(dest_sf, rd, false);
    if matches!(
        mnemonic,
        Mnemonic::Crc32b
            | Mnemonic::Crc32h
            | Mnemonic::Crc32w
            | Mnemonic::Crc32x
            | Mnemonic::Crc32cb
            | Mnemonic::Crc32ch
            | Mnemonic::Crc32cw
            | Mnemonic::Crc32cx
    ) {
        i.op0_reg = Register::w(rd);
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::w(rn);
        i.op2_kind = OpKind::Register;
        i.op2_reg = if matches!(mnemonic, Mnemonic::Crc32x | Mnemonic::Crc32cx) {
            Register::x(rm)
        } else {
            Register::w(rm)
        };
    } else {
        i.op1_kind = OpKind::Register;
        i.op1_reg = Register::gpr(sf, rn, false);
        i.op2_kind = OpKind::Register;
        i.op2_reg = Register::gpr(sf, rm, false);
    }
    i
}

fn decode_dp_1src(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let opcode = bits(raw, 15, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);
    let (code, mnemonic) = match opcode {
        0b000000 => (Code::Rbit, Mnemonic::Rbit),
        0b000001 => (Code::Rev16, Mnemonic::Rev16),
        0b000010 => (
            Code::Rev32,
            if sf {
                Mnemonic::Rev32
            } else {
                Mnemonic::Rev
            },
        ),
        0b000011 if sf => (Code::Rev, Mnemonic::Rev),
        0b000100 => (Code::Clz, Mnemonic::Clz),
        0b000101 => (Code::Cls, Mnemonic::Cls),
        0b000110 => (Code::Clz, Mnemonic::Ctz), // FEAT_CSSC
        0b000111 => (Code::Clz, Mnemonic::Cnt), // FEAT_CSSC
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rd, false);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(sf, rn, false);
    i
}

fn decode_dp_3src(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let op31 = bits(raw, 23, 21);
    let o0 = bit(raw, 15);
    let rm = bits(raw, 20, 16);
    let ra = bits(raw, 14, 10);
    let rn = bits(raw, 9, 5);
    let rd = bits(raw, 4, 0);

    let (code, mnemonic, use_ra) = match (sf as u32, op31, o0) {
        (1, 0b000, 0) | (0, 0b000, 0) if ra == 31 => (Code::Madd, Mnemonic::Mul, false),
        (1, 0b000, 0) | (0, 0b000, 0) => (Code::Madd, Mnemonic::Madd, true),
        (1, 0b000, 1) | (0, 0b000, 1) if ra == 31 => (Code::Msub, Mnemonic::Mneg, false),
        (1, 0b000, 1) | (0, 0b000, 1) => (Code::Msub, Mnemonic::Msub, true),
        (1, 0b001, 0) if ra == 31 => (Code::Smaddl, Mnemonic::Smull, false),
        (1, 0b001, 0) => (Code::Smaddl, Mnemonic::Smaddl, true),
        (1, 0b001, 1) if ra == 31 => (Code::Smsubl, Mnemonic::Smsubl, true),
        (1, 0b001, 1) => (Code::Smsubl, Mnemonic::Smsubl, true),
        (1, 0b010, 0) => (Code::Smulh, Mnemonic::Smulh, false),
        (1, 0b101, 0) if ra == 31 => (Code::Umaddl, Mnemonic::Umull, false),
        (1, 0b101, 0) => (Code::Umaddl, Mnemonic::Umaddl, true),
        (1, 0b101, 1) => (Code::Umsubl, Mnemonic::Umsubl, true),
        (1, 0b110, 0) => (Code::Umulh, Mnemonic::Umulh, false),
        _ => return undef(vaddr, raw),
    };

    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf || matches!(code, Code::Smaddl | Code::Umaddl | Code::Smsubl | Code::Umsubl | Code::Smulh | Code::Umulh), rd, false);
    i.op1_kind = OpKind::Register;
    i.op1_reg = Register::gpr(
        matches!(code, Code::Madd | Code::Msub | Code::Smulh | Code::Umulh) && sf,
        rn,
        false,
    );
    // For maddl family, Rn/Rm are W regs
    if matches!(code, Code::Smaddl | Code::Smsubl | Code::Umaddl | Code::Umsubl) {
        i.op1_reg = Register::w(rn);
        i.op2_kind = OpKind::Register;
        i.op2_reg = Register::w(rm);
    } else {
        i.op2_kind = OpKind::Register;
        i.op2_reg = Register::gpr(sf, rm, false);
    }
    if use_ra {
        i.op_count = 4;
        i.op3_kind = OpKind::Register;
        i.op3_reg = Register::gpr(true, ra, false);
    } else {
        i.op_count = 3;
    }
    i
}
