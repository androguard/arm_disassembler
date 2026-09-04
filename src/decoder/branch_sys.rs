//! Branches, exceptions, system (elfbrowser `branch_sys.rs`).

use crate::enums::{Code, Condition, OpKind, Register};
use crate::helpers::{bit, bits, sign_extend};
use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;

use super::undef;

pub(super) fn decode(vaddr: u64, raw: u32) -> Instruction {
    if bits(raw, 30, 26) == 0b00101 {
        return decode_b_imm(vaddr, raw);
    }
    if bits(raw, 31, 25) == 0b0101010 && bit(raw, 4) == 0 {
        return decode_b_cond(vaddr, raw);
    }
    if bits(raw, 30, 25) == 0b011010 {
        return decode_cbz(vaddr, raw);
    }
    if bits(raw, 30, 25) == 0b011011 {
        return decode_tbz(vaddr, raw);
    }
    if bits(raw, 31, 25) == 0b1101011 {
        return decode_uncond_reg(vaddr, raw);
    }
    if bits(raw, 31, 22) == 0b1101010100 {
        return decode_system(vaddr, raw);
    }
    // Exception generation: SVC/HVC/SMC/BRK/HLT/DCPS
    if bits(raw, 31, 24) == 0b11010100 {
        return decode_exception(vaddr, raw);
    }
    undef(vaddr, raw)
}

fn decode_b_imm(vaddr: u64, raw: u32) -> Instruction {
    let imm26 = bits(raw, 25, 0) as u64;
    let offset = sign_extend(imm26 << 2, 28);
    let target = (vaddr as i64).wrapping_add(offset) as u64;
    let link = bit(raw, 31) != 0;
    let mut i = Instruction::with_meta(
        vaddr,
        raw,
        if link { Code::Bl } else { Code::B },
        if link { Mnemonic::Bl } else { Mnemonic::B },
    );
    i.op_count = 1;
    i.op0_kind = OpKind::NearBranch;
    i.op0_imm = target;
    i.near_branch_target = target;
    i
}

fn decode_b_cond(vaddr: u64, raw: u32) -> Instruction {
    let imm19 = bits(raw, 23, 5) as u64;
    let cond = Condition::from_u32(bits(raw, 3, 0));
    let offset = sign_extend(imm19 << 2, 21);
    let target = (vaddr as i64).wrapping_add(offset) as u64;
    let mut i = Instruction::with_meta(vaddr, raw, Code::B_cond, Mnemonic::Bcond);
    i.op_count = 1;
    i.op0_kind = OpKind::NearBranch;
    i.op0_imm = target;
    i.near_branch_target = target;
    i.condition = cond;
    i.is_conditional_branch = true;
    i
}

fn decode_cbz(vaddr: u64, raw: u32) -> Instruction {
    let sf = bit(raw, 31) == 1;
    let is_cbnz = bit(raw, 24) != 0;
    let imm19 = bits(raw, 23, 5) as u64;
    let rt = bits(raw, 4, 0);
    let target = (vaddr as i64).wrapping_add(sign_extend(imm19 << 2, 21)) as u64;
    let mut i = Instruction::with_meta(
        vaddr,
        raw,
        if is_cbnz { Code::Cbnz } else { Code::Cbz },
        if is_cbnz { Mnemonic::Cbnz } else { Mnemonic::Cbz },
    );
    i.op_count = 2;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::gpr(sf, rt, false);
    i.op1_kind = OpKind::NearBranch;
    i.op1_imm = target;
    i.near_branch_target = target;
    i.is_conditional_branch = true;
    i
}

fn decode_tbz(vaddr: u64, raw: u32) -> Instruction {
    let b5 = bit(raw, 31);
    let op = bit(raw, 24);
    let b40 = bits(raw, 23, 19);
    let imm14 = bits(raw, 18, 5) as u64;
    let rt = bits(raw, 4, 0);
    let bitpos = (b5 << 5) | b40;
    let target = (vaddr as i64).wrapping_add(sign_extend(imm14 << 2, 16)) as u64;
    let mut i = Instruction::with_meta(
        vaddr,
        raw,
        if op == 0 { Code::Tbz } else { Code::Tbnz },
        if op == 0 { Mnemonic::Tbz } else { Mnemonic::Tbnz },
    );
    i.op_count = 3;
    i.op0_kind = OpKind::Register;
    i.op0_reg = Register::x(rt);
    i.op1_kind = OpKind::Immediate;
    i.op1_imm = bitpos as u64;
    i.op2_kind = OpKind::NearBranch;
    i.op2_imm = target;
    i.near_branch_target = target;
    i.is_conditional_branch = true;
    i
}

fn decode_uncond_reg(vaddr: u64, raw: u32) -> Instruction {
    // Note: elfbrowser opc mapping differs from ARM ARM naming;
    // ARM: opc 0000=BR, 0001=BLR, 0010=RET
    // Authenticated variants: bit11=1 selects PAC; bit10 selects key B (vs A);
    // braaz/blraaz/… use opc 1000/1001 with Z (bit 24? / Rm=zr forms).
    let opc = bits(raw, 24, 21);
    let rn = bits(raw, 9, 5);
    let pac = bits(raw, 11, 11) != 0;
    let key_b = bits(raw, 10, 10) != 0;
    let (code, mnemonic) = match opc {
        // BR / BRAAZ / BRABZ (Z forms share opc with BR; PAC bit selects auth)
        0b0000 => {
            if pac {
                if key_b {
                    (Code::Br, Mnemonic::Brabz)
                } else {
                    (Code::Br, Mnemonic::Braaz)
                }
            } else {
                (Code::Br, Mnemonic::Br)
            }
        }
        // BLR / BLRAAZ / BLRABZ
        0b0001 => {
            if pac {
                if key_b {
                    (Code::Blr, Mnemonic::Blrabz)
                } else {
                    (Code::Blr, Mnemonic::Blraaz)
                }
            } else {
                (Code::Blr, Mnemonic::Blr)
            }
        }
        // RET / RETAA / RETAB
        0b0010 => {
            if pac {
                if key_b {
                    (Code::Ret, Mnemonic::Retab)
                } else {
                    (Code::Ret, Mnemonic::Retaa)
                }
            } else {
                (Code::Ret, Mnemonic::Ret)
            }
        }
        // BRAA / BRAB (with modifier register)
        0b1000 => (
            Code::Br,
            if key_b {
                Mnemonic::Brab
            } else {
                Mnemonic::Braa
            },
        ),
        // BLRAA / BLRAB
        0b1001 => (
            Code::Blr,
            if key_b {
                Mnemonic::Blrab
            } else {
                Mnemonic::Blraa
            },
        ),
        0b1010 => (Code::Ret, Mnemonic::Retaa),
        0b1100 => (Code::Br, Mnemonic::Brab),
        0b1101 => (Code::Blr, Mnemonic::Blrab),
        0b1110 => (Code::Ret, Mnemonic::Retab),
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    let bare = matches!(
        mnemonic,
        Mnemonic::Ret | Mnemonic::Retaa | Mnemonic::Retab
    ) && (rn == 30 || rn == 31);
    if bare {
        // bare `ret` / `retaa` / `retab`
    } else {
        i.op_count = 1;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::x(rn);
    }
    i
}

fn decode_exception(vaddr: u64, raw: u32) -> Instruction {
    let opc = bits(raw, 23, 21);
    let imm16 = bits(raw, 20, 5);
    let ll = bits(raw, 1, 0);
    let (code, mnemonic) = match (opc, ll) {
        (0b000, 0b01) => (Code::Svc, Mnemonic::Svc),
        (0b000, 0b10) => (Code::Hvc, Mnemonic::Hvc),
        (0b000, 0b11) => (Code::Smc, Mnemonic::Smc),
        (0b001, 0b00) => (Code::Brk, Mnemonic::Brk),
        (0b010, 0b00) => (Code::Hlt, Mnemonic::Hlt),
        (0b101, _) => (Code::Dcps, Mnemonic::Dcps1),
        _ => return undef(vaddr, raw),
    };
    let mut i = Instruction::with_meta(vaddr, raw, code, mnemonic);
    i.op_count = 1;
    i.op0_kind = OpKind::Immediate;
    i.op0_imm = imm16 as u64;
    i
}

fn decode_system(vaddr: u64, raw: u32) -> Instruction {
    // HINT aliases — PAC/AUT/XPAC live in the HINT encoding space (ARMv8.3+).
    // Older tooling that only knows NOP/YIELD/… prints these as `hint #N` / nop-class.
    match raw {
        0xD503201F => return Instruction::with_meta(vaddr, raw, Code::Nop, Mnemonic::Nop),
        0xD503203F => return Instruction::with_meta(vaddr, raw, Code::Yield, Mnemonic::Yield),
        0xD503205F => return Instruction::with_meta(vaddr, raw, Code::Wfe, Mnemonic::Wfe),
        0xD503207F => return Instruction::with_meta(vaddr, raw, Code::Wfi, Mnemonic::Wfi),
        0xD503209F => return Instruction::with_meta(vaddr, raw, Code::Sev, Mnemonic::Sev),
        0xD50320BF => return Instruction::with_meta(vaddr, raw, Code::Sevl, Mnemonic::Sevl),
        // CRm=0 op2=7
        0xD50320FF => {
            return Instruction::with_meta(vaddr, raw, Code::Xpaclri, Mnemonic::Xpaclri)
        }
        // CRm=1 — *1716 forms (IA/IB keys, modifier x16)
        0xD503211F => {
            return Instruction::with_meta(vaddr, raw, Code::Pacia1716, Mnemonic::Pacia1716)
        }
        0xD503215F => {
            return Instruction::with_meta(vaddr, raw, Code::Pacib1716, Mnemonic::Pacib1716)
        }
        0xD503219F => {
            return Instruction::with_meta(vaddr, raw, Code::Autia1716, Mnemonic::Autia1716)
        }
        0xD50321DF => {
            return Instruction::with_meta(vaddr, raw, Code::Autib1716, Mnemonic::Autib1716)
        }
        // CRm=3 — SP / zero-modifier LR signing (common iOS / Android arm64e prologues)
        0xD503231F => {
            return Instruction::with_meta(vaddr, raw, Code::Paciaz, Mnemonic::Paciaz)
        }
        0xD503233F => {
            return Instruction::with_meta(vaddr, raw, Code::Paciasp, Mnemonic::Paciasp)
        }
        0xD503235F => {
            return Instruction::with_meta(vaddr, raw, Code::Pacibz, Mnemonic::Pacibz)
        }
        0xD503237F => {
            return Instruction::with_meta(vaddr, raw, Code::Pacibsp, Mnemonic::Pacibsp)
        }
        0xD503239F => {
            return Instruction::with_meta(vaddr, raw, Code::Autiaz, Mnemonic::Autiaz)
        }
        0xD50323BF => {
            return Instruction::with_meta(vaddr, raw, Code::Autiasp, Mnemonic::Autiasp)
        }
        0xD50323DF => {
            return Instruction::with_meta(vaddr, raw, Code::Autibz, Mnemonic::Autibz)
        }
        0xD50323FF => {
            return Instruction::with_meta(vaddr, raw, Code::Autibsp, Mnemonic::Autibsp)
        }
        _ => {}
    }
    if raw & 0xFFFFF01F == 0xD503201F {
        let op = bits(raw, 11, 5);
        // BTI: CRm=4, op2 in 0..3 (hint #32/#34/#36/#38)
        if bits(raw, 11, 8) == 0b0100 && bits(raw, 7, 5) <= 0b011 {
            return Instruction::with_meta(vaddr, raw, Code::Hint, Mnemonic::Bti);
        }
        // CLRBHB: hint #22 (CRm=2, op2=6) — 0xD50322DF
        if bits(raw, 11, 5) == 0b010110 {
            return Instruction::with_meta(vaddr, raw, Code::Hint, Mnemonic::Clrbhb);
        }
        let mut i = Instruction::with_meta(vaddr, raw, Code::Hint, Mnemonic::Hint);
        i.op_count = 1;
        i.op0_kind = OpKind::Immediate;
        i.op0_imm = op as u64;
        return i;
    }

    // MSR (immediate) PSTATE — Capstone prints `msr SSBS/DIT/TCO/UAO/…, #imm`
    // Encoding: 1101 0101 0000 0 op1 0100 CRm op2 11111
    if bits(raw, 31, 19) == 0b1101010100000
        && bits(raw, 15, 12) == 0b0100
        && bits(raw, 4, 0) == 31
    {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Msr, Mnemonic::Msr);
        i.op_count = 2;
        i.op0_kind = OpKind::SystemRegister;
        i.op0_imm = bits(raw, 18, 5) as u64; // op1:CRm:op2
        i.op1_kind = OpKind::Immediate;
        i.op1_imm = bits(raw, 11, 8) as u64; // CRm as imm for Capstone-style
        return i;
    }

    // Barriers: DSB/DMB/ISB — 1101 0101 0000 0011 0011 CRm op2 11111
    if bits(raw, 31, 22) == 0b1101010100
        && bit(raw, 21) == 0
        && bits(raw, 15, 12) == 0b0011
        && bits(raw, 4, 0) == 31
    {
        let crm = bits(raw, 11, 8);
        let op2 = bits(raw, 7, 5);
        let mnemonic = match op2 {
            0b001 | 0b100 => Mnemonic::Dsb, // 001: nXS / SSBB-style DSB forms in Capstone
            0b101 => Mnemonic::Dmb,
            0b110 => Mnemonic::Isb,
            0b111 => Mnemonic::Sb,
            _ => {
                let mut i = Instruction::with_meta(vaddr, raw, Code::Msr, Mnemonic::Msr);
                i.op_count = 2;
                i.op0_kind = OpKind::SystemRegister;
                i.op0_imm = ((bits(raw, 20, 19) as u64) << 14)
                    | ((bits(raw, 18, 16) as u64) << 11)
                    | ((bits(raw, 15, 12) as u64) << 7)
                    | ((bits(raw, 11, 8) as u64) << 3)
                    | bits(raw, 7, 5) as u64;
                i.op1_kind = OpKind::Register;
                i.op1_reg = Register::x(31);
                return i;
            }
        };
        let mut i = Instruction::with_meta(vaddr, raw, Code::Sys, mnemonic);
        i.op_count = 1;
        i.op0_kind = OpKind::Immediate;
        i.op0_imm = crm as u64;
        return i;
    }

    let l = bit(raw, 21);
    let rt = bits(raw, 4, 0);
    let op0 = bits(raw, 20, 19);
    let op1 = bits(raw, 18, 16);
    let crn = bits(raw, 15, 12);
    let crm = bits(raw, 11, 8);
    let op2 = bits(raw, 7, 5);
    let sysreg = ((op0 as u64) << 14)
        | ((op1 as u64) << 11)
        | ((crn as u64) << 7)
        | ((crm as u64) << 3)
        | op2 as u64;

    if l != 0 {
        let mut i = Instruction::with_meta(vaddr, raw, Code::Mrs, Mnemonic::Mrs);
        i.op_count = 2;
        i.op0_kind = OpKind::Register;
        i.op0_reg = Register::x(rt);
        i.op1_kind = OpKind::SystemRegister;
        i.op1_imm = sysreg;
        i
    } else {
        // SYS aliases: AT/DC/IC/TLBI — only in SYS encoding space (not MSR sysregs)
        let is_sys = op0 == 0b00 || (op0 == 0b01 && crn >= 7);
        if is_sys {
            let alias = match crn {
                8 | 9 => Some(Mnemonic::Tlbi), // CRn=9: FEAT_XS nxs forms
                7 if crm == 8 => Some(Mnemonic::At),
                7 if crm == 9 => Some(Mnemonic::At), // AT S1E1RP/WP etc.
                7 if matches!(crm, 0b0001 | 0b0101) && op2 == 0 => Some(Mnemonic::Ic),
                7 => Some(Mnemonic::Dc),
                _ => None,
            };
            if let Some(mnemonic) = alias {
                let mut i = Instruction::with_meta(vaddr, raw, Code::Sys, mnemonic);
                i.op_count = if rt == 31 { 0 } else { 1 };
                if rt != 31 {
                    i.op0_kind = OpKind::Register;
                    i.op0_reg = Register::x(rt);
                }
                return i;
            }
            let mut i = Instruction::with_meta(vaddr, raw, Code::Sys, Mnemonic::Sys);
            i.op_count = 1;
            i.op0_kind = OpKind::Immediate;
            i.op0_imm = sysreg;
            i
        } else {
            let mut i = Instruction::with_meta(vaddr, raw, Code::Msr, Mnemonic::Msr);
            i.op_count = 2;
            i.op0_kind = OpKind::SystemRegister;
            i.op0_imm = sysreg;
            i.op1_kind = OpKind::Register;
            i.op1_reg = Register::x(rt);
            i
        }
    }
}
