//! Mnemonic categories and compact operand summaries for similarity / rules.

use crate::enums::{OpKind, Register};
use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;

/// Bit flags for [`OperandSummary::reg_classes`].
pub mod reg_class {
    pub const GPR64: u8 = 1 << 0;
    pub const GPR32: u8 = 1 << 1;
    pub const VECTOR: u8 = 1 << 2;
    pub const SP: u8 = 1 << 3;
    pub const PC: u8 = 1 << 4;
    pub const SYS: u8 = 1 << 5;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MnemonicClass {
    DataMove,
    Arith,
    Logic,
    Shift,
    Load,
    Store,
    LoadPair,
    BranchCond,
    Branch,
    Call,
    Ret,
    Cmp,
    Csel,
    Simd,
    Crypto,
    Sys,
    Other,
}

/// Compact operand footprint (register classes + one immediate when present).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OperandSummary {
    pub reg_classes: u8,
    pub has_imm: bool,
    pub imm: i64,
}

#[inline]
pub fn reg_class_flags(reg: Register) -> u8 {
    use reg_class::*;
    if reg == Register::None {
        return 0;
    }
    let s = reg.as_str();
    if s == "sp" {
        return SP | GPR64;
    }
    if s == "wsp" {
        return SP | GPR32;
    }
    if s == "pc" {
        return PC | GPR64;
    }
    if s.starts_with('x') || s == "xzr" {
        return GPR64;
    }
    if s.starts_with('w') || s == "wzr" {
        return GPR32;
    }
    if s.starts_with('v')
        || s.starts_with('q')
        || s.starts_with('d')
        || s.starts_with('s')
        || s.starts_with('h')
        || s.starts_with('b')
    {
        return VECTOR;
    }
    0
}

pub fn mnemonic_class(m: Mnemonic) -> MnemonicClass {
    use Mnemonic::*;
    match m {
        Invalid | Undefined => MnemonicClass::Other,
        Ret | Retab | Retabsp => MnemonicClass::Ret,
        Bl | Blr | Blraa | Blraaz | Blrab | Blrabz => MnemonicClass::Call,
        B | Br | Braa | Braaz | Brab | Brabz => MnemonicClass::Branch,
        Bcond | Cbz | Cbnz | Tbz | Tbnz | Bc => MnemonicClass::BranchCond,
        Svc | Hvc | Smc | Brk | Hlt | Hint | Nop | Yield | Wfe | Wfi | Sev | Sevl => {
            MnemonicClass::Sys
        }
        Aesd | Aese | Aesimc | Aesmc => MnemonicClass::Crypto,
        _ => classify_by_name(m.as_str()),
    }
}

fn classify_by_name(s: &str) -> MnemonicClass {
    if s.is_empty() {
        return MnemonicClass::Other;
    }
    if s.starts_with("aes") || s.starts_with("sha") || s.contains("pmull") {
        return MnemonicClass::Crypto;
    }
    if s.starts_with("ldp") || s.starts_with("stp") || s.starts_with("ldnp") || s.starts_with("stnp") {
        return MnemonicClass::LoadPair;
    }
    if s.starts_with("ldr") || s.starts_with("ldur") || s.starts_with("ldxr") || s.starts_with("ldar") {
        return MnemonicClass::Load;
    }
    if s.starts_with("str") || s.starts_with("stur") || s.starts_with("stxr") || s.starts_with("stlr") {
        return MnemonicClass::Store;
    }
    if s.starts_with("mov") || s.starts_with("mvn") || s.starts_with("fmov") {
        return MnemonicClass::DataMove;
    }
    if s.starts_with("add") || s.starts_with("sub") || s.starts_with("mul") || s.starts_with("div")
        || s.starts_with("madd") || s.starts_with("msub") || s.starts_with("neg") || s.starts_with("abs")
        || s.starts_with("fadd") || s.starts_with("fsub") || s.starts_with("fmul") || s.starts_with("fdiv")
        || s.starts_with("adc") || s.starts_with("sbc")
    {
        return MnemonicClass::Arith;
    }
    if s.starts_with("and") || s.starts_with("orr") || s.starts_with("eor") || s.starts_with("bic")
        || s.starts_with("orn") || s.starts_with("eon") || s.starts_with("tst")
    {
        return MnemonicClass::Logic;
    }
    if s.starts_with("lsl") || s.starts_with("lsr") || s.starts_with("asr") || s.starts_with("ror")
        || s.starts_with("sbfm") || s.starts_with("bfm") || s.starts_with("ubfm") || s.starts_with("extr")
    {
        return MnemonicClass::Shift;
    }
    if s.starts_with("cbz") || s.starts_with("cbnz") || s.starts_with("tbz") || s.starts_with("tbnz") {
        return MnemonicClass::BranchCond;
    }
    if s.starts_with("cmp") || s.starts_with("cmn") || s.starts_with("fcmp") {
        return MnemonicClass::Cmp;
    }
    if s.starts_with("csel") || s.starts_with("csinc") || s.starts_with("csinv") || s.starts_with("csneg")
        || s.starts_with("cset") || s.starts_with("cinc") || s.starts_with("cneg")
    {
        return MnemonicClass::Csel;
    }
    if s == "ret" || s.starts_with("ret") {
        return MnemonicClass::Ret;
    }
    if s.starts_with("bl") {
        return MnemonicClass::Call;
    }
    if s == "b" || s.starts_with("br") {
        return MnemonicClass::Branch;
    }
    if s.starts_with("svc") || s.starts_with("hvc") || s.starts_with("smc") || s.starts_with("sys")
        || s.starts_with("mrs") || s.starts_with("msr") || s == "nop"
    {
        return MnemonicClass::Sys;
    }
    if s.starts_with('f') || s.starts_with('v') {
        return MnemonicClass::Simd;
    }
    MnemonicClass::Other
}

pub fn operand_summary(insn: &Instruction) -> OperandSummary {
    let mut out = OperandSummary::default();
    let ops = [
        (insn.op0_kind, insn.op0_reg, insn.op0_imm),
        (insn.op1_kind, insn.op1_reg, insn.op1_imm),
        (insn.op2_kind, insn.op2_reg, insn.op2_imm),
        (insn.op3_kind, insn.op3_reg, insn.op3_imm),
    ];
    for (kind, reg, imm) in ops {
        match kind {
            OpKind::Register => out.reg_classes |= reg_class_flags(reg),
            OpKind::Immediate | OpKind::NearBranch => {
                if !out.has_imm {
                    out.has_imm = true;
                    out.imm = imm as i64;
                }
            }
            OpKind::SystemRegister => out.reg_classes |= reg_class::SYS,
            OpKind::Memory | OpKind::None => {}
        }
    }
    if insn.memory_base != Register::None {
        out.reg_classes |= reg_class_flags(insn.memory_base);
    }
    if insn.memory_index != Register::None {
        out.reg_classes |= reg_class_flags(insn.memory_index);
    }
    if insn.memory_offset != 0 && !out.has_imm {
        out.has_imm = true;
        out.imm = insn.memory_offset as i64;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decoder;

    #[test]
    fn classifies_add_and_ret() {
        assert_eq!(mnemonic_class(Mnemonic::Add), MnemonicClass::Arith);
        assert_eq!(mnemonic_class(Mnemonic::Ret), MnemonicClass::Ret);
    }

    #[test]
    fn operand_summary_gpr_imm() {
        let code = [0x00, 0x00, 0x80, 0x52]; // mov w0, #0
        let insn = Decoder::new(&code, 0).decode();
        let s = operand_summary(&insn);
        assert!(s.reg_classes & reg_class::GPR32 != 0);
    }
}
