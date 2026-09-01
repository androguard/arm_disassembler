//! Instruction formatter — separate from the decoder (iced-style).

use crate::enums::{ExtendKind, MemMode, OpKind, ShiftKind};
use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;

/// Optional symbol resolver callback style via trait.
pub trait SymbolResolver {
    fn resolve(&self, vaddr: u64) -> Option<&str>;
}

impl SymbolResolver for () {
    fn resolve(&self, _vaddr: u64) -> Option<&str> {
        None
    }
}

pub struct Formatter {
    pub hex_prefix: bool,
    pub uppercase_hex: bool,
}

impl Default for Formatter {
    fn default() -> Self {
        Self {
            hex_prefix: true,
            uppercase_hex: false,
        }
    }
}

impl Formatter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn format_to<R: SymbolResolver>(
        &self,
        instruction: &Instruction,
        out: &mut impl FmtWrite,
        symbols: &R,
    ) {
        if instruction.mnemonic == Mnemonic::Bcond {
            let _ = write!(out, "b.{}", instruction.condition.as_str());
        } else {
            let _ = write!(out, "{}", instruction.mnemonic.as_str());
        }

        if instruction.op_count == 0 {
            return;
        }
        let _ = write!(out, " ");
        for idx in 0..instruction.op_count {
            if idx > 0 {
                let _ = write!(out, ", ");
            }
            self.format_op(instruction, idx, out, symbols);
        }

        if matches!(
            instruction.mnemonic,
            Mnemonic::Csel | Mnemonic::Csinc | Mnemonic::Csinv | Mnemonic::Csneg | Mnemonic::Ccmp | Mnemonic::Ccmn
                | Mnemonic::Cset | Mnemonic::Csetm | Mnemonic::Cinc | Mnemonic::Cinv | Mnemonic::Cneg
        ) {
            let _ = write!(out, ", {}", instruction.condition.as_str());
        }
    }

    pub fn format<R: SymbolResolver>(
        &self,
        instruction: &Instruction,
        symbols: &R,
    ) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        self.format_to(instruction, &mut s, symbols);
        s
    }

    pub fn format_simple(&self, instruction: &Instruction) -> alloc::string::String {
        self.format(instruction, &())
    }

    fn format_op<R: SymbolResolver>(
        &self,
        ins: &Instruction,
        idx: u8,
        out: &mut impl FmtWrite,
        symbols: &R,
    ) {
        let (kind, reg, imm) = match idx {
            0 => (ins.op0_kind, ins.op0_reg, ins.op0_imm),
            1 => (ins.op1_kind, ins.op1_reg, ins.op1_imm),
            2 => (ins.op2_kind, ins.op2_reg, ins.op2_imm),
            _ => (ins.op3_kind, ins.op3_reg, ins.op3_imm),
        };
        match kind {
            OpKind::None => {}
            OpKind::Register => {
                let _ = write!(out, "{}", reg.as_str());
                if idx + 1 == ins.op_count {
                    if ins.shift_kind != ShiftKind::None {
                        let _ = write!(
                            out,
                            ", {} #{}",
                            ins.shift_kind.as_str(),
                            ins.shift_amount
                        );
                    } else if ins.extend_kind != ExtendKind::None {
                        let _ = write!(out, ", {}", ins.extend_kind.as_str());
                        if ins.extend_amount != 0 {
                            let _ = write!(out, " #{}", ins.extend_amount);
                        }
                    }
                }
            }
            OpKind::Immediate | OpKind::SystemRegister => {
                if matches!(ins.mnemonic, Mnemonic::Movz | Mnemonic::Movk | Mnemonic::Movn)
                    && ins.shift_kind != ShiftKind::None
                {
                    self.write_imm(out, imm);
                    let _ = write!(
                        out,
                        ", {} #{}",
                        ins.shift_kind.as_str(),
                        ins.shift_amount
                    );
                } else {
                    self.write_imm(out, imm);
                }
            }
            OpKind::NearBranch => {
                if let Some(name) = symbols.resolve(imm) {
                    let _ = write!(out, "{name}");
                } else {
                    self.write_imm(out, imm);
                }
            }
            OpKind::Memory => {
                match ins.mem_mode {
                    MemMode::PostIndex => {
                        let _ = write!(out, "[{}]", ins.memory_base.as_str());
                        // post-index offset printed as trailing imm by caller convention:
                        // we emit ", #off" after the mem op via memory_offset when formatting memory
                        let _ = write!(out, ", #{}", ins.memory_offset);
                        return;
                    }
                    MemMode::PreIndex => {
                        let _ = write!(
                            out,
                            "[{}, #{}]!",
                            ins.memory_base.as_str(),
                            ins.memory_offset
                        );
                        return;
                    }
                    MemMode::Register => {
                        let _ = write!(
                            out,
                            "[{}, {}",
                            ins.memory_base.as_str(),
                            ins.memory_index.as_str()
                        );
                        if ins.extend_kind != ExtendKind::None {
                            let _ = write!(out, ", {}", ins.extend_kind.as_str());
                            if ins.memory_index_shift != 0 {
                                let _ = write!(out, " #{}", ins.memory_index_shift);
                            }
                        } else if ins.memory_index_shift != 0 {
                            let _ = write!(out, ", lsl #{}", ins.memory_index_shift);
                        }
                        let _ = write!(out, "]");
                        return;
                    }
                    _ => {
                        let _ = write!(out, "[{}", ins.memory_base.as_str());
                        if ins.memory_offset != 0 {
                            let _ = write!(out, ", #{}", ins.memory_offset);
                        }
                        let _ = write!(out, "]");
                    }
                }
            }
        }
    }

    fn write_imm(&self, out: &mut impl FmtWrite, imm: u64) {
        if self.hex_prefix {
            if self.uppercase_hex {
                let _ = write!(out, "#{:#X}", imm);
            } else {
                let _ = write!(out, "#{:#x}", imm);
            }
        } else {
            let _ = write!(out, "#{imm}");
        }
    }
}

pub trait FmtWrite {
    fn write_str(&mut self, s: &str) -> core::fmt::Result;
}

impl FmtWrite for alloc::string::String {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

struct WriteAdapter<'a, W: FmtWrite + ?Sized>(&'a mut W);

impl<W: FmtWrite + ?Sized> core::fmt::Write for WriteAdapter<'_, W> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.write_str(s)
    }
}

macro_rules! write {
    ($dst:expr, $($arg:tt)*) => {{
        let mut __w = WriteAdapter($dst);
        core::fmt::Write::write_fmt(&mut __w, core::format_args!($($arg)*))
    }};
}

use write;

extern crate alloc;

// silence unused import if enums::Mnemonic was wrong
