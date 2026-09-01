#![no_std]
#![allow(non_camel_case_types)]

//! Zero-allocation iced-style ARM64 decoder and formatter.
//!
//! Instruction coverage aligned with:
//! - elfbrowser `executor_arm64` (dp_imm / dp_reg / ldst / branch_sys / simd_fp)
//! - Capstone AArch64: <https://github.com/capstone-engine/capstone/tree/next/arch/AArch64>
//!   (`AArch64GenCSMappingInsnName.inc` → [`Mnemonic`])

mod enums;
mod helpers;
mod instruction;
mod mnemonic;
mod decoder;
pub mod formatter;

pub use decoder::{decode_raw, Decoder};
pub use enums::{
    Arrangement, Code, Condition, ExtendKind, MemMode, OpKind, Register, ShiftKind,
};
pub use formatter::{Formatter, SymbolResolver};
pub use instruction::Instruction;
pub use mnemonic::Mnemonic;
