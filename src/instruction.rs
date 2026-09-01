use crate::enums::{
    Arrangement, Code, Condition, ExtendKind, MemMode, OpKind, Register, ShiftKind,
};
use crate::mnemonic::Mnemonic;

/// Flat decoded instruction — no heap allocations during decode.
#[derive(Debug, Copy, Clone)]
pub struct Instruction {
    pub vaddr: u64,
    pub raw: u32,
    pub len: u8,
    pub code: Code,
    pub mnemonic: Mnemonic,
    pub op_count: u8,

    pub op0_kind: OpKind,
    pub op0_reg: Register,
    pub op0_imm: u64,

    pub op1_kind: OpKind,
    pub op1_reg: Register,
    pub op1_imm: u64,

    pub op2_kind: OpKind,
    pub op2_reg: Register,
    pub op2_imm: u64,

    pub op3_kind: OpKind,
    pub op3_reg: Register,
    pub op3_imm: u64,

    pub memory_base: Register,
    pub memory_index: Register,
    pub memory_offset: i32,
    pub memory_index_shift: u8,
    pub mem_mode: MemMode,

    pub shift_kind: ShiftKind,
    pub shift_amount: u8,
    pub extend_kind: ExtendKind,
    pub extend_amount: u8,
    pub condition: Condition,
    pub near_branch_target: u64,
    pub arrangement: Arrangement,
    pub vector_index: u8,
    pub is_conditional_branch: bool,
}

impl Default for Instruction {
    fn default() -> Self {
        Self {
            vaddr: 0,
            raw: 0,
            len: 4,
            code: Code::INVALID,
            mnemonic: Mnemonic::Invalid,
            op_count: 0,
            op0_kind: OpKind::None,
            op0_reg: Register::None,
            op0_imm: 0,
            op1_kind: OpKind::None,
            op1_reg: Register::None,
            op1_imm: 0,
            op2_kind: OpKind::None,
            op2_reg: Register::None,
            op2_imm: 0,
            op3_kind: OpKind::None,
            op3_reg: Register::None,
            op3_imm: 0,
            memory_base: Register::None,
            memory_index: Register::None,
            memory_offset: 0,
            memory_index_shift: 0,
            mem_mode: MemMode::None,
            shift_kind: ShiftKind::None,
            shift_amount: 0,
            extend_kind: ExtendKind::None,
            extend_amount: 0,
            condition: Condition::Al,
            near_branch_target: 0,
            arrangement: Arrangement::None,
            vector_index: 0,
            is_conditional_branch: false,
        }
    }
}

impl Instruction {
    pub fn is_invalid(&self) -> bool {
        matches!(self.code, Code::INVALID | Code::Undefined)
    }

    pub(crate) fn with_meta(vaddr: u64, raw: u32, code: Code, mnemonic: Mnemonic) -> Self {
        Self {
            vaddr,
            raw,
            code,
            mnemonic,
            ..Self::default()
        }
    }
}
