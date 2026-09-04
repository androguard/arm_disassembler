//! Table-driven ARM64 decoder (elfbrowser + Capstone AArch64 group layout).
//!
//! Primary dispatch on bits [28:25] mirrors both
//! [`executor_arm64`](https://github.com/) and Capstone's AArch64 backend:
//! <https://github.com/capstone-engine/capstone/tree/next/arch/AArch64>

mod dp_imm;
mod dp_reg;
mod ldst;
mod branch_sys;
mod simd_fp;

use crate::enums::{Code, OpKind};
use crate::helpers::bits;
use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;

pub struct Decoder<'a> {
    code: &'a [u8],
    ip: u64,
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(code: &'a [u8], ip: u64) -> Self {
        Self { code, ip, pos: 0 }
    }

    pub fn ip(&self) -> u64 {
        self.ip
    }

    pub fn set_ip(&mut self, ip: u64) {
        self.ip = ip;
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn can_decode(&self) -> bool {
        self.pos + 4 <= self.code.len()
    }

    pub fn decode_out(&mut self, instruction: &mut Instruction) {
        *instruction = self.decode();
    }

    pub fn decode(&mut self) -> Instruction {
        if !self.can_decode() {
            return Instruction::default();
        }
        let raw = u32::from_le_bytes([
            self.code[self.pos],
            self.code[self.pos + 1],
            self.code[self.pos + 2],
            self.code[self.pos + 3],
        ]);
        let vaddr = self.ip;
        self.pos += 4;
        self.ip = self.ip.wrapping_add(4);
        decode_raw(vaddr, raw)
    }
}

pub fn decode_raw(vaddr: u64, raw: u32) -> Instruction {
    let op0 = bits(raw, 28, 25);
    match op0 {
        0b1000 | 0b1001 => dp_imm::decode(vaddr, raw),
        0b1010 | 0b1011 => branch_sys::decode(vaddr, raw),
        0b0100 | 0b0110 | 0b1100 | 0b1110 => ldst::decode(vaddr, raw),
        // LDAPUR / STLUR (unscaled ordered) live in op0=0011
        0b0011 => ldst::decode(vaddr, raw),
        0b0101 | 0b1101 => dp_reg::decode(vaddr, raw),
        0b0111 | 0b1111 => simd_fp::decode(vaddr, raw),
        0b0000 if raw == 0 => undef(vaddr, raw),
        _ => undef(vaddr, raw),
    }
}

pub(crate) fn undef(vaddr: u64, raw: u32) -> Instruction {
    let mut i = Instruction::with_meta(vaddr, raw, Code::Undefined, Mnemonic::Undefined);
    i.op_count = 1;
    i.op0_kind = OpKind::Immediate;
    i.op0_imm = raw as u64;
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{Code, Register};
    use crate::formatter::Formatter;
    use crate::mnemonic::Mnemonic;

    fn dec(raw: u32) -> Instruction {
        decode_raw(0x1000, raw)
    }

    #[test]
    fn ret_nop_bl() {
        let ret = dec(0xD65F03C0);
        assert_eq!(ret.mnemonic, Mnemonic::Ret);
        assert_eq!(ret.code, Code::Ret);

        let nop = dec(0xD503201F);
        assert_eq!(nop.mnemonic, Mnemonic::Nop);

        let bl = dec(0x94000000);
        assert_eq!(bl.mnemonic, Mnemonic::Bl);
        assert_eq!(bl.near_branch_target, 0x1000);
    }

    #[test]
    fn add_imm() {
        let i = dec(0x91000420);
        assert_eq!(i.mnemonic, Mnemonic::Add);
        assert_eq!(i.code, Code::Add_imm);
        assert_eq!(i.op0_reg, Register::X0);
        assert_eq!(i.op1_reg, Register::X1);
        assert_eq!(i.op2_imm, 1);
    }

    #[test]
    fn movz_and_format() {
        let i = dec(0xD2824680);
        assert!(matches!(i.mnemonic, Mnemonic::Mov | Mnemonic::Movz));
        let s = Formatter::new().format_simple(&i);
        assert!(s.contains("x0"));
        assert!(s.contains("1234"));
    }

    #[test]
    fn zero_alloc_decode_loop() {
        let code = [0xC0u8, 0x03, 0x5F, 0xD6, 0x1F, 0x20, 0x03, 0xD5];
        let mut d = Decoder::new(&code, 0);
        let mut tmp = Instruction::default();
        while d.can_decode() {
            d.decode_out(&mut tmp);
        }
        assert_eq!(tmp.mnemonic, Mnemonic::Nop);
    }

    #[test]
    fn ldr_str_udiv_csel() {
        // ldr x0, [x1, #8]
        let ldr = dec(0xF9400420);
        assert_eq!(ldr.mnemonic, Mnemonic::Ldr);
        // udiv x0, x1, x2
        let udiv = dec(0x9AC20820);
        assert_eq!(udiv.mnemonic, Mnemonic::Udiv);
    }

    #[test]
    fn ldp_and_simd_and() {
        // LDP x0, x1, [sp, #16]
        let ldp = dec(0xA94007E0);
        assert_eq!(ldp.mnemonic, Mnemonic::Ldp);
        // AND V0.16B, V1.16B, V2.16B
        let aand = dec(0x4E221C20);
        assert_eq!(aand.mnemonic, Mnemonic::And);
    }

    #[test]
    fn pac_hint_aliases_not_nop() {
        // ARMv8.3 PAC lives in HINT space — must not decode as `hint` / mislabeled AUT.
        let cases = [
            (0xD50320BF, Mnemonic::Sevl),
            (0xD50320FF, Mnemonic::Xpaclri),
            (0xD503211F, Mnemonic::Pacia1716),
            (0xD503215F, Mnemonic::Pacib1716),
            (0xD503219F, Mnemonic::Autia1716),
            (0xD50321DF, Mnemonic::Autib1716),
            (0xD503231F, Mnemonic::Paciaz),
            (0xD503233F, Mnemonic::Paciasp),
            (0xD503235F, Mnemonic::Pacibz),
            (0xD503237F, Mnemonic::Pacibsp),
            (0xD503239F, Mnemonic::Autiaz),
            (0xD50323BF, Mnemonic::Autiasp),
            (0xD50323DF, Mnemonic::Autibz),
            (0xD50323FF, Mnemonic::Autibsp),
        ];
        for (raw, expect) in cases {
            let i = dec(raw);
            assert_eq!(i.mnemonic, expect, "{raw:#010x} -> {}", i.mnemonic.as_str());
            assert_ne!(i.mnemonic, Mnemonic::Hint);
            assert_ne!(i.mnemonic, Mnemonic::Nop);
        }
    }
}
