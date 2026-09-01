//! Iced-style enums (Register, Code, operand kinds). Mnemonics: see `mnemonic.rs`.

#![allow(non_camel_case_types)]

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
#[repr(u16)]
pub enum Register {
    #[default]
    None = 0,
    X0, X1, X2, X3, X4, X5, X6, X7,
    X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23,
    X24, X25, X26, X27, X28, X29, X30, XZR,
    SP,
    W0, W1, W2, W3, W4, W5, W6, W7,
    W8, W9, W10, W11, W12, W13, W14, W15,
    W16, W17, W18, W19, W20, W21, W22, W23,
    W24, W25, W26, W27, W28, W29, W30, WZR,
    WSP,
    V0, V1, V2, V3, V4, V5, V6, V7,
    V8, V9, V10, V11, V12, V13, V14, V15,
    V16, V17, V18, V19, V20, V21, V22, V23,
    V24, V25, V26, V27, V28, V29, V30, V31,
    Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7,
    Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15,
    Q16, Q17, Q18, Q19, Q20, Q21, Q22, Q23,
    Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
    D0, D1, D2, D3, D4, D5, D6, D7,
    D8, D9, D10, D11, D12, D13, D14, D15,
    D16, D17, D18, D19, D20, D21, D22, D23,
    D24, D25, D26, D27, D28, D29, D30, D31,
    S0, S1, S2, S3, S4, S5, S6, S7,
    S8, S9, S10, S11, S12, S13, S14, S15,
    S16, S17, S18, S19, S20, S21, S22, S23,
    S24, S25, S26, S27, S28, S29, S30, S31,
    H0, H1, H2, H3, H4, H5, H6, H7,
    H8, H9, H10, H11, H12, H13, H14, H15,
    H16, H17, H18, H19, H20, H21, H22, H23,
    H24, H25, H26, H27, H28, H29, H30, H31,
    B0, B1, B2, B3, B4, B5, B6, B7,
    B8, B9, B10, B11, B12, B13, B14, B15,
    B16, B17, B18, B19, B20, B21, B22, B23,
    B24, B25, B26, B27, B28, B29, B30, B31,
    PC,
}

impl Register {
    pub fn x(n: u32) -> Self {
        match n & 31 {
            0 => Self::X0, 1 => Self::X1, 2 => Self::X2, 3 => Self::X3,
            4 => Self::X4, 5 => Self::X5, 6 => Self::X6, 7 => Self::X7,
            8 => Self::X8, 9 => Self::X9, 10 => Self::X10, 11 => Self::X11,
            12 => Self::X12, 13 => Self::X13, 14 => Self::X14, 15 => Self::X15,
            16 => Self::X16, 17 => Self::X17, 18 => Self::X18, 19 => Self::X19,
            20 => Self::X20, 21 => Self::X21, 22 => Self::X22, 23 => Self::X23,
            24 => Self::X24, 25 => Self::X25, 26 => Self::X26, 27 => Self::X27,
            28 => Self::X28, 29 => Self::X29, 30 => Self::X30, _ => Self::XZR,
        }
    }

    pub fn w(n: u32) -> Self {
        match n & 31 {
            0 => Self::W0, 1 => Self::W1, 2 => Self::W2, 3 => Self::W3,
            4 => Self::W4, 5 => Self::W5, 6 => Self::W6, 7 => Self::W7,
            8 => Self::W8, 9 => Self::W9, 10 => Self::W10, 11 => Self::W11,
            12 => Self::W12, 13 => Self::W13, 14 => Self::W14, 15 => Self::W15,
            16 => Self::W16, 17 => Self::W17, 18 => Self::W18, 19 => Self::W19,
            20 => Self::W20, 21 => Self::W21, 22 => Self::W22, 23 => Self::W23,
            24 => Self::W24, 25 => Self::W25, 26 => Self::W26, 27 => Self::W27,
            28 => Self::W28, 29 => Self::W29, 30 => Self::W30, _ => Self::WZR,
        }
    }

    pub fn gpr(sf: bool, n: u32, sp_if_31: bool) -> Self {
        if n == 31 {
            if sp_if_31 {
                return if sf { Self::SP } else { Self::WSP };
            }
            return if sf { Self::XZR } else { Self::WZR };
        }
        if sf { Self::x(n) } else { Self::w(n) }
    }

    pub fn v(n: u32) -> Self {
        match n & 31 {
            0 => Self::V0, 1 => Self::V1, 2 => Self::V2, 3 => Self::V3,
            4 => Self::V4, 5 => Self::V5, 6 => Self::V6, 7 => Self::V7,
            8 => Self::V8, 9 => Self::V9, 10 => Self::V10, 11 => Self::V11,
            12 => Self::V12, 13 => Self::V13, 14 => Self::V14, 15 => Self::V15,
            16 => Self::V16, 17 => Self::V17, 18 => Self::V18, 19 => Self::V19,
            20 => Self::V20, 21 => Self::V21, 22 => Self::V22, 23 => Self::V23,
            24 => Self::V24, 25 => Self::V25, 26 => Self::V26, 27 => Self::V27,
            28 => Self::V28, 29 => Self::V29, 30 => Self::V30, _ => Self::V31,
        }
    }

    pub fn fp_sized(size_bytes: u32, n: u32) -> Self {
        let n = n & 31;
        match size_bytes {
            1 => match n {
                0 => Self::B0, 1 => Self::B1, 2 => Self::B2, 3 => Self::B3,
                4 => Self::B4, 5 => Self::B5, 6 => Self::B6, 7 => Self::B7,
                8 => Self::B8, 9 => Self::B9, 10 => Self::B10, 11 => Self::B11,
                12 => Self::B12, 13 => Self::B13, 14 => Self::B14, 15 => Self::B15,
                16 => Self::B16, 17 => Self::B17, 18 => Self::B18, 19 => Self::B19,
                20 => Self::B20, 21 => Self::B21, 22 => Self::B22, 23 => Self::B23,
                24 => Self::B24, 25 => Self::B25, 26 => Self::B26, 27 => Self::B27,
                28 => Self::B28, 29 => Self::B29, 30 => Self::B30, _ => Self::B31,
            },
            2 => match n {
                0 => Self::H0, 1 => Self::H1, 2 => Self::H2, 3 => Self::H3,
                4 => Self::H4, 5 => Self::H5, 6 => Self::H6, 7 => Self::H7,
                8 => Self::H8, 9 => Self::H9, 10 => Self::H10, 11 => Self::H11,
                12 => Self::H12, 13 => Self::H13, 14 => Self::H14, 15 => Self::H15,
                16 => Self::H16, 17 => Self::H17, 18 => Self::H18, 19 => Self::H19,
                20 => Self::H20, 21 => Self::H21, 22 => Self::H22, 23 => Self::H23,
                24 => Self::H24, 25 => Self::H25, 26 => Self::H26, 27 => Self::H27,
                28 => Self::H28, 29 => Self::H29, 30 => Self::H30, _ => Self::H31,
            },
            4 => match n {
                0 => Self::S0, 1 => Self::S1, 2 => Self::S2, 3 => Self::S3,
                4 => Self::S4, 5 => Self::S5, 6 => Self::S6, 7 => Self::S7,
                8 => Self::S8, 9 => Self::S9, 10 => Self::S10, 11 => Self::S11,
                12 => Self::S12, 13 => Self::S13, 14 => Self::S14, 15 => Self::S15,
                16 => Self::S16, 17 => Self::S17, 18 => Self::S18, 19 => Self::S19,
                20 => Self::S20, 21 => Self::S21, 22 => Self::S22, 23 => Self::S23,
                24 => Self::S24, 25 => Self::S25, 26 => Self::S26, 27 => Self::S27,
                28 => Self::S28, 29 => Self::S29, 30 => Self::S30, _ => Self::S31,
            },
            8 => match n {
                0 => Self::D0, 1 => Self::D1, 2 => Self::D2, 3 => Self::D3,
                4 => Self::D4, 5 => Self::D5, 6 => Self::D6, 7 => Self::D7,
                8 => Self::D8, 9 => Self::D9, 10 => Self::D10, 11 => Self::D11,
                12 => Self::D12, 13 => Self::D13, 14 => Self::D14, 15 => Self::D15,
                16 => Self::D16, 17 => Self::D17, 18 => Self::D18, 19 => Self::D19,
                20 => Self::D20, 21 => Self::D21, 22 => Self::D22, 23 => Self::D23,
                24 => Self::D24, 25 => Self::D25, 26 => Self::D26, 27 => Self::D27,
                28 => Self::D28, 29 => Self::D29, 30 => Self::D30, _ => Self::D31,
            },
            _ => match n {
                0 => Self::Q0, 1 => Self::Q1, 2 => Self::Q2, 3 => Self::Q3,
                4 => Self::Q4, 5 => Self::Q5, 6 => Self::Q6, 7 => Self::Q7,
                8 => Self::Q8, 9 => Self::Q9, 10 => Self::Q10, 11 => Self::Q11,
                12 => Self::Q12, 13 => Self::Q13, 14 => Self::Q14, 15 => Self::Q15,
                16 => Self::Q16, 17 => Self::Q17, 18 => Self::Q18, 19 => Self::Q19,
                20 => Self::Q20, 21 => Self::Q21, 22 => Self::Q22, 23 => Self::Q23,
                24 => Self::Q24, 25 => Self::Q25, 26 => Self::Q26, 27 => Self::Q27,
                28 => Self::Q28, 29 => Self::Q29, 30 => Self::Q30, _ => Self::Q31,
            },
        }
    }

    pub fn as_str(self) -> &'static str {
        use Register::*;
        match self {
            None => "",
            X0 => "x0", X1 => "x1", X2 => "x2", X3 => "x3", X4 => "x4", X5 => "x5", X6 => "x6", X7 => "x7",
            X8 => "x8", X9 => "x9", X10 => "x10", X11 => "x11", X12 => "x12", X13 => "x13", X14 => "x14", X15 => "x15",
            X16 => "x16", X17 => "x17", X18 => "x18", X19 => "x19", X20 => "x20", X21 => "x21", X22 => "x22", X23 => "x23",
            X24 => "x24", X25 => "x25", X26 => "x26", X27 => "x27", X28 => "x28", X29 => "x29", X30 => "x30", XZR => "xzr",
            SP => "sp",
            W0 => "w0", W1 => "w1", W2 => "w2", W3 => "w3", W4 => "w4", W5 => "w5", W6 => "w6", W7 => "w7",
            W8 => "w8", W9 => "w9", W10 => "w10", W11 => "w11", W12 => "w12", W13 => "w13", W14 => "w14", W15 => "w15",
            W16 => "w16", W17 => "w17", W18 => "w18", W19 => "w19", W20 => "w20", W21 => "w21", W22 => "w22", W23 => "w23",
            W24 => "w24", W25 => "w25", W26 => "w26", W27 => "w27", W28 => "w28", W29 => "w29", W30 => "w30", WZR => "wzr",
            WSP => "wsp",
            V0 => "v0", V1 => "v1", V2 => "v2", V3 => "v3", V4 => "v4", V5 => "v5", V6 => "v6", V7 => "v7",
            V8 => "v8", V9 => "v9", V10 => "v10", V11 => "v11", V12 => "v12", V13 => "v13", V14 => "v14", V15 => "v15",
            V16 => "v16", V17 => "v17", V18 => "v18", V19 => "v19", V20 => "v20", V21 => "v21", V22 => "v22", V23 => "v23",
            V24 => "v24", V25 => "v25", V26 => "v26", V27 => "v27", V28 => "v28", V29 => "v29", V30 => "v30", V31 => "v31",
            Q0 => "q0", Q1 => "q1", Q2 => "q2", Q3 => "q3", Q4 => "q4", Q5 => "q5", Q6 => "q6", Q7 => "q7",
            Q8 => "q8", Q9 => "q9", Q10 => "q10", Q11 => "q11", Q12 => "q12", Q13 => "q13", Q14 => "q14", Q15 => "q15",
            Q16 => "q16", Q17 => "q17", Q18 => "q18", Q19 => "q19", Q20 => "q20", Q21 => "q21", Q22 => "q22", Q23 => "q23",
            Q24 => "q24", Q25 => "q25", Q26 => "q26", Q27 => "q27", Q28 => "q28", Q29 => "q29", Q30 => "q30", Q31 => "q31",
            D0 => "d0", D1 => "d1", D2 => "d2", D3 => "d3", D4 => "d4", D5 => "d5", D6 => "d6", D7 => "d7",
            D8 => "d8", D9 => "d9", D10 => "d10", D11 => "d11", D12 => "d12", D13 => "d13", D14 => "d14", D15 => "d15",
            D16 => "d16", D17 => "d17", D18 => "d18", D19 => "d19", D20 => "d20", D21 => "d21", D22 => "d22", D23 => "d23",
            D24 => "d24", D25 => "d25", D26 => "d26", D27 => "d27", D28 => "d28", D29 => "d29", D30 => "d30", D31 => "d31",
            S0 => "s0", S1 => "s1", S2 => "s2", S3 => "s3", S4 => "s4", S5 => "s5", S6 => "s6", S7 => "s7",
            S8 => "s8", S9 => "s9", S10 => "s10", S11 => "s11", S12 => "s12", S13 => "s13", S14 => "s14", S15 => "s15",
            S16 => "s16", S17 => "s17", S18 => "s18", S19 => "s19", S20 => "s20", S21 => "s21", S22 => "s22", S23 => "s23",
            S24 => "s24", S25 => "s25", S26 => "s26", S27 => "s27", S28 => "s28", S29 => "s29", S30 => "s30", S31 => "s31",
            H0 => "h0", H1 => "h1", H2 => "h2", H3 => "h3", H4 => "h4", H5 => "h5", H6 => "h6", H7 => "h7",
            H8 => "h8", H9 => "h9", H10 => "h10", H11 => "h11", H12 => "h12", H13 => "h13", H14 => "h14", H15 => "h15",
            H16 => "h16", H17 => "h17", H18 => "h18", H19 => "h19", H20 => "h20", H21 => "h21", H22 => "h22", H23 => "h23",
            H24 => "h24", H25 => "h25", H26 => "h26", H27 => "h27", H28 => "h28", H29 => "h29", H30 => "h30", H31 => "h31",
            B0 => "b0", B1 => "b1", B2 => "b2", B3 => "b3", B4 => "b4", B5 => "b5", B6 => "b6", B7 => "b7",
            B8 => "b8", B9 => "b9", B10 => "b10", B11 => "b11", B12 => "b12", B13 => "b13", B14 => "b14", B15 => "b15",
            B16 => "b16", B17 => "b17", B18 => "b18", B19 => "b19", B20 => "b20", B21 => "b21", B22 => "b22", B23 => "b23",
            B24 => "b24", B25 => "b25", B26 => "b26", B27 => "b27", B28 => "b28", B29 => "b29", B30 => "b30", B31 => "b31",
            PC => "pc",
        }
    }
}

/// Exact encoding variant (iced `Code` style). Covers all families decoded here.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
#[repr(u16)]
pub enum Code {
    #[default]
    INVALID = 0,
    // DP immediate
    Adr, Adrp,
    Add_imm, Adds_imm, Sub_imm, Subs_imm,
    And_imm, Orr_imm, Eor_imm, Ands_imm,
    Movn, Movz, Movk,
    Sbfm, Bfm, Ubfm, Extr,
    // DP register
    And_shift, Bic_shift, Orr_shift, Orn_shift,
    Eor_shift, Eon_shift, Ands_shift, Bics_shift,
    Add_shift, Adds_shift, Sub_shift, Subs_shift,
    Add_ext, Adds_ext, Sub_ext, Subs_ext,
    Adc, Adcs, Sbc, Sbcs,
    Ccmp_reg, Ccmp_imm, Ccmn_reg, Ccmn_imm,
    Csel, Csinc, Csinv, Csneg,
    Rbit, Rev16, Rev, Rev32, Clz, Cls,
    Udiv, Sdiv, Lslv, Lsrv, Asrv, Rorv,
    Madd, Msub, Smaddl, Smsubl, Umaddl, Umsubl, Smulh, Umulh,
    // Branches / system
    B, Bl, Br, Blr, Ret,
    B_cond, Cbz, Cbnz, Tbz, Tbnz,
    Svc, Hvc, Smc, Brk, Hlt, Dcps,
    Nop, Yield, Wfe, Wfi, Sev, Sevl,
    Hint, Mrs, Msr, Sys, Sysl,
    Paciasp, Pacibsp, Autia1716, Autib1716, Retab,
    // Loads / stores
    Ldr_lit, Ldrsw_lit, Ldr_fp_lit,
    Ldr_uimm, Ldrb_uimm, Ldrh_uimm, Ldrsb_uimm, Ldrsh_uimm, Ldrsw_uimm,
    Str_uimm, Strb_uimm, Strh_uimm,
    Ldr_imm, Str_imm, // pre/post/unscaled
    Ldr_reg, Str_reg,
    Ldp, Stp, Ldpsw,
    Ldxr, Stxr, Ldxrb, Stxrb, Ldxrh, Stxrh, Ldxrp, Stxrp,
    Ldar, Stlr, Ldarb, Stlrb, Ldarh, Stlrh,
    Ldr_fp_uimm, Str_fp_uimm, Ldp_fp, Stp_fp,
    // SIMD / FP
    Simd_three_same, Simd_modified_imm, Simd_copy, Simd_two_misc,
    Simd_across, Simd_shift_imm, Simd_tbl, Simd_permute, Simd_ext,
    Simd_ldst_multi, Simd_ldst_single, Simd_three_diff, Simd_by_element,
    Fp_data_2src, Fp_conversion, Fp_compare, Fp_imm, Fp_1src,
    Undefined,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum OpKind {
    #[default]
    None,
    Register,
    Immediate,
    Memory,
    NearBranch,
    SystemRegister,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum Condition {
    #[default]
    Eq, Ne, Cs, Cc, Mi, Pl, Vs, Vc,
    Hi, Ls, Ge, Lt, Gt, Le, Al, Nv,
}

impl Condition {
    pub fn from_u32(v: u32) -> Self {
        match v & 0xF {
            0x0 => Self::Eq, 0x1 => Self::Ne, 0x2 => Self::Cs, 0x3 => Self::Cc,
            0x4 => Self::Mi, 0x5 => Self::Pl, 0x6 => Self::Vs, 0x7 => Self::Vc,
            0x8 => Self::Hi, 0x9 => Self::Ls, 0xA => Self::Ge, 0xB => Self::Lt,
            0xC => Self::Gt, 0xD => Self::Le, 0xE => Self::Al, _ => Self::Nv,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq", Self::Ne => "ne", Self::Cs => "hs", Self::Cc => "lo",
            Self::Mi => "mi", Self::Pl => "pl", Self::Vs => "vs", Self::Vc => "vc",
            Self::Hi => "hi", Self::Ls => "ls", Self::Ge => "ge", Self::Lt => "lt",
            Self::Gt => "gt", Self::Le => "le", Self::Al => "al", Self::Nv => "nv",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum ShiftKind {
    #[default]
    None, Lsl, Lsr, Asr, Ror,
}

impl ShiftKind {
    pub fn from_u32(v: u32) -> Self {
        match v & 3 {
            0 => Self::Lsl, 1 => Self::Lsr, 2 => Self::Asr, _ => Self::Ror,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "", Self::Lsl => "lsl", Self::Lsr => "lsr",
            Self::Asr => "asr", Self::Ror => "ror",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum ExtendKind {
    #[default]
    None, Uxtb, Uxth, Uxtw, Uxtx, Sxtb, Sxth, Sxtw, Sxtx,
}

impl ExtendKind {
    pub fn from_u32(v: u32) -> Self {
        match v & 7 {
            0 => Self::Uxtb, 1 => Self::Uxth, 2 => Self::Uxtw, 3 => Self::Uxtx,
            4 => Self::Sxtb, 5 => Self::Sxth, 6 => Self::Sxtw, _ => Self::Sxtx,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Uxtb => "uxtb", Self::Uxth => "uxth", Self::Uxtw => "uxtw", Self::Uxtx => "uxtx",
            Self::Sxtb => "sxtb", Self::Sxth => "sxth", Self::Sxtw => "sxtw", Self::Sxtx => "sxtx",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum MemMode {
    #[default]
    None,
    Offset,   // [base{, #imm}]
    PreIndex, // [base, #imm]!
    PostIndex,// [base], #imm
    Register, // [base, Xm{, extend}]
    Literal,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default)]
pub enum Arrangement {
    #[default]
    None,
    B8, B16, H4, H8, S2, S4, D1, D2,
}
