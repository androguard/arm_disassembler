//! Capstone-style MC regression harness.
//!
//! Corpus: Capstone `suite/MC/AArch64/*.cs`
//! <https://github.com/capstone-engine/capstone/tree/next/suite/MC/AArch64>
//!
//! Line format: `0xaa,0xbb,0xcc,0xdd = asm` (little-endian bytes).

#![cfg(test)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use std::fs;
use std::path::PathBuf;

use arm_disassembler::{decode_raw, Formatter, Mnemonic};

fn parse_cs_line(line: &str) -> Option<(u32, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (bytes_part, asm_part) = if let Some(i) = line.find("==") {
        (&line[..i], &line[i + 2..])
    } else if let Some(i) = line.find('=') {
        (&line[..i], &line[i + 1..])
    } else {
        return None;
    };
    let mut bytes = Vec::new();
    for tok in bytes_part.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let v = u8::from_str_radix(tok.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()?;
        bytes.push(v);
    }
    if bytes.len() < 4 {
        return None;
    }
    let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let asm = asm_part.trim().to_string();
    if asm.is_empty() {
        return None;
    }
    Some((raw, asm))
}

fn expected_mnemonic(asm: &str) -> String {
    asm.split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn our_mnemonic_str(m: Mnemonic) -> String {
    m.as_str().to_ascii_lowercase()
}

fn normalize_asm(s: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for ch in s.chars() {
        if ch == '\t' || ch == ' ' {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_space = false;
        }
    }
    out.trim().to_string()
}

fn mnemonics_match(got: &str, exp: &str) -> bool {
    if got == exp {
        return true;
    }
    // Capstone conditional branch `b.eq` vs our `b` / `bcond`
    if exp.starts_with("b.") && (got == "b" || got == "bcond") {
        return true;
    }
    false
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/capstone_mc")
}

fn is_base_isa_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("arm64-")
        || n.starts_with("arm64e")
        || n.starts_with("armv8.")
        || n.starts_with("a64-")
        || n == "add.s.cs"
}

fn load_cases<F: Fn(&str) -> bool>(include: F) -> Vec<(String, u32, String)> {
    let dir = corpus_dir();
    let mut cases = Vec::new();
    let Ok(rd) = fs::read_dir(&dir) else {
        return cases;
    };
    for ent in rd.flatten() {
        let path = ent.path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        if !name.ends_with(".cs") || !include(&name) {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            if let Some((raw, asm)) = parse_cs_line(line) {
                cases.push((name.clone(), raw, asm));
            }
        }
    }
    cases
}

fn run_cases(cases: &[(String, u32, String)]) -> (usize, usize, Vec<String>) {
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut samples = Vec::new();
    for (file, raw, asm) in cases {
        let ins = decode_raw(0, *raw);
        let got = our_mnemonic_str(ins.mnemonic);
        let exp = expected_mnemonic(asm);
        if mnemonics_match(&got, &exp) {
            pass += 1;
        } else {
            fail += 1;
            if samples.len() < 30 {
                samples.push(format!(
                    "{file}: {raw:#010x} expected `{exp}` got `{got}` asm=`{asm}`"
                ));
            }
        }
    }
    (pass, fail, samples)
}

fn assert_rate(label: &str, pass: usize, fail: usize, min: f64, samples: &[String]) {
    let total = pass + fail;
    eprintln!("{label}: {pass}/{total} ({:.1}%)", 100.0 * pass as f64 / total.max(1) as f64);
    for s in samples {
        eprintln!("  FAIL {s}");
    }
    assert!(total > 0, "{label}: empty corpus");
    let rate = pass as f64 / total as f64;
    assert!(
        rate >= min,
        "{label}: pass rate {:.1}% < {:.0}% ({pass}/{total})",
        rate * 100.0,
        min * 100.0
    );
}

#[test]
fn capstone_mc_core_a64_mnemonics() {
    let cases = load_cases(|n| {
        n.contains("arm64-arithmetic")
            || n.contains("arm64-branch")
            || n.contains("arm64-logical")
            || n.contains("arm64-bitfield")
            || n.contains("arm64-memory")
            || n.contains("arm64-adr")
            || n.contains("arm64-aliases")
            || n.contains("arm64-basic")
            || n == "add.s.cs"
            || n.contains("arm64-system-encoding")
    });
    let (pass, fail, samples) = run_cases(&cases);
    assert_rate("core A64", pass, fail, 0.91, &samples);
}

#[test]
fn capstone_mc_fp_encoding_mnemonics() {
    let cases = load_cases(|n| n.contains("arm64-fp-encoding"));
    let (pass, fail, samples) = run_cases(&cases);
    assert_rate("scalar FP", pass, fail, 0.90, &samples);
}

#[test]
fn capstone_mc_advsimd_mnemonics() {
    let cases = load_cases(|n| n.contains("arm64-advsimd") || n.contains("arm64-crypto") || n.contains("arm64-simd-ldst"));
    let (pass, fail, samples) = run_cases(&cases);
    assert_rate("AdvSIMD/crypto/ldst", pass, fail, 0.88, &samples);
}

#[test]
fn capstone_mc_base_isa_no_sve() {
    let cases = load_cases(is_base_isa_file);
    let (pass, fail, samples) = run_cases(&cases);
    assert_rate("base ISA (arm64-/armv8. corpus)", pass, fail, 0.85, &samples);
}

#[test]
fn capstone_mc_full_corpus_report() {
    let cases = load_cases(|_| true);
    let (pass, fail, samples) = run_cases(&cases);
    // Full Capstone corpus includes thousands of SVE/SME encodings not yet decoded.
    assert_rate("FULL Capstone MC AArch64", pass, fail, 0.77, &samples);
}

#[test]
fn capstone_mc_sample_asm_format() {
    let fmt = Formatter::new();
    let ins = decode_raw(0, 0x1a030041);
    assert_eq!(ins.mnemonic, Mnemonic::Adc);
    let s = normalize_asm(&fmt.format_simple(&ins));
    assert!(s.starts_with("adc "), "{s}");
    assert!(s.contains("w1") && s.contains("w2") && s.contains("w3"), "{s}");

    let fdiv = decode_raw(0, 0x1e231841);
    assert_eq!(fdiv.mnemonic, Mnemonic::Fdiv, "got {}", fdiv.mnemonic.as_str());

    let line = "0x41,0x18,0x23,0x1e = fdiv\ts1, s2, s3";
    let (raw, asm) = parse_cs_line(line).expect("parse");
    assert_eq!(raw, 0x1e231841);
    let ins = decode_raw(0, raw);
    assert!(mnemonics_match(
        &our_mnemonic_str(ins.mnemonic),
        &expected_mnemonic(&asm)
    ));
}
