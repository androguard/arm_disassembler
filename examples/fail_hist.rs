//! Print Capstone MC mnemonic mismatch histogram (base ISA files).
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use arm_disassembler::decode_raw;

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/capstone_mc");
    let mut hist: HashMap<String, usize> = HashMap::new();
    let mut total = 0usize;
    let mut fail = 0usize;
    for ent in fs::read_dir(&dir).unwrap().flatten() {
        let path = ent.path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".cs") { continue; }
        let n = name.to_ascii_lowercase();
        let base = n.starts_with("arm64-") || n.starts_with("arm64e") || n.starts_with("armv8.") || n.starts_with("a64-") || n == "add.s.cs";
        if !base { continue; }
        let text = fs::read_to_string(&path).unwrap_or_default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let (left, right) = if let Some(i) = line.find("==") {
                (&line[..i], &line[i + 2..])
            } else if let Some(i) = line.find('=') {
                (&line[..i], &line[i + 1..])
            } else {
                continue;
            };
            let mut bytes = Vec::new();
            for tok in left.split(',') {
                let tok = tok.trim().trim_start_matches("0x").trim_start_matches("0X");
                if tok.is_empty() { continue; }
                if let Ok(v) = u8::from_str_radix(tok, 16) { bytes.push(v); }
            }
            if bytes.len() < 4 { continue; }
            let raw = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let exp = right.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            if exp.is_empty() || exp == "=" { continue; }
            total += 1;
            let got = decode_raw(0, raw).mnemonic.as_str().to_ascii_lowercase();
            let ok = got == exp || (exp.starts_with("b.") && (got == "b" || got == "bcond"));
            if !ok {
                fail += 1;
                let key = format!("{exp}←{got}");
                *hist.entry(key).or_default() += 1;
            }
        }
    }
    let mut items: Vec<_> = hist.into_iter().collect();
    items.sort_by(|a,b| b.1.cmp(&a.1));
    println!("base fail {fail}/{total} ({:.1}%)", 100.0 * fail as f64 / total as f64);
    for (k,v) in items.into_iter().take(40) {
        println!("{v:5} {k}");
    }
}
