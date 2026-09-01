# arm_disassembler

Zero-allocation iced-style ARM64 decoder and formatter (`#![no_std]` + `alloc`).

Consumed by [apple-re](https://github.com/androguard/apple-re) and
[arm_decompiler](https://github.com/androguard/arm_decompiler) as a sibling path dependency.

## Layout

```
androguard/
  apple-re/
  arm_decompiler/
  arm_disassembler/   ← this repo
```

## Build & test

```bash
cargo test
cargo test --test capstone_mc_tests
cargo run --example fail_hist
```

Capstone AArch64 MC corpus notes: [`tests/capstone_mc/README.md`](tests/capstone_mc/README.md).

Coverage focus is A64 + scalar FP; AdvSIMD / SVE / SME still have gaps versus Capstone.

## Library usage

```rust
use arm_disassembler::{decode_raw, Decoder, Formatter, SymbolResolver};

let mut dec = Decoder::new(code, text_base_vaddr);
let fmt = Formatter::new();
while dec.can_decode() {
    let ins = dec.decode();
    println!("{}", fmt.format_simple(&ins));
}

let ins = decode_raw(0x1000, 0xD503201F); // nop
assert_eq!(ins.mnemonic.as_str(), "nop");
```
