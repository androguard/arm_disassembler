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
    arm_disassembler-py/   Python bindings (PyO3 / maturin)
```

## Build & test

```bash
cargo test
cargo test --test capstone_mc_tests
cargo run --example fail_hist
```

Capstone AArch64 MC corpus notes: [`tests/capstone_mc/README.md`](tests/capstone_mc/README.md).

Coverage focus is A64 + scalar FP; AdvSIMD / SVE / SME still have gaps versus Capstone.

## Rust usage

```rust
use arm_disassembler::{decode_raw, Decoder, Formatter};

// A64 little-endian: nop; mov x0, #1; ret
let code: &[u8] = &[
    0x1f, 0x20, 0x03, 0xd5,
    0x20, 0x00, 0x80, 0xd2,
    0xc0, 0x03, 0x5f, 0xd6,
];

let mut dec = Decoder::new(code, 0x1000);
let fmt = Formatter::new();
while dec.can_decode() {
    let ins = dec.decode();
    println!("{:#x}: {}", ins.vaddr, fmt.format_simple(&ins));
}
// 0x1000: nop
// 0x1004: mov x0, #0x1
// 0x1008: ret

let ins = decode_raw(0x1000, 0xD503201F); // nop
assert_eq!(ins.mnemonic.as_str(), "nop");
assert_eq!(fmt.format_simple(&ins), "nop");
```

Path dependency from a sibling crate:

```toml
[dependencies]
arm_disassembler = { path = "../arm_disassembler" }
```

## Python usage

Bindings live in [`arm_disassembler-py/`](arm_disassembler-py/). Build and install with [maturin](https://www.maturin.rs/):

```bash
cd arm_disassembler-py
python3 -m venv .venv && source .venv/bin/activate
pip install maturin
maturin develop
```

```python
from arm_disassembler import disassemble, decode_one, decode_bytes

# A64 little-endian: nop; mov x0, #1; ret
code = bytes([
    0x1f, 0x20, 0x03, 0xd5,
    0x20, 0x00, 0x80, 0xd2,
    0xc0, 0x03, 0x5f, 0xd6,
])

for ins in disassemble(code, base_vaddr=0x1000):
    print(f"{ins['vaddr']:#x}: {ins['text']}")
# 0x1000: nop
# 0x1004: mov x0, #0x1
# 0x1008: ret

print(decode_one(0xD503201F, vaddr=0x1000))
# {'vaddr': 4096, 'raw': 3573751839, 'length': 4, 'mnemonic': 'nop', 'text': 'nop'}

print(decode_bytes(b"\x1f\x20\x03\xd5", vaddr=0x1000))
# same dict as above
```

Each instruction dict has `vaddr`, `raw`, `length`, `mnemonic`, and `text`.
