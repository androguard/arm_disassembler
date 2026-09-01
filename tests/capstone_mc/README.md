# Capstone AArch64 MC corpus

Source: https://github.com/capstone-engine/capstone/tree/next/suite/MC/AArch64

These `.cs` files are Capstone's machine-code regression inputs (LLVM MC derived).
Refresh:

```bash
cd tests/capstone_mc
curl -sL 'https://api.github.com/repos/capstone-engine/capstone/contents/suite/MC/AArch64?ref=next' \
  | python3 -c '...'  # see project history / scripts
```

Run:

```bash
cargo test --test capstone_mc_tests
```
