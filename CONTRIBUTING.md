# Contributing to Mohar

Thanks for looking. Mohar is a small compiler, and the interesting bugs are usually in the checker: a label that should have been rejected, or a diagnostic that points at the wrong line.

## Ground rules

- Be kind. The [code of conduct](CODE_OF_CONDUCT.md) applies to issues, reviews and chat.
- Do not claim the language is unhackable, quantum-proof, or the first of its kind. The README's limits section is load-bearing. If you change a guarantee, change that section in the same commit.
- No hand-rolled cryptography. New primitives go through `mohar-std` and an existing crate. If a crate says it has not been audited, the docs keep saying that.
- Rustfmt and Clippy are part of the build, not a suggestion.

## Build

Stable Rust, MSRV 1.87.

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`mohar` is the binary from `crates/mohar-cli`.

## Tests worth adding

- A program under `tests/leaks/` that must fail. The first line is `// error: E105` (or whichever code). The corpus test fails if the program type-checks or reports a different code.
- A program under `tests/ok/` that must run. `// stdout: 15\n` compares the console. `// check` only type-checks.
- A lattice property belongs in `mohar-types` and should use `proptest`.

Please include the source span you expect the diagnostic to highlight. The messages are part of the product.

## Commits

Write the message as a sentence about the change. The author and committer for this repository are Saddam Malik. Do not add a `Co-authored-by` trailer.

## Reporting a security issue

See [SECURITY.md](SECURITY.md). Please do not file a public issue for a seal bypass, a label leak the checker accepts, or a problem in the crypto glue.
