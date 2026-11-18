# Changelog

## 0.1.0 — 2026-11-19

First release of the compiler.

- Hand-written lexer and Pratt parser, with spans, carets and stable error codes (`E0xx` syntax, `E1xx` secrecy, `E2xx` capabilities, `E3xx` integrity, `E4xx` policy, `Q1xx` quantum lints).
- Type checker for secrecy and integrity labels, capability scopes, the `plan` / `sealed` profiles, and the crypto policy.
- Canonical labelled IR and SHA3-256 artifact hashes.
- Tree-walking interpreter with a capability host: fuel, a memory ceiling, path confinement, symlink refusal.
- Standard library glue over RustCrypto: ChaCha20-Poly1305, SHA-2, SHA-3, HKDF, ML-KEM-768/1024, ML-DSA-44/65/87, SLH-DSA (SHA2-128s), X25519 mixed with ML-KEM-768 by HKDF, and ECDSA P-256 for the legacy lint.
- `mohar check`, `run`, `build`, `seal`, `review`, `cbom`, `fmt`, `keygen`, and a small `repl`.
- Seals are RFC 8785 JSON signed with ML-DSA-65. `mohar run --require-seal` checks the signature, the IR hash and the grant.
- Examples from the design notes, a corpus of programs that must not compile, and property tests for the label lattice.

The RustCrypto ML-KEM, ML-DSA and SLH-DSA crates have not been independently audited. The README says so, and the CLI prints a notice when the default backend is used to seal.
