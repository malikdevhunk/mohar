# Mohar

Mohar is a small language where secrets, authority and untrusted input are types — and the compiler hands you a post-quantum-signed **seal** that states exactly what the program can touch.

Created by Saddam Malik.

```
fn main(caps: Caps) {
    let out = caps.console();
    out.println("namaste, duniya");
}
```

```
$ mohar review examples/hello.mo
profile:    default
authority:  Console (write)
files:      none
network:    none
crypto:     none
flows:      no declassify, no endorse
verdict:    nothing beyond printing to the terminal
```

Slogan: **Know what it can touch.**

Mohar combines ideas from object-capability languages, information-flow typing, constant-time crypto DSLs and post-quantum standards into one small language, and adds a signed, human-readable authority seal. [Strata](https://github.com/beardedeagle/strata), Kryos, Rune and CaMeL explore neighbouring ground. The longer comparison is in [docs/prior-art.md](docs/prior-art.md).

## Thirty seconds

```mohar
use std.aead;

fn main(caps: Caps) {
    let log = caps.console();
    let key: secret [u8; 32] = caps.rand().secret_bytes::<32>();
    let nonce: [u8; 12] = caps.rand().public_bytes::<12>();
    let sealed: Bytes = aead::seal(key, nonce, "release-token".to_bytes());
    log.println(sealed.to_hex());
}
```

`log.println(key.to_hex())` does not compile. The key is `secret`, and `Console.println` is a public sink:

```
error[E105]: secret value flows to public sink `Console.println`
  = note: `key` created at line 4 as `secret`
  = help: encrypt it, or request the `Declassify` capability and say why
```

`aead::seal` is a named trusted declassifier. The ciphertext is public by the standard-library contract, and the seal lists that the program used `aead::seal`.

## What the compiler guarantees

For a program that type-checks, v0.1 aims at the following. The evidence is the type checker, the negative corpus under `tests/leaks/`, and the seal tests. It is not a machine-checked proof.

| | Guarantee | How |
|---|---|---|
| G1 | No ambient authority. Code can only use capabilities it was handed. | No global I/O. Capabilities come from `main`'s `Caps` argument and from narrowing. |
| G2 | The authority report matches the program. | Derived from the call graph the interpreter runs. A test compares a traced run with the report. |
| G3 | A secret does not reach a public sink without a named declassifier. | Label flow. `public` may flow into a `secret` slot. The other direction is `E105`. |
| G4 | An untrusted value does not reach a trusted parameter without a named endorser. | Integrity labels, plus the program-counter label (`E301`, `E302`). |
| G5 | Secret-dependent branches, indices, loop bounds and variable-time operations are rejected. | `E101`–`E104`. |
| G6 | The artifact hash is reproducible. | Canonical IR, no floats, sorted authority, pinned dependencies. |
| G7 | A seal cannot be altered quietly. | ML-DSA-65 over RFC 8785 canonical JSON. Tamper tests reject a changed byte. |

## What it does not guarantee

Read this before you trust a seal with anything you care about.

1. **Not a proof.** v0.1 has a typed semantics in the design notes and a test suite, not a mechanised soundness proof.
2. **Constant-time is at the language level only.** Rejecting a secret branch does not make the interpreter, the allocator, the OS or the CPU constant-time. Real timing claims need a backend that emits a constant-time subset and a check of that output. That backend is not in v0.1.
3. **The post-quantum crates have not been independently audited.** Mohar's `pq` and seal code call RustCrypto `ml-kem`, `ml-dsa` and `slh-dsa`. Those crates say so in their own READMEs, and Mohar repeats it. The CLI prints the notice when it seals a program or uses the default backend. "Post-quantum" here means "based on standards designed to resist known quantum attacks." It does not mean proven quantum-proof, and this document does not say quantum-proof.
4. **Termination, timing and resource use are visible.** The label system is termination-insensitive. Fuel and a memory ceiling bound a run. They do not hide how much fuel it used. Lengths of values are treated as a public size channel.
5. **Declassifiers and endorsers are trusted code.** `aead::seal`, `kem::encaps`, `sig::sign`, `ct::verify_eq` and `agent::pick_from` are the trusted base. A bug in one of them is a bug in the guarantee.
6. **A seal says who approved the authority, not that the approver was right.**
7. **Prompt injection is constrained, not cured.** Untrusted text cannot choose a trusted argument or widen authority. A model can still be talked into a bad plan that stays inside the grant, or into harmful content in an untrusted body.
8. **Host and key compromise are out of scope.** If the machine running `mohar run`, or the signing key, is compromised, the seal is worthless.
9. **Hardware side channels and fault injection are out of scope.**
10. **Crypto agility is a policy switch, not a downgrade-protected protocol.** Negotiation belongs to the program.

## Install

Mohar builds with stable Rust. The minimum supported version is 1.87.

```
git clone https://github.com/malikdevhunk/mohar
cd mohar
cargo install --path crates/mohar-cli
mohar check examples/hello.mo
mohar run examples/hello.mo
mohar review examples/hello.mo
```

From a clone you can also run `cargo run -p mohar-cli -- run examples/hello.mo`.

## The rest of the tour

The runnable programs from the design are in [`examples/`](examples/):

| Program | What it shows |
|---|---|
| `hello.mo` | Console authority, and nothing else. |
| `tag_check.mo` | `ct::verify_eq` instead of a secret branch. |
| `seal_token.mo` | A secret key sealed with ChaCha20-Poly1305, then printed as hex. |
| `open_channel.mo` | `Kem::default()` — X25519 + ML-KEM-768 under the hybrid policy. |
| `sign_release.mo` | ML-DSA-65 over a file. |
| `invoice_plan.mo` | A `plan` profile. Untrusted invoice text, trusted recipient. |
| `triage.mo` | A pure function and a narrowed `FsRead`. |
| `legacy_lint.mo` | `Q101` on ECDSA P-256. |

```
mohar run examples/open_channel.mo --grant examples/open_channel.grant.toml --root examples
mohar run examples/invoice_plan.mo --grant examples/invoice_plan.grant.toml --root examples
```

`mohar run file.mo` with no grant is a developer mode: console, randomness and the clock are available, and files, network, tools and the model stay closed. `mohar run --require-seal` grants nothing by default. Pass `--trust` and `--grant`.

```
mohar keygen --out release.key
mohar seal examples/hello.mo --key release.key
mohar cbom examples/legacy_lint.mo --format cyclonedx
```

The default crypto policy lives in `mohar.toml`:

```toml
[crypto]
policy = "pq-hybrid"          # or "pq-only", or "legacy"
allow_legacy_until = "2030-01-01"
```

`pq-only` resolves `Kem::default()` to ML-KEM-1024 and turns a legacy import into `E402`. `pq-hybrid` warns (`Q101`) until the cutoff date. The hybrid is Mohar's own combiner (X25519 and ML-KEM-768, then HKDF-SHA3-256). It is not the IETF X-Wing construction.

## Prior art, briefly

| | Overlap with Mohar | Different in kind |
|---|---|---|
| Rust, Zig | Implementation language; allocator-passing culture. | No information-flow or capability types. |
| Pony, Austral | Capability or linear authority. | No secrecy/integrity pair, no PQC seal. |
| FaCT, Jasmin, CT-Wasm | Secret/public and constant-time rules. | Crypto DSLs, not a general seal. |
| Jif, FlowCaml, LIO | Information-flow type systems. | Research systems, no authority seal. |
| Move | Types as a security boundary. | Assets on a chain, not host authority. |
| CaMeL | Provenance for model-written plans. | Python, checked at runtime. |
| Strata, Kryos, Rune | Young languages in the same neighbourhood. | See the table in the design notes. |

## Layout

```
crates/   mohar-syntax, mohar-diag, mohar-types, mohar-ir,
          mohar-interp, mohar-std, mohar-seal, mohar-cli, mohar-wasm
examples/ the eight programs above
tests/    ok/, leaks/, grants
docs/     tutorial, prior art, decisions
```

The v0.1 pipeline is a hand-written lexer and Pratt parser, a bidirectional checker, a canonical labelled IR whose SHA3-256 is the artifact hash, and a tree-walking interpreter. Crypto is thin glue over RustCrypto. No primitive is implemented in this repository.

## Status

v0.1.0 is the first cut that a person can read, run and refuse. The roadmap after this tag:

- **v0.2** — Wasm backend, `mohar fmt` that keeps comments, rewriting of pure secret branches into selects, real `Net`.
- **v0.3** — Cranelift, an output-level constant-time check, user generics, a language server, a proof sketch of noninterference.
- **v0.4** — Delegation tokens in the style of Biscuit or UCAN.

A browser playground crate (`mohar-wasm`) exposes the checker as a library. The page under `playground/` is static; serving a compiled Wasm build is the next step, not this tag.

## License

MIT. Copyright (c) 2026 Saddam Malik. See [LICENSE](LICENSE).
