# Prior art

Mohar is a combination, not a new type theory. The notes below follow the survey in `docs/DESIGN.md` (19 Nov 2026). Star counts there were taken that day and will be stale. Re-check them before a launch post.

## Languages people already use

Rust is the implementation language. It has no capability, effect or information-flow types. `secrecy` and `subtle` are conventions a caller can ignore. Zig's habit of passing the allocator in is a cousin of passing a capability in, and it stops there. Mojo, Move, Cairo, Noir, Vale, Pony, Austral, Koka, Hylo, Unison, Roc and Gleam each solve a real problem (assets, proofs, memory, effects, platforms) and do not ship the pair of label axes plus a signed authority report.

Pony and Austral are the closest mainstream-ish languages on authority. Pony's standard library uses tokens such as `AmbientAuth`. Austral is deliberately small and capability-based. Neither has secrecy and integrity as one lattice, and neither signs an authority manifest with ML-DSA.

## Research the design is borrowing from

Object-capability work: E, Joe-E, Caja, Monte, Wyvern, Scala 3 capture checking, Effekt. Information-flow type systems: Jif, FlowCaml, Paragon, Haskell LIO. Constant-time languages: FaCT, Jasmin, CT-Wasm, Cryptol. Owl mixes information flow with a cryptographic soundness argument for protocols. Macaroons, Biscuit and UCAN are attenuable credentials, not languages. Sigstore, SLSA and CycloneDX CBOM are the supply-chain shapes a seal should be able to sit next to. Deno permissions, WASI and the WebAssembly component model are runtime sandboxes; Mohar wants the same facts in the types, with the runtime as a backstop.

## The neighbours that showed up while the design was being written

Strata is a capability-typed systems language with effects, optional information-flow checking, post-quantum obligations and signed artifacts. It is the closest design on paper, and it is aimed at a large runtime rather than a small plan a person reads before running. Rune describes itself in governance and information-flow terms and lists classical cryptography. Kryos puts capabilities in signatures and talks about provenance for model-written code; the public notes do not describe secrecy labels or a seal. Verum has refinement types and names ML-KEM, ML-DSA and SLH-DSA; its own docs have said the post-quantum backends were not in the build that was current at the time of the survey. CaMeL tracks provenance in a restricted Python plan at runtime. Owl is a protocol language with a proof assistant in the loop.

Mohar does not claim to be first, most secure, or unhackable. The thing it is trying to ship in one small compiler is the list in the design notes: both label axes, scoped capabilities you can read off the types, a human authority report signed with ML-DSA and bound to the artifact hash, a compile-time crypto policy with a CBOM, and constant-time restrictions on secret values.

## Post-quantum status, as checked for the design

NIST published FIPS 203 (ML-KEM), 204 (ML-DSA) and 205 (SLH-DSA) on 13 Aug 2024. NIST IR 8547 is the deprecation timeline Mohar's `Q101` warning cites: deprecate the quantum-vulnerable algorithms, and remove them from the NIST standards by 2035. The RustCrypto crates Mohar links state that they have not been independently audited. Chrome has shipped a hybrid X25519+ML-KEM key exchange by default since late 2024, which is useful context and not a formal verification of this compiler.
