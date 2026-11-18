# The seal

`mohar build` writes canonical IR. `mohar seal` hashes it, records the authority and the crypto the checker resolved, and signs the RFC 8785 JSON with ML-DSA-65.

```
mohar keygen --out release.key
mohar seal examples/hello.mo --key release.key -o hello.mohar
mohar run --require-seal --trust trusted.toml hello.mohar --grant grant.toml
```

The key file is the 32-byte ML-DSA seed with a one-line header, not a PKCS#8 document. RustCrypto's preferred private-key encoding for ML-DSA is that seed. `release.key.pub` holds the verifying key and a key id (SHA3-256 of the encoded key).

Verification refuses to start unless:

1. A signature checks against a key in the trust file.
2. The embedded IR's SHA3-256 matches the hash in the seal, and a rebuild of the embedded source produces that same hash.
3. If you passed `--grant`, every capability in the seal is inside the grant.

`mohar review file.mohar --against grant.toml` prints the human diff: granted, or `NOT GRANTED`.

Changing one byte of the signed document, including the IR or the authority list, makes verification fail. Tests cover that.

## Crypto policy

`Kem::default()` and `Sig::default()` are not macros you edit by hand. They resolve from `mohar.toml`.

| Policy | `Kem::default` | Legacy import |
|---|---|---|
| `pq-hybrid` | X25519 + ML-KEM-768, then HKDF-SHA3-256 | Warning `Q101` until `allow_legacy_until` |
| `pq-only` | ML-KEM-1024 | Error `E402` |
| `legacy` | Same hybrid KEM | Warning, and you have said you meant to |

`Sig::default()` is ML-DSA-65 in all three. SLH-DSA is available as `Sig::slh_dsa()` (SHA2-128s) if you want a second family.

The hybrid is not X-Wing. The info string is `mohar-hybrid-v1`. The seal records the name `X25519-MLKEM768`.

`mohar cbom --format cyclonedx` prints a cryptographic bill of materials from the call sites the checker saw, not from a binary scanner.

## The audit notice

`ml-kem`, `ml-dsa` and `slh-dsa` have not been independently audited. Mohar prints that when it seals, and it stores the crate versions in the seal. If you need an audited implementation, this backend is not it. Symmetric algorithms in the standard library (ChaCha20-Poly1305, SHA-2, SHA-3) are the same family's crates; they are not the quantum question, and they are still not a Mohar-specific audit.
