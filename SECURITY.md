# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes, as a research compiler. Fixes are best-effort. |

v0.1 is not a production security boundary. The README lists what a well-typed program is aiming at, and what it is not.

## Reporting

Email a report to the address on the GitHub profile `malikdevhunk`, or open a private security advisory on the repository if that feature is enabled. Please include:

- The Mohar source that should have been rejected, or the seal bytes that verified when they should not have.
- The `mohar` version (`mohar --version`) and the Rust version.
- Whether you believe the issue is in the checker, the interpreter's capability host, or the crypto glue.

Give us a chance to look before you publish. A label bug that accepts a secret-to-public flow is in scope. A request for a new feature is an ordinary issue.

## Threat model, short version

In scope for a fix:

- A well-typed program that delivers a `secret` value to a public sink without a named declassifier.
- A well-typed program that delivers an `untrusted` value to a trusted parameter, or that reaches a trusted sink under an untrusted program counter, without a named endorser.
- A capability the program uses at run time that the authority report does not list.
- A path that escapes its scope (`..`, an absolute path, a symlink) and is still opened.
- A seal whose bytes changed and still verifies, or whose embedded IR hash does not match a rebuild.

Out of scope, and said so in the README:

- Timing, cache, power and transient-execution channels. The interpreter is not constant-time.
- A compromised host or a stolen signing key.
- Whether a granted action was a good idea.
- Claims about the absence of bugs in `ml-kem`, `ml-dsa` or `slh-dsa`. Those crates have not been independently audited. Mohar does not add an audit.

## Cryptography

Mohar does not implement a primitive. The seal is ML-DSA-65 via the `ml-dsa` crate. KEMs, signatures, AEAD and hashes in `mohar-std` call RustCrypto. If you need an audited implementation, do not treat the default backend as one.

## Disclosure

We will acknowledge a report, keep you posted, and credit you in the changelog unless you ask us not to. There is no bug bounty.
