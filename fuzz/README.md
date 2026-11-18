# Fuzzing

The parser test `parser_does_not_panic_on_noise` and the property tests on the label lattice run under `cargo test`. They are a smoke test: random-looking inputs should not panic the lexer or the parser.

A `cargo-fuzz` target (libFuzzer) is the right next step for multi-hour runs against the lexer, the parser, the checker and the seal verifier. v0.1 does not vendor a fuzz crate, because libFuzzer is a nightly extra and the CI contract is `cargo test` on stable. When you add one, keep the harness free of panics on arbitrary bytes and do not treat a one-hour run as a proof.
