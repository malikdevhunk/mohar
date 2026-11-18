# Good first issues

Twelve tasks that a new contributor can finish without redesigning the checker. Each one has a place to start and a way to know it is done.

1. **Colour the severity word.** `mohar-diag` prints plain text. Add a `--color auto` flag on the CLI that paints `error` and `warning`, and leave tests on the plain renderer. Done when `mohar check` on `tests/leaks/secret_branch.mo` is unchanged with `--color never`.

2. **Unused `let` warning.** The checker accepts `let n = 1;` and never mentions it. Warn, with the binding's span. Done when a new file under `tests/ok` expects the warning and still runs.

3. **`mohar fmt` should be idempotent on `examples/`.** Format each example and format again. Done when the second format is a no-op, and a test locks that in. Comments will still be dropped; say so in the test name.

4. **Column numbers for tabs.** A tab currently counts as one column. Decide on width 4, update `mohar-diag`, and add a lexer test with a tab before `if`.

5. **Better unknown-method errors.** `no method to_hex on i64` should suggest `to_text` when the receiver is an integer. Done when the diagnostic contains the suggestion.

6. **Grant-file errors should name the key.** A grant with `nett = ["x"]` is currently a TOML error or a silent ignore. Reject unknown keys with the file path and the key. Done when a unit test covers `nett`.

7. **CBOM evidence should be `file:line:col`.** `mohar cbom` currently prints byte offsets. Thread the `SourceFile` into `cbom_json` and print `legacy_lint.mo:1:1`. Done when the example's CBOM contains that string.

8. **A `// error:` corpus test for `E006`.** Write a non-exhaustive `match` on the `Color` enum from `tests/ok/enum_match.mo` and expect `E006`. The harness already reads the header.

9. **Document `plan` totality in the tutorial.** `docs/book/03-labels.md` does not yet walk through a mutual recursion being rejected. Add a short section and a `tests/leaks` file if one is missing. `plan_mutual.mo` is the specimen.

10. **REPL: print the value of the tail.** `mohar repl` prints console output and drops the value `main` returns. Print `-> 15` when the result is not `Unit`. Done when a one-line session in a test (or a comment with a transcript) shows it.

11. **SHA-512 next to SHA3-256.** Add `std.hash::sha512` as a thin call to the `sha2` crate, with a known-answer test for `abc`. It is public output, not a declassifier. Update the crypto list in the README only if the default policy changes; this is an extra function, not a new default.

12. **Benchmark note for `fib(10)`.** `bench/RESULTS.md` has no numbers. Time `tests/ok/fib.mo` with `mohar run` on your machine, record the hardware, and add a row. Do not claim a comparison you did not run.
