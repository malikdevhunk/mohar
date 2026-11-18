# Benchmarks

v0.1 does not publish timing numbers. The interpreter is a tree walk and is expected to be slow next to native code. Cryptographic builtins call RustCrypto directly, so their cost is the crate's cost plus the time to copy bytes across the interpreter boundary.

When you measure, record the machine, the Rust version, and the command. `tests/ok/fib.mo` is a reasonable first loop. Do not compare with a number you did not run, and do not describe the interpreter as constant-time.
