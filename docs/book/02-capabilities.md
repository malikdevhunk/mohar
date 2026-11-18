# Capabilities

A capability is an unforgeable value. You cannot write `Console { }` (`E201`). You derive one from `caps`, and you can only narrow it.

```mohar
let docs = caps.fs_read::<"./inbox/2026">();
let net  = caps.net::<"relay.example.com:443">();
let mail = caps.tool::<"mail.send">();
```

The string inside `<...>` is a scope. For files it is a directory prefix. For network it is `host:port`, and a more specific host is a subtype of a suffix (`api.example.com:443` may be passed where `example.com:443` is expected, not the other way round). Tool names are equal or they are not: `mail.draft` is not `mail.send` (`E202`).

Passing a wider capability where a narrower one is required is a type error. Scopes only get narrower: `FsRead<"./inbox/2026/q1">` is a subtype of `FsRead<"./inbox/2026">`. The runtime checks again, and it refuses `..`, absolute paths and symlinks (`E206` when the path is a literal).

## Pure functions

```mohar
fn count_words(text: untrusted Text) -> u64 {
    text.split_whitespace().len()
}
```

No capability in the signature, no capability captured (closures cannot capture in v0.1). `count_words` cannot read a file even if the caller can. That is the whole point of passing `docs` into `triage` in `examples/triage.mo` instead of passing all of `caps`.

## Profiles

- `default` — ordinary programs. `while` and recursion are allowed. Fuel still stops a runaway loop.
- `sealed` — scopes are string literals, and a seal is meaningful.
- `plan` — `sealed`, plus no recursion and no `while`. Loops are `for` over a range or a list. This is the profile meant for a plan a person will approve by reading the authority report.

```mohar
#[profile(plan)]
fn main(caps: Caps) { /* ... */ }
```

`E210` is recursion in a plan. `E211` is `while` in a plan. Non-recursive helpers are allowed; forbidding every helper made the totality argument simpler and the examples worse, so v0.1 allows an acyclic call graph. That choice is recorded in `docs/v0.1-decisions.md`.
