# Hello

Mohar looks like a small Rust. Functions, `let`, `if`, `match`, structs and enums. There is no `null`, no exceptions and, in v0.1, no floats.

Every program starts at `main`, and `main` receives the only ambient value in the language: the capability set the host granted.

```mohar
fn main(caps: Caps) {
    let out = caps.console();
    out.println("namaste, duniya");
}
```

`caps.console()` does not open the console by a hidden global. It narrows `Caps` to a `Console` value. The authority report is that value, read back out of the types:

```
authority:  Console (write)
files:      none
network:    none
crypto:     none
verdict:    nothing beyond printing to the terminal
```

Try removing the `caps` parameter and calling `println` anyway. There is no such function. That is G1: no ambient authority.

## Run it

```
mohar run examples/hello.mo
mohar review examples/hello.mo
mohar build examples/hello.mo
```

`build` writes canonical IR and prints its SHA3-256. The same source produces the same hash. The interpreter that `run` uses walks the typed tree; the IR is what a seal binds.
