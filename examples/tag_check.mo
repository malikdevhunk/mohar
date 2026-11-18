use std.ct;

// `expected` is secret. Comparing it to the attacker-supplied `given`
// must not leak how many bytes matched.
fn tag_ok(expected: secret [u8; 32], given: [u8; 32]) -> bool {
    ct::verify_eq(expected, given)
}

fn main(caps: Caps) {
    let out = caps.console();
    let expected: secret [u8; 32] = caps.rand().secret_bytes::<32>();
    let given: [u8; 32] = [0; 32];
    if tag_ok(expected, given) {
        out.println("match");
    } else {
        out.println("differ");
    }
}
