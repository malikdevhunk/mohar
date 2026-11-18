// error: E101
fn bad(expected: secret [u8; 32], given: [u8; 32]) -> bool {
    if expected == given { true } else { false }
}
