// error: E102
fn bad(xs: List<u8>, i: secret i64) -> u8 {
    let v = xs.get(i);
    0
}
