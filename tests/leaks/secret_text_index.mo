// error: E102
fn bad(t: secret Text, i: i64) -> u8 {
    let _ = t[i];
    0
}
