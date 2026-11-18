// error: E103
fn bad(n: secret i64) -> i64 {
    let mut s = 0;
    for i in 0..n { s = s + i; }
    s
}
