// error: E103
fn bad(xs: secret List<i64>) -> i64 {
    let mut s = 0;
    for x in xs { s = s + x; }
    s
}
