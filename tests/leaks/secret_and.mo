// error: E101
fn bad(s: secret bool) -> bool {
    if s && true { true } else { false }
}
