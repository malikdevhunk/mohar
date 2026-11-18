// error: E101
fn bad(s: secret i64) -> i64 {
    match s { 0 => 1, _ => 2 }
}
