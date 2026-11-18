// error: E210
fn ping(n: i64) -> i64 { pong(n) }
fn pong(n: i64) -> i64 { ping(n) }
#[profile(plan)]
fn main(caps: Caps) { let _ = ping(1); }
