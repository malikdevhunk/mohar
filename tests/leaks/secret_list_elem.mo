// error: E105
fn reveal(x: secret i64) -> i64 {
    x
}

fn main(caps: Caps) {
    let _ = reveal(1);
}
