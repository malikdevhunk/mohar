// error: E211
#[profile(plan)]
fn main(caps: Caps) {
    let mut i = 0;
    while i < 3 { i = i + 1; }
}
