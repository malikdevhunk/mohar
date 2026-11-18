// error: E102
fn bad(buf: [u8; 4], i: secret u64) -> u8 {
    buf[i]
}
