// error: E105
fn leak(s: secret i64) -> i64 { s }
fn main(caps: Caps) {
    let log = caps.console();
    log.println(leak(3).to_text());
}
