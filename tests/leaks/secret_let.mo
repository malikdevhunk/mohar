// error: E105
fn main(caps: Caps) {
    let log = caps.console();
    let key: secret i64 = 4;
    let copy = key;
    log.println(copy.to_text());
}
