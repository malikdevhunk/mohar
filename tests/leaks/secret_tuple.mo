// error: E105
fn main(caps: Caps) {
    let log = caps.console();
    let t = (1, caps.rand().secret_bytes::<4>());
    let (_a, b) = t;
    log.println(b.to_hex());
}
