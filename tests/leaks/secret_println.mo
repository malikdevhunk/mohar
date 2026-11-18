// error: E105
fn main(caps: Caps) {
    let log = caps.console();
    let key: secret [u8; 32] = caps.rand().secret_bytes::<32>();
    log.println(key.to_hex());
}
