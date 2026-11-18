use std.aead;

fn main(caps: Caps) {
    let log = caps.console();
    let key: secret [u8; 32] = caps.rand().secret_bytes::<32>();
    let nonce: [u8; 12] = caps.rand().public_bytes::<12>();
    let sealed: Bytes = aead::seal(key, nonce, "release-token".to_bytes());
    log.println(sealed.to_hex());
}
