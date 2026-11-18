// error: E105
fn main(caps: Caps) {
    let net = caps.net::<"api.example.com:443">();
    let key: secret [u8; 32] = caps.rand().secret_bytes::<32>();
    net.send(key.to_hex().to_bytes());
}
