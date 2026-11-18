// error: E209
// grant: deny-net
fn main(caps: Caps) {
    let net = caps.net::<"evil.example:443">();
}
