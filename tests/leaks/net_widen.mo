// error: E202
fn talk(net: Net<"api.example.com:443">) {
    net.send("hi".to_bytes());
}
fn main(caps: Caps) {
    let net = caps.net::<"example.com:443">();
    talk(net);
}
