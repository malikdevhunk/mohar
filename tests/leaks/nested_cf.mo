// error: E302
fn main(caps: Caps) {
    let net = caps.net::<"api.example.com:443">();
    let page: untrusted Text = "x";
    if page == "x" {
        if true {
            net.send("hi".to_bytes());
        }
    }
}
