// stdout: 6869\n
fn main(caps: Caps) {
    let out = caps.console();
    let b = "hi".to_bytes();
    out.println(b.to_hex());
}
