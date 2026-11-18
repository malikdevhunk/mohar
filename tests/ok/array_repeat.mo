// stdout: 4\n
fn main(caps: Caps) {
    let out = caps.console();
    let a: [u8; 4] = [1; 4];
    out.println(a.len().to_text());
}
