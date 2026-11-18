// stdout: 2\n
fn main(caps: Caps) {
    let out = caps.console();
    let (a, b) = (1, 2);
    out.println(b.to_text());
}
