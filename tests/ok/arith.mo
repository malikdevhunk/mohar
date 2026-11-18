// stdout: 15\n
fn main(caps: Caps) {
    let out = caps.console();
    let n = (1 + 2) * 3 + 6;
    out.println(n.to_text());
}
