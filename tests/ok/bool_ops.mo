// stdout: true\n
fn main(caps: Caps) {
    let out = caps.console();
    let b = true && !false || false;
    out.println(b.to_text());
}
