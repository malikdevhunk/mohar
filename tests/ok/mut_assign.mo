// stdout: 2\n
fn main(caps: Caps) {
    let out = caps.console();
    let mut n = 1;
    n = n + 1;
    out.println(n.to_text());
}
