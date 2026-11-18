// stdout: 10\n
fn main(caps: Caps) {
    let out = caps.console();
    let mut s = 0;
    for i in 0..5 { s = s + i; }
    out.println(s.to_text());
}
