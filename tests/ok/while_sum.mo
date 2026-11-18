// stdout: 10\n
fn main(caps: Caps) {
    let out = caps.console();
    let mut i = 0;
    let mut s = 0;
    while i < 5 { s = s + i; i = i + 1; }
    out.println(s.to_text());
}
