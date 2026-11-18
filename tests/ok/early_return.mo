// stdout: 1\n
fn main(caps: Caps) -> i64 {
    let out = caps.console();
    out.println("1");
    return 1;
}
