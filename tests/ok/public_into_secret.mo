// stdout: ok\n
fn main(caps: Caps) {
    let out = caps.console();
    let s: secret i64 = 4;
    out.println("ok");
}
