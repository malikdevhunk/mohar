// stdout: yes\n
fn main(caps: Caps) {
    let out = caps.console();
    let n = 3;
    if n > 1 { out.println("yes"); } else { out.println("no"); }
}
