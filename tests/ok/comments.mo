// stdout: 1\n
// a comment
fn main(caps: Caps) {
    let out = caps.console();
    /* block */
    out.println("1");
}
