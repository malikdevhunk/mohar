// stdout: 8\n
const N: i64 = 3;
fn main(caps: Caps) {
    let out = caps.console();
    out.println((N + 5).to_text());
}
