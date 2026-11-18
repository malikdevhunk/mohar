// stdout: 6\n
fn double(n: i64) -> i64 { n + n }
fn main(caps: Caps) {
    let out = caps.console();
    out.println(double(3).to_text());
}
