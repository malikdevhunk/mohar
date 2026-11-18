// stdout: 55\n
fn fib(n: i64) -> i64 {
    if n < 2 { n } else { fib(n - 1) + fib(n - 2) }
}
fn main(caps: Caps) {
    let out = caps.console();
    out.println(fib(10).to_text());
}
