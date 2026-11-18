// stdout: 2\n
fn main(caps: Caps) {
    let out = caps.console();
    let mut xs = List::<i64>::new();
    xs.push(1);
    xs.push(2);
    out.println(xs.len().to_text());
}
