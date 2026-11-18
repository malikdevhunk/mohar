// stdout: 3\n
enum Color { Red, Blue(i64) }
fn main(caps: Caps) {
    let out = caps.console();
    let c = Color::Blue(3);
    let n = match c { Color::Red => 0, Color::Blue(k) => k };
    out.println(n.to_text());
}
