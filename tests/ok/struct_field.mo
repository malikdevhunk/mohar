// stdout: 4\n
struct Point { x: i64, y: i64 }
fn main(caps: Caps) {
    let out = caps.console();
    let p = Point { x: 1, y: 3 };
    out.println((p.x + p.y).to_text());
}
