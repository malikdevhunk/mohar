// stdout: 7\n
fn main(caps: Caps) {
    let out = caps.console();
    let v: Option<i64> = Some(7);
    match v { Some(n) => out.println(n.to_text()), None => out.println("no") }
}
