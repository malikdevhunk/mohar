// error: E105
enum Box { Hold(secret i64), Empty }
fn main(caps: Caps) {
    let log = caps.console();
    let v = Box::Hold(7);
    match v { Box::Hold(n) => log.println(n.to_text()), Box::Empty => log.println("e") }
}
