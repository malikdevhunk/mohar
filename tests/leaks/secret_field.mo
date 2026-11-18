// error: E105
struct Pair { key: secret [u8; 4], n: i64 }
fn main(caps: Caps) {
    let log = caps.console();
    let p = Pair { key: [1, 2, 3, 4], n: 1 };
    log.println(p.key.to_hex());
}
