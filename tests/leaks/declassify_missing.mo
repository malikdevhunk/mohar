// error: E204
fn main(caps: Caps) {
    let key: secret i64 = 1;
    let pub_key = declassify(key, "because");
}
