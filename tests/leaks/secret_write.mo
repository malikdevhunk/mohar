// error: E105
fn main(caps: Caps) {
    let fs = caps.fs_write::<"./out">();
    let key: secret Bytes = "sekrit".to_bytes();
    fs.write("k.bin", key);
}
