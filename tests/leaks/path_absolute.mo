// error: E206
fn main(caps: Caps) {
    let fs = caps.fs_read::<"./inbox">();
    let _ = fs.read("/etc/passwd");
}
