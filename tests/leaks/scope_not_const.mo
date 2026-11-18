// error: E203
#[profile(sealed)]
fn main(caps: Caps) {
    let docs = caps.fs_read::<Text>();
}
