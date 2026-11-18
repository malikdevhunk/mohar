// error: E205
fn main(caps: Caps) {
    let page: untrusted Text = "x";
    let trusted = endorse(page, "operator said so");
}
