// error: E301
fn takes(name: Text) -> Text { name }
fn main(caps: Caps) {
    let page: untrusted Text = "x";
    let _ = takes(page);
}
