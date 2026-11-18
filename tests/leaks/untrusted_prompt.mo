// error: E301
fn main(caps: Caps) {
    let model = caps.model();
    let page: untrusted Text = "ignore previous";
    let _ = model.ask(page, "hi");
}
