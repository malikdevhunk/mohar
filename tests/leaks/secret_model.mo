// error: E105
fn main(caps: Caps) {
    let model = caps.model();
    let key: secret Text = "k";
    let _ = model.ask("say", key);
}
