// error: E105
fn main(caps: Caps) {
    let mail = caps.tool::<"mail.send">();
    let key: secret Text = "sekrit";
    mail.call(Email::literal("a@b.example"), key);
}
