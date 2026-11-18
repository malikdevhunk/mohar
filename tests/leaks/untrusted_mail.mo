// error: E301
fn main(caps: Caps) {
    let inbox = caps.fs_read::<"./inbox">();
    let mail = caps.tool::<"mail.send">();
    let summary: untrusted Text = inbox.read_text("a.txt");
    let to = Email::parse(summary);
    mail.call(to, "body");
}
