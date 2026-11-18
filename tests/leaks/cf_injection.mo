// error: E302
fn main(caps: Caps) {
    let inbox = caps.fs_read::<"./inbox">();
    let mail = caps.tool::<"mail.send">();
    let page: untrusted Text = inbox.read_text("a.txt");
    if page == "go" {
        mail.call(Email::literal("a@b.example"), page);
    }
}
