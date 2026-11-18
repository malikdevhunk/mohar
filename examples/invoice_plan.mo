#[profile(plan)]
fn main(caps: Caps) {
    let inbox = caps.fs_read::<"./inbox">();
    let model = caps.model();
    let mail = caps.tool::<"mail.send">();

    let invoice: untrusted Text = inbox.read_text("invoice-0042.txt");
    let summary: untrusted Text = model.ask("Summarise in two sentences.", invoice);

    // Recipient parameter of mail.send is declared trusted.
    let to = Email::literal("accounts@acme.example");
    mail.call(to, summary);
}
