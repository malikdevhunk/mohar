// error: E202
fn send(mail: Tool<"mail.send">) { mail.call("x"); }
fn main(caps: Caps) {
    let t = caps.tool::<"mail.draft">();
    send(t);
}
