// error: E202
fn read_q1(docs: FsRead<"./inbox/2026/q1">) {
    let _ = docs.read_text("q.txt");
}
fn main(caps: Caps) {
    let docs = caps.fs_read::<"./inbox/2026">();
    read_q1(docs);
}
