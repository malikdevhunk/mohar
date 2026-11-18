// Pure: no capabilities in the signature, cannot touch anything.
fn count_words(text: untrusted Text) -> u64 {
    text.split_whitespace().len()
}

fn triage(docs: FsRead<"./inbox/2026">) -> List<u64> {
    let mut counts = List::new();
    for name in docs.list() {
        counts.push(count_words(docs.read_text(name)));
    }
    counts
}

fn main(caps: Caps) {
    let out = caps.console();
    let docs = caps.fs_read::<"./inbox/2026">();
    let counts = triage(docs);
    out.println(counts.len().to_text());
}
