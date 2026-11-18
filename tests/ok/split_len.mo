// stdout: 3\n
fn count_words(text: untrusted Text) -> u64 { text.split_whitespace().len() }
fn main(caps: Caps) {
    let out = caps.console();
    let t: untrusted Text = "one two three";
    out.println(count_words(t).to_text());
}
