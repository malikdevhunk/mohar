// stdout: 9\n
fn parse(n: i64) -> Result<i64, Text> { Ok(n) }
fn main(caps: Caps) -> Result<Unit, Text> {
    let out = caps.console();
    let n = parse(9)?;
    out.println(n.to_text());
    Ok(())
}
