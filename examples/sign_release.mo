use std.pq::{Sig, SigSecretKey};

fn sign_release(fs: FsRead<"./dist">, sk: secret SigSecretKey) -> Bytes {
    let artifact = fs.read("app-0.1.0.tar");
    Sig::default().sign(sk, artifact)
}

fn main(caps: Caps) {
    let out = caps.console();
    let fs = caps.fs_read::<"./dist">();
    let rand = caps.rand();
    let (sk, pk) = Sig::generate(rand);
    let _ = pk;
    let sig = sign_release(fs, sk);
    out.println(sig.len().to_text());
}
