use std.pq::{Kem, KemPublicKey};

fn open_channel(net: Net<"relay.example.com:443">, peer: KemPublicKey) -> secret [u8; 32] {
    let kem = Kem::default();
    let (ct, shared) = kem.encaps(peer);
    net.send(ct.to_bytes());
    shared
}

fn main(caps: Caps) {
    let out = caps.console();
    let rand = caps.rand();
    let net = caps.net::<"relay.example.com:443">();
    let kem = Kem::default();
    let (sk, peer) = Kem::generate(rand);
    let _ = sk;
    let _shared = open_channel(net, peer);
    out.println("channel open");
}
