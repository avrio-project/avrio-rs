use serde::{Deserialize, Serialize};
use libsodium_sys::{
    crypto_box_keypair, sodium_init,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Keypair {
    publickey: [u8; 16],
    privatekey: [u8; 32],
}

fn generateKeys() -> Keypair {
    let out: Keypair;

    if sodium_init() == -1 {
        return out;
    } else {
        crypto_box_keypair(out.publickey, out.privatekey);
        return out;
    }
}

fn hash(msg: String) -> String {
    String::from("")
}
