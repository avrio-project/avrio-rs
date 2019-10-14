
use libsodium_sys::{
    sodium_init,
    randombytes_buf,
    crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES,
    crypto_box_keypair,
    crypto_scalarmult,
    crypto_secretbox_easy,
    crypto_secretbox_open_easy,
    crypto_secretbox_MACBYTES,
    sodium_memzero,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct keypair{
    publickey: [u8; crypto_box_PUBLICKEYBYTES],
    privatekey: [u8; crypto_box_SECRETKEYBYTES],
}

fn generateKeys()-> keypair {
    let out: keypair;
    if (sodium_init() == -1) {
        return out;
    }else {
        crypto_box_keypair(out.publickey, out.privatekey);
        return out;
    }

}

fn hash(msg: String) -> String {
    
}
