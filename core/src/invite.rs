// Copyright 2020 he avrio core developers

extern crate ring;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};
extern crate bs58;

pub fn per_epoch_limit(nodes: u64) -> u64 {
    return (1 / 3) * (nodes / 2);
}

pub fn generate_invite() -> (String, String) {
    let rngc = randc::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let peer_public_key_bytes = key_pair.public_key().as_ref();
    return(bs58::encode(peer_public_key_bytes).into_string(), bs58::encode(pkcs8_bytes).into_string());
}
