// This lib deals with the generation of ID's based off the random strings provided by the consensius commitee at the end of the last round
use std::io::{stdin, stdout, Write};
use std::time::{SystemTime, UNIX_EPOCH};
extern crate rand;
extern crate cryptonight;
use cryptonight::cryptonight;
use rand::Rng;
extern crate hex;
#[macro_use]
extern crate log;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};

pub struct HashParams {
    pub iterations: u32,
    pub memory: u32,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct IdDetails {
    pub hash: String,
    pub signed: String,
    pub nonce: u64,
    pub start_t: u64,
    pub end_t: u64,
}

pub fn difficulty_bytes_as_u128(v: &Vec<u8>) -> u128 {
    ((v[63] as u128) << 0xf * 8)
        | ((v[62] as u128) << 0xe * 8)
        | ((v[61] as u128) << 0xd * 8)
        | ((v[60] as u128) << 0xc * 8)
        | ((v[59] as u128) << 0xb * 8)
        | ((v[58] as u128) << 0xa * 8)
        | ((v[57] as u128) << 0x9 * 8)
        | ((v[56] as u128) << 0x8 * 8)
        | ((v[55] as u128) << 0x7 * 8)
        | ((v[54] as u128) << 0x6 * 8)
        | ((v[53] as u128) << 0x5 * 8)
        | ((v[52] as u128) << 0x4 * 8)
        | ((v[51] as u128) << 0x3 * 8)
        | ((v[50] as u128) << 0x2 * 8)
        | ((v[49] as u128) << 0x1 * 8)
        | ((v[48] as u128) << 0x0 * 8)
}

pub fn check_difficulty(hash: &String, difficulty: u128) -> bool {
    difficulty > difficulty_bytes_as_u128(&hash.as_bytes().to_vec())
}

fn calculate_hash_params(PrevBlockHash: String) -> HashParams {
    let mut cu = PrevBlockHash.as_bytes();
    let mut b: Vec<u8> = cu.iter().cloned().collect();
    let mut a: u32 = 0;
    let mut i = 0;

    for x in &b {
        a = a + *x as u32;
    }
    return HashParams { iterations: a * 10, memory: a * 20 }
}

fn hash_string(params: &HashParams, s: &String) -> String {
    unsafe {
        let input = s.as_bytes();
        cryptonight::set_params(params.memory as u64, params.iterations as u64);
        let out = cryptonight(&input, input.len(), 0);
        return hex::encode(out);
    }
}

pub fn generateId(
    k: String,
    public_key: String,
    private_key: String,
    difficulty: u128
) -> IdDetails {
    let mut struct_: IdDetails = IdDetails::default();
    let params = HashParams {
        memory: 262144,
        iterations: 65536,
    };
    let mut nonce: u32 = 0;
    let mut hashed: String;

    struct_.start_t = SystemTime::now().duration_since(UNIX_EPOCH)
    .expect("Time went backwards").as_millis() as u64;

    loop {
        nonce = nonce + 1;
        hashed = hash_string(&params, &(k.clone() + &public_key + &nonce.to_string()));

        // check difficulty
        if check_difficulty(&hashed, difficulty) {
            struct_.nonce = nonce as u64;
            struct_.hash = hashed.clone();
            struct_.end_t = SystemTime::now().duration_since(UNIX_EPOCH)
            .expect("Time went backwards").as_millis() as u64;
            info!(
                "Found ID hash: {} with nonce: {} (in {} secconds)",
                hashed,
                nonce,
                (struct_.end_t - struct_.start_t) / 1000
            );
            break;
        }
    }

    struct_.signed = sign(hashed, private_key);

    return struct_;
}

fn sign(s: String, pk: String) -> String {
    let pkcs8_bytes = hex::decode(pk);
    match pkcs8_bytes {
        Ok(out) => {
            let key_pair = signature::Ed25519KeyPair::from_pkcs8(out.as_ref()).unwrap();
let msg: &[u8] = s.as_bytes();
            return hex::encode(key_pair.sign(msg));
        },
        Err(e) => {
            warn!("failed to decode hex, gave error: {}", e);
            return "failed to hex decode".to_string();
        }
    }
}
