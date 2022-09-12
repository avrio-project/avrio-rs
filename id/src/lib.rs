// This lib deals with the generation of ID's based off the random strings provided by the consensius commitee at the end of the last round

use std::time::{SystemTime, UNIX_EPOCH};

extern crate hex;
extern crate rand;
#[macro_use]
extern crate log;
use avrio_crypto::raw_hash;
use ring::signature;
use serde::{Deserialize, Serialize};
pub struct HashParams {
    pub iterations: u32,
    pub memory: u32,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct IdDetails {
    pub hash: String,
    pub signed: String,
    pub nonce: u64,
    pub start_t: u64,
    pub end_t: u64,
}

pub fn difficulty_bytes_as_u128(v: &[u8]) -> u128 {
    return v.iter().sum::<u8>() as u128;
}

pub fn check_difficulty(hash: &str, difficulty: u128) -> bool {
    difficulty > difficulty_bytes_as_u128(hash.as_bytes())
}

fn _calculate_hash_params(seed: String) -> HashParams {
    let cu = seed.as_bytes();
    let b: Vec<u8> = cu.to_vec();
    let mut a: u32 = 0;
    let _i = 0;

    for x in &b {
        a += *x as u32;
    }
    HashParams {
        iterations: a * 10,
        memory: a * 20,
    }
}

fn hash_string(params: &HashParams, s: &String) -> String {
    let mut out: String = s.to_owned();
    for _ in 0..params.iterations {
        out = raw_hash(&out);
    }
    out
}

pub fn generate_id(
    k: String,
    public_key: String,
    private_key: String,
    difficulty: u128,
) -> IdDetails {
    let mut struct_: IdDetails = IdDetails::default();
    let params = HashParams {
        memory: 262144,
        iterations: 65536,
    };
    let mut nonce: u32 = 0;
    let mut hashed: String;

    struct_.start_t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    loop {
        nonce += 1;
        hashed = hash_string(&params, &(k.clone() + &public_key + &nonce.to_string()));

        // check difficulty
        if check_difficulty(&hashed, difficulty) {
            struct_.nonce = nonce as u64;
            struct_.hash = hashed.clone();
            struct_.end_t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64;
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

    struct_
}

fn sign(s: String, pk: String) -> String {
    let pkcs8_bytes = hex::decode(pk);
    match pkcs8_bytes {
        Ok(out) => {
            let key_pair = signature::Ed25519KeyPair::from_pkcs8(out.as_ref()).unwrap();
            let msg: &[u8] = s.as_bytes();
            hex::encode(key_pair.sign(msg))
        }
        Err(e) => {
            warn!("failed to decode hex, gave error: {}", e);
            "failed to hex decode".to_string()
        }
    }
}
