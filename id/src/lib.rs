// This lib deals with the generation of ID's based off the random strings provided by the consensius commitee at the end of the last round
use std::io::{stdin,stdout,Write};
use std::time::{SystemTime, UNIX_EPOCH};
extern crate rand;
use rand::Rng;

struct HashParams {
    iterations: u32,
    memory: u32
}

struct IdDetails {
    hash: String,
    signed: String,
    nonce: u64,
    start_t: u64,
    end_t: u64
}

pub fn difficulty_bytes_as_u128 (v: &Vec<u8>) -> u128 {
    ((v[63] as u128) << 0xf * 8) |
    ((v[62] as u128) << 0xe * 8) |
    ((v[61] as u128) << 0xd * 8) |
    ((v[60] as u128) << 0xc * 8) |
    ((v[59] as u128) << 0xb * 8) |
    ((v[58] as u128) << 0xa * 8) |
    ((v[57] as u128) << 0x9 * 8) |
    ((v[56] as u128) << 0x8 * 8) |
    ((v[55] as u128) << 0x7 * 8) |
    ((v[54] as u128) << 0x6 * 8) |
    ((v[53] as u128) << 0x5 * 8) |
    ((v[52] as u128) << 0x4 * 8) |
    ((v[51] as u128) << 0x3 * 8) |
    ((v[50] as u128) << 0x2 * 8) |
    ((v[49] as u128) << 0x1 * 8) |
    ((v[48] as u128) << 0x0 * 8)
}

pub fn check_difficulty (hash: &Hash, difficulty: u128) -> bool {
    difficulty > difficulty_bytes_as_u128(&hash)
}

fn calculate_hash_params(PrevBlockHash: String) -> HashParams {
  let mut cu = PrevBlockHash.as_bytes();
  let mut b: Vec<u8> = cu.iter().cloned().collect();
  let mut a: u32 =0;
  let mut i =0;
  for x in &b {
    a = a + *x as u32;
  }
  return HashParams{iterations: a * 10, memory: a * 20);  
}

fn hash_string(params: HashParams, s: String) -> String {
  unsafe 
  {
    let in = s.as_bytes();
    cryptonight::set_params(params.memory, params.iterations);
    let out = cryptonight(&in, in.len(), 0);
    let mut out_abs: Vec<u8> = vec![];
    for x in out {
        if x < 0 {
            let x_pos = x + (x*2);
            out_abs.push(x_pos);
        }else {
            out_abs.push(x);
        }
    }
    return hex::encode(out_abs);
  }
}

}
pub fn generateId(k: String, public_key: String, private_key, difficulty: u128) -> IdDetails
{
  let mut struct_ =  new IdDetails;
  let params = calculate_hash_params(getLastBlockHash());
  let mut nonce: u32 = 0;
  let mut hashed: String = "";
  struct_.start_t = SystemTime::now().as_millis();
  while true {
      nonce = nonce + 1;
      hashed = hash_string(params, k + public_key + nonce);
      // check difficulty
      if (check_difficulty(&hashed, difficulty) {
          struct_.nonce = nonce;
          struct_.hash = hashed;
          struct_.end_t = SystemTime::now().as_millis();
          println!("[INFO] Found ID hash: {0} with nonce: {1} (in {2} secconds)",hashed,nonce, (struct_.end_t - start_.start_t) / 1000);
          break;
      }
  }
  
  struct_.signed = sign(hashed,private_key);
  return struct_;
}
  
