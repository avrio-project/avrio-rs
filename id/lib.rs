// This lib deals with the generation of ID's based off the random strings provided by the consensius commitee at the end of the last round
use std::io::{stdin,stdout,Write};
extern crate rand;
use rand::Rng;

struct HashParams {
    iterations: u32,
    scratchpad: u32,
    pagesize: u32,
}

calculate hash_params(PrevBlockHash: String) -> HashParams {
  let mut cu = PrevBlockHash.as_bytes();
  let mut b: Vec<u8> = cu.iter().cloned().collect();
  let mut a: u32 =0;
  let mut i =0;
  for x in &b {
    a = a + *x as u32;
  }
  return HashParams{iterations: a * 10, scratchpad: a * 20, pagesize: a * 40);  
}



}
pub fn generateId(k: String, public_key: String, private_key) {
  let mut i = 1;
  let mut random = rand::thread_rng();
  let mut randomString = k[random(1,k[0])];
  let mut randomString = k[random(1,k[0])];
  let hashed = hash(randomString + randomString + public_key);
  return sign(hashed,private_key);
}
  
