// This lib deals with the generation of ID's based off the random strings provided by the consensius commitee at the end of the last round
use std::io::{stdin,stdout,Write};
extern crate rand;
use rand::Rng;

struct HashParams {
    iterations: u32,
    memory: u32
}

calculate hash_params(PrevBlockHash: String) -> HashParams {
  let mut cu = PrevBlockHash.as_bytes();
  let mut b: Vec<u8> = cu.iter().cloned().collect();
  let mut a: u32 =0;
  let mut i =0;
  for x in &b {
    a = a + *x as u32;
  }
  return HashParams{iterations: a * 10, memory: a * 20);  
}



}
pub fn generateId(k: String, public_key: String, private_key, difficulty: u64) {
  let mut nonce: u32 = 0;
  let mut hashed: String = "";
  let mut c = 0;
  while true {
      nonce = nonce + 1;
      c = 0;
      hashed = hash(k + public_key + nonce);
      c = hashed.as_bytes().iter().sum();
      // check difficulty
      if (c < difficulty) {
          println!("[INFO] Found ID hash: {0} with nonce: {1}",hashed,nonce);
          break;
      }
  }
  return sign(hashed,private_key);
}
  
