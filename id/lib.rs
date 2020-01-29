// This lib deala with the generation of ID's based off the random strings provided by the consensius commitee at the end of the last round

pub fn generateId(k: String, public_key: String, private_key) {
  let mut i = 1;
  let mut randomString = k[random(1,k[0])];
  let mut randomString = k[random(1,k[0])];
  let hashed = hash(randomString + randomString + public_key);
  return sign(hashed,private_key);
}
  
