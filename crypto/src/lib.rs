// Lyra2
extern crate lyra2;
use lyra2::lyra2rev3::sum;

// sha256
use sha2::{Digest, Sha256};

// Base58
extern crate bs58;
// VRF/ openssl
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;
// scrypt
extern crate scrypt;

// ring, for wallet
extern crate ring;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};

use bigdecimal::BigDecimal;
use std::str::FromStr;

// avrio config, for getting the address prefix
extern crate avrio_config;
use primitive_types::U512;
// static MAX_ADDR_DEC: &str =
//     "115792089237316195423570985008687907853269984665640564039457584007913129639935";
pub struct Keypair {
    pub public_key: Publickey,
    pub private_key: Privatekey,
}

pub fn generate_keypair() -> Keypair {
    let rngc = randc::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let peer_public_key_bytes = key_pair.public_key().as_ref();
    Keypair {
        public_key: bs58::encode(peer_public_key_bytes).into_string(),
        private_key: bs58::encode(pkcs8_bytes).into_string(),
    }
}

pub fn raw_lyra(s: &str) -> String {
    bs58::encode(sum(s.as_bytes().to_vec())).into_string()
}

pub fn raw_hash(s: &str) -> String {
    // First we calculate the bytes of the string being passed to us
    let bytes = s.as_bytes().to_vec();

    // Lyra round 1/2 on the bytes
    let lyra2res = sum(bytes.clone());

    // sha256 round 1/3
    let mut hasher = Sha256::new();
    hasher.input(lyra2res);
    let sharesult = hasher.result();

    // sha256 round 3/3
    let mut hasher = Sha256::new();
    hasher.input(sharesult);
    let sharesult = hasher.result();

    // sha256 round 3/3
    let mut hasher = Sha256::new();
    hasher.input(sharesult);
    let sharesult = hasher.result();

    // the following code is a hacky way of making a Generic Array into a vec
    let sha_res_slice = &bs58::decode(bs58::encode(sharesult).into_string())
        .into_vec()
        .unwrap_or_default();

    // BLAKE round 1/2
    let mut blakeresult = [0; 32];
    blake::hash(256, sha_res_slice, &mut blakeresult).unwrap();

    // BLAKE round 2/2
    let mut blakeresult_two = [0; 32];
    blake::hash(256, &blakeresult, &mut blakeresult_two).unwrap();

    // Lyra2 round 2/2 on the BLAKE result + salt
    let mut sk: u64 = 0;
    for byte in bytes.iter() {
        sk += *byte as u64;
    }
    let salt = sk.to_string();
    let lyra2res_two = sum((bs58::encode(blakeresult_two).into_string() + &salt)
        .as_bytes()
        .to_vec());

    // A final sha256 round on the lyra res
    let mut hasher = Sha256::new();
    hasher.input(lyra2res_two);
    let sharesult = hasher.result();

    // Finally we base 58 encode the result
    let hash: String = bs58::encode(sharesult).into_string();
    hash
}

pub trait Hashable {
    fn bytes(&self) -> Vec<u8>;

    fn hash_item(&self) -> String {
        // First we calculate the bytes of the object being passed to us
        let bytes = self.bytes();

        // Lyra round 1/2 on the bytes
        let lyra2res = sum(bytes.clone());

        // sha256 round 1/3
        let mut hasher = Sha256::new();
        hasher.input(lyra2res);
        let sharesult = hasher.result();

        // sha256 round 3/3
        let mut hasher = Sha256::new();
        hasher.input(sharesult);
        let sharesult = hasher.result();

        // sha256 round 3/3
        let mut hasher = Sha256::new();
        hasher.input(sharesult);
        let sharesult = hasher.result();

        // the following code is a hacky way of making a Generic Array into a vec
        let sha_res_slice = &bs58::decode(bs58::encode(sharesult).into_string())
            .into_vec()
            .unwrap_or_default();

        // BLAKE round 1/2
        let mut blakeresult = [0; 32];
        blake::hash(256, sha_res_slice, &mut blakeresult).unwrap();

        // BLAKE round 2/2
        let mut blakeresult_two = [0; 32];
        blake::hash(256, &blakeresult, &mut blakeresult_two).unwrap();

        // Lyra2 round 2/2 on the BLAKE result + salt
        let mut sk: u64 = 0;
        for byte in bytes.iter() {
            sk += *byte as u64;
        }
        let salt = sk.to_string();
        let lyra2res_two = sum((bs58::encode(blakeresult_two).into_string() + &salt)
            .as_bytes()
            .to_vec());

        // A final sha256 round on the lyra res
        let mut hasher = Sha256::new();
        hasher.input(lyra2res_two);
        let sharesult = hasher.result();

        // Finally we base 58 encode the result
        let hash: String = bs58::encode(sharesult).into_string();
        hash
    }
}

pub struct StringHash {
    pub s: String,
}
impl Hashable for StringHash {
    fn bytes(&self) -> Vec<u8> {
        self.s.as_bytes().to_vec()
    }
}
#[derive(Debug, PartialEq, Clone)]
pub struct Wallet {
    pub public_key: Publickey,
    pub private_key: Privatekey,
}

pub type Publickey = String;
pub type Privatekey = String;

impl Hashable for Publickey {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.as_bytes().to_vec().iter());
        bytes
    }
}

pub fn commitee_from_address(address: &str) -> u64 {
    let decoded: Vec<u8> = bs58::decode(address)
        .into_vec()
        .unwrap_or_else(|_| vec![0, 6, 9, 0]);
    if decoded == vec![0, 6, 9, 0] {
        return 0;
    }

    0
}

pub fn get_vrf(
    private_key: String,
    message: String,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Initialization of VRF context by providing a curve
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key & Message
    let secret_key = bs58::decode(private_key).into_vec()?;
    let message: &[u8] = message.as_bytes();

    // VRF proof and hash output
    let pi = vrf.prove(&secret_key, &message).unwrap();
    let hash = vrf.proof_to_hash(&pi).unwrap();
    return Ok((
        bs58::encode(pi).into_string(),
        bs58::encode(hash).into_string(),
    ));
}

pub fn validate_vrf(public_key: String, proof: String, message: String) -> bool {
    if let Ok(mut vrf) = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI) {
        if let Ok(pi) = bs58::decode(proof).into_vec() {
            if let Ok(msg_vec) = bs58::decode(message).into_vec() {
                if let Ok(pubkey) = bs58::decode(public_key).into_vec() {
                    if let Ok(_) = vrf.verify(&pubkey, &pi, &msg_vec) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn vrf_hash_to_integer(hash: String) -> BigDecimal {
    let mut as_binary: String = String::from("");
    for hash_bit in hash.as_bytes() {
        as_binary += &format!("{:b}", hash_bit);
    }
    let before_normal = binary_to_u512(as_binary.clone());
    let _two_u518: U512 = 2.into();

    let bn_dec = BigDecimal::from_str(&before_normal.to_string()).unwrap();
    BigDecimal::from_str(&format!("0.{}", bn_dec.normalized())).unwrap()
}

fn binary_to_u512(s: String) -> U512 {
    let mut binary_digit = s.chars().count();
    let mut real_num: U512 = U512::zero();
    let two_u518: U512 = 2.into();
    for c in s.chars() {
        let mut temp_var = two_u518.pow(binary_digit.into());
        temp_var /= 2;
        if c == '1' {
            real_num += temp_var;
        }
        binary_digit -= 1;
    }
    return real_num;
}

fn divide_two_vec(a: Vec<u8>, b: Vec<u8>) -> Vec<f64> {
    if a.len() != b.len() {
        return vec![];
    }
    let mut out: Vec<f64> = vec![];
    for i in 0..a.len() {
        out.push(a[i] as f64 / b[i] as f64);
    }
    out
}

fn max_vec(len: u64) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    for _ in 0..len {
        out.push(255);
    }
    out
}

pub fn valid_address(address: &str) -> bool {
    let decoded: Vec<u8> = bs58::decode(address)
        .into_vec()
        .unwrap_or_else(|_| vec![0, 6, 9, 0]);
    if decoded == vec![0, 6, 9, 0] {
        return false;
    }
    let length = decoded.len();
    if address.len() != 68 || &address[0..1] != "1" {
        return false;
    }
    let checked_bytes = decoded[length - 1] as usize;
    let without_prefix = &decoded[1..=((length - checked_bytes) - 2)];
    let checked: String = StringHash {
        s: String::from_utf8((*without_prefix).to_vec()).unwrap_or_default(),
    }
    .hash_item();
    if decoded[((length - 1) - checked_bytes)..=length - 2]
        != *(checked[0..checked_bytes].as_bytes())
    {
        return false;
    }
    true
}

impl Wallet {
    pub fn new(public_key: Publickey, private_key: Privatekey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
    pub fn from_address(addr: String) -> Wallet {
        let decoded = bs58::decode(&addr).into_vec().unwrap();
        let length = decoded.len();
        if addr.len() != 68 || decoded[0..1] != [0] {
            return Wallet {
                private_key: "".into(),
                public_key: "".into(),
            };
        }
        let checked_bytes = decoded[length - 1] as usize;
        let without_prefix = &decoded[1..=((length - checked_bytes) - 2)];
        let checked: String = StringHash {
            s: String::from_utf8((*without_prefix).to_vec()).unwrap_or_default(),
        }
        .hash_item();
        if decoded[((length - 1) - checked_bytes)..=length - 2]
            != *(checked[0..checked_bytes].as_bytes())
        {
            return Wallet {
                private_key: "".into(),
                public_key: "".into(),
            };
        }
        Wallet {
            private_key: "".into(),
            public_key: String::from_utf8(without_prefix.to_vec()).unwrap_or_default(),
        }
    }
    pub fn from_private_key(pk: String) -> Wallet {
        let pkcs8_bytes = bs58::decode(&pk).into_vec().unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let peer_public_key_bytes = key_pair.public_key().as_ref();
        Wallet {
            public_key: bs58::encode(peer_public_key_bytes).into_string(),
            private_key: pk,
        }
    }
    pub fn address(&self) -> String {
        let mut unencoded: Vec<u8> = vec![];
        unencoded.extend(vec![0].iter());
        unencoded.extend(self.public_key.bytes());
        let checked: String = self.public_key.hash_item();
        let mut i: usize = 0;
        while unencoded.len() != 49 {
            i += 1;
            unencoded.extend(checked[i - 1..i].bytes());
        }
        unencoded.push(i as u8);
        return bs58::encode(unencoded).into_string();
    }
    pub fn gen() -> Wallet {
        let rngc = randc::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let peer_public_key_bytes = key_pair.public_key().as_ref();
        Wallet {
            public_key: bs58::encode(peer_public_key_bytes).into_string(),
            private_key: bs58::encode(pkcs8_bytes).into_string(),
        }
    }
}
pub fn public_key_to_address(public_key: &str) -> String {
    let mut unencoded: Vec<u8> = vec![];
    unencoded.extend(vec![0].iter());
    unencoded.extend(public_key.bytes());
    let checked: String = public_key.to_string().hash_item();
    let mut i: usize = 0;
    while unencoded.len() != 49 {
        i += 1;
        unencoded.extend(checked[i - 1..i].bytes());
    }
    unencoded.push(i as u8);
    return bs58::encode(unencoded).into_string();
}

#[cfg(test)]
mod tests {
    pub use crate::*;
    pub use csv::Writer;
    use std::error::Error;

    #[test]
    fn test_address_prefix() {
        for _ in 0..1000 {
            let wallet = Wallet::gen();
            println!("wallet: {:?}", wallet);
            let addr = wallet.address();
            assert_eq!(addr[0..1].to_owned(), "1".to_owned());
        }
    }
    #[test]
    fn test_from_addr() {
        for _ in 0..1000 {
            let mut wallet_init: Wallet = Wallet::gen();
            let addr = wallet_init.address();
            wallet_init.private_key = "".into();
            assert_eq!(Wallet::from_address(addr), wallet_init);
        }
    }
    #[test]
    fn max_addr() {
        // Max JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG (dec: 115792089237316195423570985008687907853269984665640564039457584007913129639935)
        // Min 11111111111111111111111111111111 (dec 0)
        let max = [u8::MAX; 32].as_ref();
        let min = [u8::MIN; 32].as_ref();
        let rngc = randc::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        println!("{}", key_pair.public_key().as_ref().len());
        println!(
            "Max: {}, Min: {}",
            bs58::encode(max).into_string(),
            bs58::encode(min).into_string()
        );
    }
    use std::collections::HashMap;
    #[test]
    fn culmulative_addr_freq() -> Result<(), Box<dyn Error>> {
        let mut freq = HashMap::new();
        freq.insert("0".to_string(), "0".to_string());
        for i in 0..u8::MAX {
            for n in 0..32 {
                let mut arr = [0; 32];
                if n == 0 {
                    arr[0] = i;
                } else {
                    for n in 0..n {
                        arr[n] = i;
                    }
                }

                let mut out_num: u64 = 0;
                for o in arr.iter() {
                    out_num += u64::from(o.to_owned())
                }
                let out = out_num.to_string();

                let curr: u64 = match freq.get(&out) {
                    Some(val) => val.parse::<u64>().unwrap_or_default(),
                    None => 0,
                };
                freq.insert(out, (curr + 1).to_string());
            }
        }

        let mut wtr = Writer::from_path("culmulative_addr_freq.csv")?;
        wtr.write_record(&["value", "freq"])?;
        let mut cou: u128 = 0;
        for (val, freq) in &freq {
            cou += 1;

            wtr.write_record(&[val, freq])?;
            println!("{},{}", val, freq);
        }
        println!("COU: {}", cou);
        wtr.flush()?;
        Ok(())
    }
}
#[test]
fn test_hashrate() {
    use std::time::SystemTime;
    let start = SystemTime::now();
    let amount = 10000;
    for n in 0..amount {
        raw_hash(&n.to_string());
    }
    let _time_took = SystemTime::now()
        .duration_since(start)
        .expect("negative time")
        .as_millis();
    let time_took = SystemTime::now()
        .duration_since(start)
        .expect("negative time")
        .as_millis();
    let start_lyra = SystemTime::now();
    let amount = 10000;
    for n in 0..amount {
        raw_lyra(&n.to_string());
    }

    println!(
        "Raw_hash: Hashed {}k hashes in {} ms, {} h/s",
        amount / 1000,
        time_took,
        1000 / (time_took / amount)
    );
    let time_took = SystemTime::now()
        .duration_since(start_lyra)
        .expect("negative time")
        .as_millis();
    println!(
        "Raw_lyra: Hashed {}k hashes in {} ms, {} h/s",
        amount / 1000,
        time_took,
        1000 / (time_took + 1 / amount + 1)
    );
}
mod vrf_test;
