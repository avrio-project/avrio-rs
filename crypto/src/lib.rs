use secp256k1::bitcoin_hashes::sha256;
use secp256k1::{rand::rngs::OsRng, Signature};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
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
use log::*;
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

pub fn raw_hash(s: &str) -> String {
    // First we calculate the bytes of the string being passed to us
    let bytes = s.as_bytes().to_vec();

    // sha256 round 1/3
    let mut hasher = Sha256::new();
    hasher.input(bytes.clone());
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

    let mut sk: u64 = 0;
    for byte in bytes.iter() {
        sk += *byte as u64;
    }
    let salt = sk.to_string();

    // A final sha256 round on the balkeresult + salt
    let mut hasher = Sha256::new();
    hasher.input(bs58::encode(blakeresult_two).into_string() + &salt);
    let sharesult = hasher.result();

    // Finally we base 58 encode the result
    let hash: String = bs58::encode(sharesult).into_string();
    hash
}

pub trait Hashable {
    fn bytes(&self) -> Vec<u8>;

    fn hash_item(&self) -> String {
        // First we calculate the bytes of the string being passed to us
        let bytes = self.bytes();

        // sha256 round 1/3
        let mut hasher = Sha256::new();
        hasher.input(bytes.clone());
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

        let mut sk: u64 = 0;
        for byte in bytes.iter() {
            sk += *byte as u64;
        }
        let salt = sk.to_string();

        // A final sha256 round on the balkeresult + salt
        let mut hasher = Sha256::new();
        hasher.input(bs58::encode(blakeresult_two).into_string() + &salt);
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

pub fn generate_secp256k1_keypair() -> Vec<String> {
    if let Ok(mut rng) = OsRng::new() {
        let secp = Secp256k1::new();
        let seckey = SecretKey::new(&mut rng);
        let _pubkey = PublicKey::from_secret_key(&secp, &seckey);
        return vec![
            bs58::encode(seckey.as_ref()).into_string(),
            bs58::encode(_pubkey.serialize()).into_string(),
        ];
    } else {
        return vec![];
    }
}

pub fn private_to_public_secp256k1(
    privatekey: &String,
) -> Result<String, Box<dyn std::error::Error>> {
    let secretekey = SecretKey::from_slice(&bs58::decode(privatekey).into_vec()?)?;
    let secp = Secp256k1::new();
    let publickey = PublicKey::from_secret_key(&secp, &secretekey);
    Ok(bs58::encode(publickey.serialize()).into_string())
}

pub fn sign_secp256k1(
    privatekey: &String,
    message: &String,
) -> Result<String, Box<dyn std::error::Error>> {
    let privatekey_bytes = bs58::decode(privatekey).into_vec()?;
    let secretkey: SecretKey = SecretKey::from_slice(&privatekey_bytes)?;
    let message = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
    let secp = Secp256k1::new();
    Ok(bs58::encode(&secp.sign(&message, &secretkey).to_string().bytes()).into_string())
}

pub fn valid_signature_secp256k1(
    publickey: &String,
    message_string: &String,
    signature: &String,
) -> Result<bool, Box<dyn std::error::Error>> {
    let publickey_bytes = bs58::decode(publickey).into_vec()?;
    let message = Message::from_hashed_data::<sha256::Hash>(message_string.as_bytes());
    let signature_bytes = bs58::decode(signature).into_vec()?;
    let publickey = PublicKey::from_slice(&publickey_bytes)?;
    let signature = Signature::from_str(&String::from_utf8(signature_bytes)?)?;
    let secp = Secp256k1::new();
    if secp.verify(&message, &signature, &publickey).is_ok() {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn commitee_from_address(address: &str) -> u64 {
    let decoded: Vec<u8> = bs58::decode(address).into_vec().unwrap_or_else(|_| vec![]);
    if decoded.len() == 0 {
        return 0;
    }
    // TODO
    1
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
    let proof = vrf.prove(&secret_key, &message).unwrap();
    let hash = vrf.proof_to_hash(&proof).unwrap();
    return Ok((hex::encode(proof), hex::encode(hash)));
}
pub fn proof_to_hash(proof: &String) -> Result<String, Box<dyn std::error::Error>> {
    trace!("Turning VRF proof: {} into hash", proof);
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let proof_to_hash_result = vrf.proof_to_hash(&hex::decode(proof)?);
    if let Ok(hash) = proof_to_hash_result {
        Ok(hex::encode(hash))
    } else {
        error!(
            "Failed to turn proof={} into hash, gave error={}",
            proof,
            proof_to_hash_result.unwrap_err()
        );
        return Err("failed to turn vrf proof into hash".into());
    }
}

pub fn validate_vrf(public_key: String, proof: String, message: String) -> bool {
    if let Ok(mut vrf) = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI) {
        if let Ok(pi) = hex::decode(proof) {
            let msg_vec = message.as_bytes().to_vec();
            if let Ok(publickey_bytes) = bs58::decode(public_key).into_vec() {
                if let Ok(publickey) = PublicKey::from_slice(&publickey_bytes) {
                    if let Ok(_) = vrf.verify(&publickey.serialize_uncompressed(), &pi, &msg_vec) {
                        return true;
                    } else {
                        trace!("vrf invalid");
                    }
                } else {
                    trace!("publickey bytes invalid");
                }
            } else {
                trace!("Failed to base decode publickey");
            }
        } else {
            trace!("Failed to base decode proof");
        }
    } else {
        trace!("Failed to create VRF context");
    }
    false
}
/// hash must be hex encoded or this will fail
pub fn vrf_hash_to_u64(hash: String) -> Result<u64, Box<dyn std::error::Error>> {
    let hash_slice: String = String::from_utf8(hash.as_bytes()[0..16].to_vec())?;
    Ok(u64::from_str_radix(&hash_slice, 16)?)
}

pub fn normalize(num: u64) -> f64 {
    (num as f64 / u64::MAX as f64) as f64
}
pub fn vrf_hash_to_integer(hash: String) -> BigDecimal {
    let mut as_binary: String = String::from("");
    for hash_bit in hash.as_bytes() {
        as_binary += &format!("{:b}", hash_bit);
    }
    log::trace!("as_binary={}", as_binary);
    let before_normal = binary_to_u512(as_binary.clone());
    log::trace!("before_normal={}", before_normal);
    let bn_dec = BigDecimal::from_str(&before_normal.to_string()).unwrap();
    let after_normal = BigDecimal::from_str(&format!("0.{}", bn_dec.normalized())).unwrap();
    trace!("After normal={}", after_normal);
    after_normal
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

pub fn raw_sha(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input(s);
    let sharesult = hasher.result();
    bs58::encode(sharesult).into_string() // TODO: FIX INTO NEW FAST HASH ALGO
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

mod vrf_test;
