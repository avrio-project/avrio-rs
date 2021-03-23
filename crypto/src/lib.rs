// Lyra2
extern crate lyra2;
use lyra2::lyra2rev3::sum;

// sha256
use sha2::{Digest, Sha256};

// Base58
extern crate bs58;

// scrypt
extern crate scrypt;

// ring, for wallet
extern crate ring;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};

// avrio config, for getting the address prefix
extern crate avrio_config;

static max_addr_dec: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";
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

pub fn raw_lyra(s: &String) -> String {
    return bs58::encode(sum(s.as_bytes().to_vec())).into_string();
}

pub fn raw_hash(s: &String) -> String {
    // First we calculate the bytes of the string being passed to us
    let bytes = s.as_bytes().to_vec();

    // Lyra round 1/2 on the bytes
    let lyra2res = sum(bytes.clone());

    // sha256 round 1/3
    let mut hasher = Sha256::new();
    hasher.input(lyra2res.clone());
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
    drop(sk);
    let lyra2res_two = sum((bs58::encode(blakeresult_two).into_string() + &salt)
        .as_bytes()
        .to_vec());

    // A final sha256 round on the lyra res
    let mut hasher = Sha256::new();
    hasher.input(lyra2res_two);
    let sharesult = hasher.result();

    // Finally we base 58 encode the result
    let hash: String = bs58::encode(sharesult).into_string();
    return hash;
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
        hasher.input(lyra2res.clone());
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
        drop(sk);
        let lyra2res_two = sum((bs58::encode(blakeresult_two).into_string() + &salt)
            .as_bytes()
            .to_vec());

        // A final sha256 round on the lyra res
        let mut hasher = Sha256::new();
        hasher.input(lyra2res_two);
        let sharesult = hasher.result();

        // Finally we base 58 encode the result
        let hash: String = bs58::encode(sharesult).into_string();
        return hash;
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
#[derive(Debug, PartialEq)]
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

pub fn commitee_from_address(address: &String) -> u64 {
    let decoded: Vec<u8> = bs58::decode(address).into_vec().unwrap_or(vec![0, 6, 9, 0]);
    if decoded == vec![0, 6, 9, 0] {
        return 0;
    }

    return 0;
}

pub fn valid_address(address: &String) -> bool {
    let decoded: Vec<u8> = bs58::decode(address).into_vec().unwrap_or(vec![0, 6, 9, 0]);
    if decoded == vec![0, 6, 9, 0] {
        return false;
    }
    let length = decoded.len();
    if address.len() != 68 {
        return false;
    } else if &address[0..1] != "1" {
        return false;
    }
    let checked_bytes = decoded[length - 1] as usize;
    let without_prefix = &decoded[1..=((length - checked_bytes) - 2)];
    let checked: String = StringHash {
        s: String::from_utf8(without_prefix.clone().to_vec()).unwrap_or_default(),
    }
    .hash_item()
    .to_string();
    if decoded[((length - 1) - checked_bytes)..=length - 2]
        != *(checked[0..checked_bytes].as_bytes())
    {
        return false;
    }
    return true;
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
        if addr.len() != 68 {
            return Wallet {
                private_key: "".into(),
                public_key: "".into(),
            };
        } else if decoded[0..1] != [0] {
            return Wallet {
                private_key: "".into(),
                public_key: "".into(),
            };
        }
        let checked_bytes = decoded[length - 1] as usize;
        let without_prefix = &decoded[1..=((length - checked_bytes) - 2)];
        let checked: String = StringHash {
            s: String::from_utf8(without_prefix.clone().to_vec()).unwrap_or_default(),
        }
        .hash_item()
        .to_string();
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
pub fn public_key_to_address(public_key: &String) -> String {
    let mut unencoded: Vec<u8> = vec![];
    unencoded.extend(vec![0].iter());
    unencoded.extend(public_key.bytes());
    let checked: String = public_key.hash_item();
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

                let mut out = "".to_owned();
                let mut out_num: u64 = 0;
                for o in arr.iter() {
                    out_num += u64::from(o.to_owned())
                }
                out = out_num.to_string();

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
