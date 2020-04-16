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
use avrio_config::config;

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

#[cfg(test)]
mod tests {
    pub use crate::*;
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
}
