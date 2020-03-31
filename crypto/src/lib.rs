// Lyra2
extern crate lyra2;
use lyra2::lyra2rev3::sum;

// sha256
use sha2::{Digest, Sha256};

// Base58
extern crate bs58;

// scrypt
extern crate scrypt;

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
