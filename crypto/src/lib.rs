// Lyra2
extern crate lyra2;
use lyra2::lyra2rev3::sum;

// Argon2
use argonautica::Hasher;

extern crate bs58;
pub trait Hashable {
    fn bytes(&self) -> Vec<u8>;

    fn hash_item(&self) -> String {
        let bytes = self.bytes();
        let lyra2res = sum(bytes);
        let mut hasher = Hasher::default().opt_out_of_secret_key(true);
        let mut sk = 0;
        while i < bytes.len() {
            sk += bytes[i]
        }
        let hash = hasher
            .with_password(lyra2res)
            .with_salt(bs58::encode(sk).into_string())
            .with_secret_key(bs58::encode(sk).into_string())
            .with_salt(bs)
            .hash()
            .unwrap_or("hash".to_string());
        return bs58::encode(hash).into_string();
    }
}
