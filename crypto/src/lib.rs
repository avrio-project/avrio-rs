// Lyra2
extern crate lyra2;
use lyra2::lyra2rev3::sum;

// Argon2
use argon2::{self, Config, ThreadMode, Variant, Version};

extern crate bs58;
pub trait Hashable {
    fn bytes(&self) -> Vec<u8>;

    fn hash_item(&self) -> String {
        let bytes = self.bytes();
        let lyra2res = sum(bytes.clone());
        let mut sk = 0;
        let i: usize = 0;
        while i < bytes.len() {
            sk += bytes[i]
        }

        let password = lyra2res;
        let salt = sk.to_string();
        let config = Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: 65536,
            time_cost: 5,
            lanes: 4,
            thread_mode: ThreadMode::Parallel,
            secret: &[],
            ad: &[],
            hash_length: 32,
        };
        let hash: String = bs58::encode(
            argon2::hash_encoded(&password, salt.as_bytes(), &config)
                .unwrap_or("".to_string())
                .as_bytes(),
        )
        .into_string();
        return hash;
    }
}
