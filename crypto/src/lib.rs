extern crate lyra2;
use lyra2::lyra2rev3::sum;

extern crate bs58;
pub trait Hashable {
    fn bytes (&self) -> Vec<u8>;

    fn hash_item (&self) -> String{
        let bytes = self.bytes();
        let lyra2res = sum(bytes);
        return bs58::encode(lyra2res).into_string();
    }
}