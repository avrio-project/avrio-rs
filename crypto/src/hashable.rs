use cryptonight::*
pub trait Hashable {
    fn bytes (&self) -> Vec<u8>;

    fn hash (&self) -> Vec<u8> {
        if !cryptonight::getHashingParams().memory {
            cryptonight::setHAshingParams(i,m); // needs defult value setting
        cryptonight::cryptonight(&self.bytes(), self.bytes().len(), 0);
    }
}
