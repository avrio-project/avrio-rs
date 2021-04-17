use std::error::Error;

/// This trait should be implmented by any item that should be linked to the blockchain. For example, fullnode certificates, blocks, transactions etc.
/// Anything included in a block or transaction or any other type that implments this should also implment this.
/// The struct should have a hash or some form of unique id that is used when calling save
/// When validating, saving or enacting fails you should return a custom enum which inherits the error trait. For example:
/// BlockValidationErrors::HashMissmatch
pub trait Verifiable {
    fn verify(&self) -> Result<(), Box<dyn Error>>;
    fn get(hash: String) -> Result<Box<Self>, Box<dyn Error>>;
    fn save(&self) -> Result<(), Box<dyn Error>>;
    fn enact(&self) -> Result<(), Box<dyn Error>>;
    fn is_valid(&self) -> bool {
        self.verify().is_ok()
    }
}
