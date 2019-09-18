pub struct Block {
    versionMajor: u8,
    versionMinor: u8
    chainKey: String,
    prevHash: String,
    timestamp: u64,
    hash: String,
    txns: Vec<Transaction>,
    signature: String,
    nodeSignature String,
}