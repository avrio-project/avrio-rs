pub struct Block {
    version_major: u8,
    version_minor: u8,
    chain_key: String,
    prev_hash: String,
    timestamp: u64,
    hash: String,
    txns: Vec<Transaction>,
    signature: String,
    node_signature: String,
}

pub struct Transaction {
    amount: u64,
    sender_key: String,
    reciever_key: String,
    unlock_time: u64,
    gas_price: u64,
    max_gas: u64,
    nonce: u64,
    signature: String,
}
