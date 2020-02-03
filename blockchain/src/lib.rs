use config::config;
use std::sync::mutex;
use std::sync::once;
use serde::{Serialize, Deserialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
    hash: String,
    amount: u64,
    sender_key: String,
    access_key: String,
    gas_price: u64,
    max_gas: u64,
    gas: u64, // gas used
    nonce: u8,
    signature: String,
}
impl Hash for Transaction {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.amount.hash(state);
        self.sender_key.hash(state);
        self.access_key.hash(state);
        self.nonce.hash(state);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TxStore { // remove data not needed to be stored
    hash: String,
    amount: u64,
    sender_key: String,
    access_key: String
    fee: u64, // fee in AIO
    nonce: u8,
    signature: String,
}    

#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
    version_major: u8,
    version_minor: u8,
    chain_key: String,
    prev_hash: String,
    height: u64,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    header: Header,
    txns: Vec<Transaction>,
    hash: String,
    signature: String,
    node_signatures:Vec<String>, // a block must be signed by at least (c / 2) + 1 nodes to be valid (ensures at least ne honest node has singed it)
}


pub fn check_block(blk: Block) -> bool {
    if blk.header.version_major > config.version_major {
        return false;
    } else if blk.header.prev_hash != get_block(blk.header.chain_key, blk.header.height ) {
        return false;
    } else if !check_signature(blk.signature,blk.header.chain_key) {
        return false;
    }

    for txn in blk.txns {
        if !validate_transaction(txn) {
            return false;
        }
    }

    // Todo continue blk validation

    return false;
}

fn hashTransaction(tx: Transaction) -> String {
    let h = DefaultHasher::new();
    tx.hash(&mut h);
    return h.finish();
}
