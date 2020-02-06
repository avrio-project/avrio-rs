extern crate config;
extern crate core;
extern crate crypto;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
    hash: String,
    amount: u64,
    extra: String,
    flag: char,
    sender_key: String,
    receive_key: String,
    access_key: String,
    gas_price: u64,
    max_gas: u64,
    gas: u64, // gas used
    nonce: u8,
    signature: String,
}
impl Hashable for Transaction { // TXN CREATION 101: run this then do tx.hash(); then sign the hash provided
    fn bytes (&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.ammount);
        bytes.extend(self.extra);
        bytes.extend(self.flag);
        bytes.extend(self.sender_key);
        bytes.extend(self.receive_key);
        bytes.extend(self.gas * self.gas_price); // aka fee
        bytes.extend(self.nonce);
        bytes
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TxStore { // remove data not needed to be stored
    hash: String,
    amount: u64,
    extra: String,
    sender_key: String,
    receive_key: String,
    access_key: String,
    fee: u64, // fee in AIO (gas_used * gas_price)
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
    return tx.hash();
}
