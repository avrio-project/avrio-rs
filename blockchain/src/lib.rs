extern crate config;
extern crate core;
extern crate crypto;
use serde::{Deserialize, Serialize};

enum blockValidationErrors {
    invalidBlockhash,
    badSignature,
    indexMissmatch,
    invalidPreviousBlockhash,
    invalidTransaction,
    genesisBlockMissmatch,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
    version_major: u8,
    version_brekaing: u8,
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
    node_signatures: Vec<String>, // a block must be signed by at least (c / 2) + 1 nodes to be valid (ensures at least ne honest node has singed it)
}

impl Hashable for Header {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.version_major.to_string());
        bytes.extend(self.version_breaking.to_string());
        bytes.extend(self.version_minor.to_string());
        bytes.extend(self.chain_key);
        bytes.extend(self.prev_hash);
        bytes.extend(self.receive_key);
        bytes.extend(self.height.to_string());
        bytes.extend(self.timestamp.to_string());
        bytes
    }
}

impl Hashable for Block {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.header.bytes());
        bytes.extend(
            self.txns.hash
                .iter()
                .collect::<Vec<u8>>(),
        );
        bytes
    }
}

pub fn check_block(blk: Block) -> Result<(), blockValidationErrors> {
    if blk.header.height == 0 {
        // genesis block
        // could be costly 
        if blk != generateGenesisBlock() {
            return Err(blockValidationErrors::genesisBlockMissmatch);
        }
        else {
            return Ok(());
        }
    } else {
        // not genesis block
        if blk.header.prev_hash != get_block(&blk.header.chain_key, &blk.header.height - 1) {
            return Err(blockValidationErrors::invalidPreviousBlockhash);
        } else if check_signature(&blk.signature, hex::decode(&blk.header.chain_key.unwrap_or_else(|e| { return Err(blockValidationErrors::badSignature); }))) == Err(()) {
            return Err(blockValidationErrors::badSignature);
        } else {
            for txn in blk.txns {
                if validate_transaction(&txn) == Err(()) {
                    return Err(blockValidationErrors::invalidTransaction);
                } else {
                    Ok(());
                }
            }
        return Ok(());
        }
    }
}
