extern crate avrio_config;
extern crate avrio_core;
extern crate avrio_database;
use crate::genesis::{genesisBlockErrors, getGenesisBlock};
use avrio_config::config;
use avrio_core::{account::getAccount, transaction::*};
use avrio_database::getData;
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate log;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};
extern crate rand;
use rand::Rng;
extern crate cryptonightrs;
use bincode::{deserialize, serialize};
use cryptonightrs::cryptonight;
use serde_json::*;
use std::fs::File;
use std::io::prelude::*;
#[derive(Debug)]
pub enum blockValidationErrors {
    invalidBlockhash,
    badSignature,
    indexMissmatch,
    invalidPreviousBlockhash,
    invalidTransaction,
    genesisBlockMissmatch,
    failedToGetGenesisBlock,
    other,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Header {
    pub version_major: u8,
    pub version_breaking: u8,
    pub version_minor: u8,
    pub chain_key: String,
    pub prev_hash: String,
    pub height: u64,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Block {
    pub header: Header,
    pub txns: Vec<Transaction>,
    pub hash: String,
    pub nonce: String,
    pub signature: String,
    pub node_signatures: Vec<String>, // a block must be signed by at least (c / 2) + 1 nodes to be valid (ensures at least ne honest node has singed it)
}

pub fn getBlock(chainkey: &String, height: u64) -> Block {
    // returns the block when you know the chain and the height
    let hash = getData(
        config().db_path + &"/".to_owned() + chainkey + &"-invs".to_owned(),
        &height.to_string(),
    );
    if hash == "-1".to_owned() {
        return Block::default();
    } else if hash == "0".to_owned() {
        return Block::default();
    } else {
        return getBlockFromRaw(hash);
    }
}

pub fn getBlockFromRaw(hash: String) -> Block {
    // returns the block when you only know the hash by opeining the raw blk-HASH.dat file (where hash == the block hash)
    let mut file =
        File::open(config().db_path + &"/blocks/blk-".to_owned() + &hash + ".dat").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents);
    return serde_json::from_str(&contents).unwrap_or_default();
}

pub fn saveBlock(block: Block) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // formats the block into a .dat file and saves it under block-hash.dat
    let encoded: Vec<u8> = serde_json::to_string(&block)?.as_bytes().to_vec();
    let mut file =
        File::create(config().db_path + &"/blocks/blk-".to_owned() + &block.hash + ".dat")?;
    file.write_all(&encoded)?;
    Ok(())
}

impl Header {
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.version_major.to_string().as_bytes());
        bytes.extend(self.version_breaking.to_string().as_bytes());
        bytes.extend(self.version_minor.to_string().as_bytes());
        bytes.extend(self.chain_key.as_bytes());
        bytes.extend(self.prev_hash.as_bytes());
        bytes.extend(self.height.to_string().as_bytes());
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes
    }
    pub fn hash(&mut self) -> String {
        let asbytes = self.bytes();
        let out = cryptonight(&asbytes, asbytes.len(), 0);
        return hex::encode(out);
    }
}

impl Block {
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.header.bytes());
        for tx in self.txns.clone() {
            bytes.extend(tx.hash.as_bytes());
        }
        bytes.extend(self.nonce.to_string().as_bytes());
        bytes
    }
    pub fn hash(&mut self) {
        let asbytes = self.bytes();
        let out = cryptonight(&asbytes, asbytes.len(), 0);
        self.hash = hex::encode(out);
    }
    pub fn sign(
        &mut self,
        private_key: &String,
    ) -> std::result::Result<(), ring::error::KeyRejected> {
        let key_pair =
            signature::Ed25519KeyPair::from_pkcs8(hex::decode(private_key).unwrap().as_ref())?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = hex::encode(key_pair.sign(msg));
        return Ok(());
    }
    pub fn validSignature(&self) -> bool {
        let msg: &[u8] = self.hash.as_bytes();
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            hex::decode(self.header.chain_key.to_owned()).unwrap_or_else(|e| {
                error!(
                    "Failed to decode public key from hex {}, gave error {}",
                    self.header.chain_key, e
                );
                return vec![0, 1, 0];
            }),
        );
        let mut res: bool = true;
        peer_public_key
            .verify(
                msg,
                hex::decode(self.signature.to_owned())
                    .unwrap_or_else(|e| {
                        error!(
                            "failed to decode signature from hex {}, gave error {}",
                            self.signature, e
                        );
                        return vec![0, 1, 0];
                    })
                    .as_ref(),
            )
            .unwrap_or_else(|_e| {
                res = false;
            });
        return res;
    }
    pub fn isOtherBlock(&self, OtherBlock: &Block) -> bool {
        self == OtherBlock
    }
}

pub fn check_block(blk: Block) -> std::result::Result<(), blockValidationErrors> {
    if blk.header.height == 0 {
        // This is a genesis block (the first block)
        // First we will check if there is a entry for this chain in the genesis blocks db
        let genesis: Block;
        let mut is_in_db = false;
        match getGenesisBlock(&blk.header.chain_key) {
            Ok(b) => {
                genesis = b;
                is_in_db = true;
            }
            Err(e) => match e {
                genesisBlockErrors::BlockNotFound => {
                    // this block is not in the genesis block db therefor this is a new chain that is not from the swap
                    genesis = Block::default();
                    is_in_db = false;
                }
                _ => {
                    warn!(
                        "Failed to get genesis block for chain: {}, gave error: {:?}",
                        &blk.header.chain_key, e
                    );
                    return Err(blockValidationErrors::failedToGetGenesisBlock);
                }
            },
        }
        if blk != genesis || genesis != Block::default() {
            return Err(blockValidationErrors::genesisBlockMissmatch);
        } else {
            if is_in_db == true {
                // if it is in the db it is guarenteed to be valid, we do not need to validate the block
                return Ok(());
            } else {
                // if it isn't it needs to be validated like any other block
                if blk.header.prev_hash != "00000000000".to_owned() {
                    return Err(blockValidationErrors::invalidPreviousBlockhash);
                } else if let Ok(_) = getAccount(&blk.header.chain_key) {
                    // this account allready exists, you can't have two genesis blocks
                    return Err(blockValidationErrors::genesisBlockMissmatch);
                } else if !blk.validSignature() {
                    return Err(blockValidationErrors::badSignature);
                }
                return Ok(());
            }
        }
    } else {
        // not genesis block
        if blk.header.prev_hash != getBlock(&blk.header.chain_key, &blk.header.height - 1).hash {
            return Err(blockValidationErrors::invalidPreviousBlockhash);
        } else if let Err(e) = getAccount(&blk.header.chain_key) {
            // this account allready exists, you can't have two genesis blocks
            return Err(blockValidationErrors::other);
        } else if !blk.validSignature() {
            return Err(blockValidationErrors::badSignature);
        }
        for txn in blk.txns {
            if !txn.validate_transaction() {
                return Err(blockValidationErrors::invalidTransaction);
            } else {
                return Ok(());
            }
        }
        return Ok(());
    }
}

pub mod genesis;
#[cfg(test)]
mod tests {
    use crate::*;
    use avrio_config::*;
    extern crate simple_logger;
    fn hash(subject: String) -> String {
        let asBytes = subject.as_bytes();
        unsafe {
            let out = cryptonight(&asBytes, asBytes.len(), 0);
            return hex::encode(out);
        }
    }
    #[test]
    fn test_block() {
        simple_logger::init_with_level(log::Level::Info).unwrap();
        let mut i_t: u64 = 0;
        let mut rng = rand::thread_rng();
        let rngc = randc::SystemRandom::new();
        for i in 0..=1000 {
            let mut block = Block::default();
            block.nonce = i.to_string();
            let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
            let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
            let peer_public_key_bytes = key_pair.public_key().as_ref();
            while i_t < 10 {
                let mut txn = Transaction {
                    hash: String::from(""),
                    amount: rng.gen(),
                    extra: String::from(""),
                    flag: 'n',
                    sender_key: String::from(""),
                    receive_key: (hash(String::from(
                        "rc".to_owned() + &rng.gen::<u64>().to_string(),
                    ))),
                    access_key: String::from(""),
                    gas_price: rng.gen::<u16>() as u64,
                    max_gas: rng.gen::<u16>() as u64,
                    gas: rng.gen::<u16>() as u64,
                    nonce: rng.gen(),
                    signature: String::from(""),
                    timestamp: 0,
                    unlock_time: 0,
                };
                txn.sender_key = hex::encode(peer_public_key_bytes);
                txn.hash();
                // Sign the hash
                let msg: &[u8] = txn.hash.as_bytes();
                txn.signature = hex::encode(key_pair.sign(msg));
                let peer_public_key =
                    signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
                //peer_public_key.verify(msg, hex::decode(&txn.signature.to_owned()).unwrap().as_ref()).unwrap();
                block.txns.push(txn);
                i_t += 1;
            }
            block.hash();
            let msg: &[u8] = block.hash.as_bytes();
            block.signature = hex::encode(key_pair.sign(msg));
            block.header.chain_key = hex::encode(peer_public_key_bytes);
            println!("constructed block: {}, checking signature...", block.hash);
            assert_eq!(block.validSignature(), true);
            let block_clone = block.clone();
            println!("saving block");
            let mut conf = Config::default();
            conf.create();
            println!("Block: {:?}", block);
            saveBlock(block).unwrap();
            println!("reading block...");
            let block_read = getBlockFromRaw(block_clone.hash.clone());
            println!("read block: {}", block_read.hash);
            assert_eq!(block_read, block_clone);
        }
    }
}
