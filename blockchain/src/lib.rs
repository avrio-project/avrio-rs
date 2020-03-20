extern crate avrio_config;
extern crate avrio_core;
extern crate avrio_database;
use avrio_config::config;
use avrio_database::getData;
use crate::genesis::getGenesisBlock;
use avrio_core::transaction::*;
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate log;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};

use std::fs::File;
use std::io::prelude::*;
use bincode::{deserialize, serialize};
pub enum blockValidationErrors {
    invalidBlockhash,
    badSignature,
    indexMissmatch,
    invalidPreviousBlockhash,
    invalidTransaction,
    genesisBlockMissmatch,
    failedToGetGenesisBlock,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Header {
    pub version_major: u8,
    pub version_breaking: u8,
    pub version_minor: u8,
    pub chain_key: String,
    pub prev_hash: String,
    pub height: u64,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Block {
    pub header: Header,
    pub txns: Vec<Transaction>,
    pub hash: String,
    pub signature: String,
    pub node_signatures: Vec<String>, // a block must be signed by at least (c / 2) + 1 nodes to be valid (ensures at least ne honest node has singed it)
}
// todo
pub fn getBlock(chainkey: &String, height: u64) -> Block { // returns the block when you know the chain and the height
    let hash = getData(config().db_path + &"/".to_owned() + chainkey + &"-inventories".to_owned() , height.to_string());
    if hash == "-1".to_owned() {
        return Block::default();
    } else if hash == "0".to_owned() {
        return Block::default();
    }
    else {
        return getBlockFromRaw(hash);
    }
}

pub fn getBlockFromRaw(hash: String) -> Block { // returns the block when you only know the hash by opeining the raw block-HASH.dat file (where hash == the block hash)
    let mut file = File::open("block-".to_owned() + &hash + ".dat").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    return deserialize(&contents.as_bytes()).unwrap_or_default();
}

pub fn saveBlock(block: Block) -> std::result::Result<(), Box<dyn std::error::Error>> { // formats the block into a .dat file and saves it under block-hash.dat
    let encoded: Vec<u8> = serialize(&block).unwrap();
    let mut file = File::create("block-".to_owned() + &block.hash + ".dat")?;
    file.write_all(&encoded)?;
    Ok(())
}

impl Header {
    fn bytes(&self) -> Vec<u8> {
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
    fn hash(&mut self) {
        // TODO
    }
}

impl Block {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.header.bytes());
        for tx in self.txns.clone() {
            bytes.extend(tx.hash.as_bytes());
        }
        bytes
    }
    fn hash(&mut self) {
        // TODO
    }
    pub fn sign(&mut self, privateKey: &String) -> std::result::Result<(), ring::error::KeyRejected> {
        let key_pair =
            signature::Ed25519KeyPair::from_pkcs8(hex::decode(privateKey).unwrap().as_ref())?;
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
                return ();
            });
        return true; // ^ wont unwrap if sig is invalid
    }
    fn isOtherBlock(&self, OtherBlock: &Block) -> bool {
        self == OtherBlock
    }
}

pub fn check_block(blk: Block) -> std::result::Result<(), blockValidationErrors> {
    if blk.header.height == 0 {
        // genesis block
        // could be costly
        let genesis: Block;
        match getGenesisBlock(&blk.header.chain_key) {
            Ok(b) => genesis = b,
            Err(e) => {
                warn!(
                    "Failed to get genesis block for chain: {}, gave error: {:?}",
                    &blk.header.chain_key, e
                );
                return Err(blockValidationErrors::failedToGetGenesisBlock);
            }
        }
        if blk != genesis {
            return Err(blockValidationErrors::genesisBlockMissmatch);
        } else {
            return Ok(());
        }
    } else {
        // not genesis block
        if blk.header.prev_hash != getBlock(&blk.header.chain_key, &blk.header.height - 1).hash {
            return Err(blockValidationErrors::invalidPreviousBlockhash);
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

mod genesis;
