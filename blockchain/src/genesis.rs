// This file generates the genesis block for a new network.

extern crate avrio_config;
use avrio_config::config;
extern crate avrio_database;
use avrio_database::{getData, saveData};
use rand::Rng;
extern crate hex;
use crate::{Block, Header};
use avrio_core::transaction::Transaction;
use serde::{Deserialize, Serialize};
#[derive(Debug, PartialEq)]
pub enum geneisBlockErrors {
    BlockNotFound,
    OtherDb,
    Other,
}
pub fn getGenesisTxns() -> Vec<Transaction> {
    return vec![
        // any txns to be in the genesis block are defined here, below is a template for one.
        Transaction {
            hash: String::from(""),
            amount: 0,
            extra: String::from(""),
            flag: 'n',
            sender_key: hex::encode(vec![0, 32]).to_owned(),
            receive_key: String::from(""),
            access_key: String::from(""),
            unlock_time: 0,
            gas_price: 0,
            gas: 0,
            max_gas: u64::max_value(),
            nonce: 0,
            timestamp: 0,
            signature: String::from(""),
        },
    ];
}

pub fn generateGenesisBlock(chainKey: String) -> Block {
    let mut my_genesis_txns: Vec<Transaction> = vec![];
    let genesis_txns = getGenesisTxns();
    for tx in genesis_txns {
        if tx.receive_key == chainKey {
            my_genesis_txns.push(tx);
        }
    }

    let mut genesis_block = Block {
        header: Header {
            version_major: 0,
            version_breaking: 0,
            version_minor: 1,
            chain_key: chainKey,
            prev_hash: hex::encode(vec![0, 32]).to_owned(),
            height: 0,
            timestamp: 0,
        },
        hash: "".to_string(),
        txns: my_genesis_txns,
        signature: "".to_string(),
        node_signatures: vec!["".to_string(); 11],
    };

    genesis_block.hash();
    return genesis_block;
}

pub fn getGenesisBlock(chainkey: &String) -> Result<Block, geneisBlockErrors> {
    let data = getData(
        config().db_path + &"genesis-blocks".to_string(),
        chainkey.to_owned(),
    );
    let none = String::from("-1");
    let zero = String::from("0");
    return match data {
        none => Err(geneisBlockErrors::BlockNotFound),
        zero => Err(geneisBlockErrors::OtherDb),
        _ => {
            let b: Block = serde_json::from_str(&data).unwrap_or_else(|e| {
                warn!(
                    "Failed to parse genesis block from blob {}, gave error: {}",
                    &data, e
                );
                return Block::default();
            });
            if b == Block::default() {
                return Err(geneisBlockErrors::Other);
            } else {
                return Ok(b);
            }
        }
    };
}
