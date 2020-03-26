// This file generates the genesis block for a new network.

extern crate avrio_config;
use avrio_config::config;
use avrio_database::getData;

extern crate hex;
use crate::{Block, Header};
use avrio_core::transaction::Transaction;

#[derive(Debug, PartialEq)]
pub enum genesisBlockErrors {
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

pub fn generateGenesisBlock(
    chainKey: String,
    privKey: String,
) -> Result<Block, genesisBlockErrors> {
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
            prev_hash: "00000000000".to_owned(),
            height: 0,
            timestamp: 0,
            network: config().network_id,
        },
        hash: "".to_string(),
        txns: my_genesis_txns,
        signature: "".to_string(),
        confimed: false,
        node_signatures: vec![],
    };

    genesis_block.hash();
    genesis_block.sign(&privKey);
    return Ok(genesis_block);
}
/// Reads the genesis block for this chain from the genesis blcoks db
pub fn getGenesisBlock(chainkey: &String) -> Result<Block, genesisBlockErrors> {
    let data = getData(config().db_path + &"/genesis-blocks".to_string(), chainkey);
    let _none = String::from("-1");
    let _zero = String::from("0");
    return match data {
        _none => Err(genesisBlockErrors::BlockNotFound),
        _zero => Err(genesisBlockErrors::OtherDb),
        _ => {
            let b: Block = serde_json::from_str(&data).unwrap_or_else(|e| {
                warn!(
                    "Failed to parse genesis block from blob {}, gave error: {}",
                    &data, e
                );
                return Block::default();
            });
            if b == Block::default() {
                return Err(genesisBlockErrors::Other);
            } else {
                return Ok(b);
            }
        }
    };
}
