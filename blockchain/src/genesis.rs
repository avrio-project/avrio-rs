// This file generates the genesis block for a new network.

extern crate avrio_config;
use avrio_config::config;

extern crate hex;
use crate::{Block, BlockType, Header};
use avrio_core::transaction::Transaction;
use std::time::{SystemTime, UNIX_EPOCH};
#[derive(Debug, PartialEq)]
pub enum GenesisBlockErrors {
    BlockNotFound,
    OtherDb,
    Other,
}

extern crate avrio_crypto;

pub fn genesis_blocks() -> Vec<Block> {
    /*example
    let priv_key= "GD8M1Qm17WXoukx8QqqfvXY5t8ft7APi9iUqUXAytM1dUsiZxCwaDyMhn7pNDBaybagw6QVgYkye5oosd2zmoeiFRak1MjoUSi5Nfen6PQHrzj6y3FrR".to_owned();
    let wall = Wallet::from_private_key(priv_key);
    let mut txn = Transaction {
        hash: String::from(""),
        amount: 10000, // 1 AIO
        extra: String::from(""),
        flag: 'c',
        sender_key: wall.public_key.clone(),
        receive_key: String::from(""),
        access_key: String::from(""),
        unlock_time: 0,
        gas_price: 10, // 0.001 AIO
        gas: 0,        // claim uses 0 fee
        max_gas: u64::max_value(),
        nonce: 0,
        timestamp: 0,
        signature: String::from(""),
    };
    txn.hash();
    let _ = txn.sign(&wall.private_key);
    let mut blk = Block {
        header: Header {
            version_major: 0,
            version_breaking: 0,
            version_minor: 0,
            chain_key: wall.public_key.clone(),
            prev_hash: bs58::encode("0".to_owned()).into_string(),
            height: 0,
            timestamp: 0,
            network: vec![97, 118, 114, 105, 111, 32, 110, 111, 111, 100, 108, 101],
        },
        txns: vec![txn],
        hash: "".to_owned(),
        signature: "".to_owned(),
        confimed: false,
        node_signatures: vec![],
    };
    blk.hash();
    let _ = blk.sign(&wall.private_key);
    vec![blk]
    */
    vec![]
}

pub fn get_genesis_txns() -> Vec<Transaction> {
    return vec![
        // any txns to be in the genesis block are defined here, below is a template for one.
        Transaction {
            hash: String::from(""),
            amount: 0,
            extra: String::from(""),
            flag: 'n',
            sender_key: hex::encode(vec![0, 32]),
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

pub fn generate_genesis_block(
    chain_key: String,
    priv_key: String,
) -> Result<Block, GenesisBlockErrors> {
    let mut my_genesis_txns: Vec<Transaction> = vec![];
    let genesis_txns = get_genesis_txns();
    for tx in genesis_txns {
        if tx.receive_key == chain_key {
            my_genesis_txns.push(tx);
        }
    }

    let mut genesis_block = Block {
        header: Header {
            version_major: 0,
            version_breaking: 0,
            version_minor: 1,
            chain_key,
            prev_hash: "00000000000".to_owned(),
            height: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64,
            network: config().network_id,
        },
        block_type: BlockType::Send,
        send_block: None,
        hash: "".to_string(),
        txns: my_genesis_txns,
        signature: "".to_string(),
        confimed: false,
        node_signatures: vec![],
    };

    genesis_block.hash();
    genesis_block.sign(&priv_key).unwrap();
    Ok(genesis_block)
}
/// Reads the genesis block for this chain from the list of blocks
pub fn get_genesis_block(chainkey: &str) -> Result<Block, GenesisBlockErrors> {
    for block in genesis_blocks() {
        if block.header.chain_key == *chainkey {
            return Ok(block);
        }
    }
    Err(GenesisBlockErrors::BlockNotFound)
}
