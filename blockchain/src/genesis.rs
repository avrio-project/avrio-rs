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

pub fn genesis_blocks() -> Vec<Block> {
    //example
    vec![
        Block { 
            header: Header { 
                version_major: 0,
                version_breaking: 0,
                version_minor: 0,
                chain_key: "5ohL19qYPbp9eK1UNBjjasL9Vum1Ge1NAjMUE81xpkBb".to_owned(), 
                prev_hash: bs58::encode("0".to_owned()).into_string(), 
                height: 0, 
                timestamp: 0, 
                network: vec![97, 118, 114, 105, 111, 32, 110, 111, 111, 100, 108, 101] 
            }, 
            txns: vec![], 
            hash: "HDgfnUKNXQSu9Gv6aYcqcqeryYyehF19EqdAYETVqrw7".to_owned(), 
            signature: "5wzafcinKZ22gtbSKWWT9vKxB79dWU3CJRqWJemvv4DLhzkarASk32HskJfqznKfXjK5WCzW2Vu2ZmZm5AqucvRn".to_owned(), 
            confimed: false, 
            node_signatures: vec![] 
        }
    ]
}

pub fn get_genesis_txns() -> Vec<Transaction> {
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
    let genesis_txns = get_genesis_txns();
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
/// Reads the genesis block for this chain from the list of blocks
pub fn getGenesisBlock(chainkey: &String) -> Result<Block, genesisBlockErrors> {
    for block in genesis_blocks() {
        if block.header.chain_key == *chainkey {
            return Ok(block);
        }
    }
    return Err(genesisBlockErrors::BlockNotFound);
}
