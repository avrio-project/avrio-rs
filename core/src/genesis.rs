// This file generates the genesis block for a new network.

extern crate database;
extern crate blockchain;
extern crate config;
extern crate rand;
use rand::Rng;
extern crate hex;

let mut genesis_txns: Vec<Transactions> = vec![ // any txns to be in the genesis block are defined here, below is a template for one.
    Transaction {
        amount: 0,
        extra: "",
        flag: 0x00,
        sender_key: hex::encode(vec![0, 32]).to_owned(),
        receive_key: "",
        access_key: Option::None,
        gas_price: 1,
        gas: 0,
        max_gas: u64::max_value(),
        nonce: 192,
    }
];

fn generateGenesisBlock(chainKey: String, private_key: String) -> Block{
    let mut my_genesis_txns: Vec<Transactions> = vec![];
    for tx in genesis_txns {
        if tx.receive_key == chainKey {
            tx.hash = tx.hash();
            tx.signature = sign(hex::encode(private_key, tx.hash);
            my_genesis_txns.push(tx);
    }
    let mut genesis_block = Block {
        header: Header {
            version_major: 0,
            version_minor: 0
            chain_key: chainKey,
            prev_hash: hex::encode(vec![0, 32]).to_owned(),
            height: 0,
            timestamp: 0,
        },
        txns: my_genesis_txns,
    }
    genesis_block.hash = genesis_block.hash();
    genesis_block.signature = genesis_block.sign(private_key, genesis_block.hash);
    return genesis_block;
}
        
