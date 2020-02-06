// This file generates the genesis block for a new network.

extern crate database;
extern crate blockchain;
extern crate config;
extern crate rand;
use rand::Rng;
extern crate hex;

let mut genesis_txns: Vec<Transactions> = vec![
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
        nonce: rng.gen::<u8>(),
    }
];

fn generateGenesisBlock() -> Block{
    for tx in genesis_txns {
        tx.hash = tx.hash();
        tx.signature = sign(hex::encode(vec![0, 32]).to_owned(), tx.hash);
    }
    let mut genesis_block = Block {
        header: Header {
            version_major: 0,
            version_minor: 0
            chain_key: hex::encode(vec![0, 32]).to_owned(),
            prev_hash: hex::encode(vec![0, 32]).to_owned(),
            height: 0,
            timestamp: 0,
        },
        txns: genesis_txns,
    }
    genesis_block.hash = genesis_block.hash();
    genesis_block.signature = genesis_block.sign(hex::encode(vec![0, 32]).to_owned(), genesis_block.hash);
    return genesis_block;
}
        
