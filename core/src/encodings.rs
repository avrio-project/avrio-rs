use crate::{
    block::{Block, BlockType, Header},
    transaction::Transaction,
};
use log::*;
use std::error::Error;

impl Transaction {
    pub fn encode_compressed(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.hash,
            self.amount,
            self.extra,
            self.flag,
            self.sender_key,
            self.receive_key,
            self.access_key,
            self.unlock_time,
            self.gas_price,
            self.max_gas,
            self.nonce,
            self.timestamp,
        )
    }
    pub fn decode_compressed(&mut self, encoded: String) -> Result<(), Box<dyn std::error::Error>> {
        let components: Vec<&str> = encoded.split(':').collect();
        if components.len() != 12 {
            error!(
                "Failed to decode compressed transaction, expected component count=14, got={}",
                components.len()
            );
            println!(
                "Faulty encoded transaction: encoded={}, components={:#?}",
                encoded, components
            );
            return Err("components len not 14".into());
        }
        self.hash = components[0].to_string();
        self.amount = components[1].parse()?;
        self.extra = components[2].to_string();
        self.flag = components[3].parse()?;
        self.sender_key = components[4].to_string();
        self.receive_key = components[5].to_string();
        self.access_key = components[6].to_string();
        self.unlock_time = components[7].parse()?;
        self.gas_price = components[8].parse()?;
        self.max_gas = components[9].parse()?;
        self.nonce = components[10].parse()?;
        self.timestamp = components[11].parse()?;
        Ok(())
    }
}
impl Block {
    pub fn encode_compressed(&self) -> String {
        match self.block_type {
            BlockType::Recieve => {
                let mut transactions: String = String::from("");
                for txn in &self.txns {
                    transactions += &(txn.encode_compressed() + ","); // TODO: replace with a vector of txn hashes
                }
                return format!(
                    "{}│{}│{}│{}│{}",
                    self.header.encode_compressed(),
                    self.send_block.clone().unwrap_or_default(),
                    transactions,
                    self.hash,
                    self.signature,
                );
            }
            BlockType::Send => {
                let mut transactions: String = String::from("");
                for txn in &self.txns {
                    transactions += &(txn.encode_compressed() + ",");
                }
                return format!(
                    "{}│{}│{}│{}",
                    self.header.encode_compressed(),
                    transactions,
                    self.hash,
                    self.signature,
                );
            }
        }
    }

    pub fn decode_compressed(&mut self, encoded: String) -> Result<(), Box<dyn Error>> {
        let components: Vec<&str> = encoded.split('│').collect();

        if components.len() == 5 {
            // rec block
            self.header.decode_compressed(components[0].to_string())?;
            self.send_block = Some(components[1].to_string());
            self.block_type = BlockType::Recieve;
            let transactions_string: Vec<&str> = components[2].split(',').collect();
            for txn_string in transactions_string {
                if txn_string != "" {
                    let mut txn_new = Transaction::default();
                    txn_new.decode_compressed(txn_string.to_string())?;
                    self.txns.push(txn_new);
                }
            }
            self.hash = components[3].to_string();
            self.signature = components[4].to_string();
        } else if components.len() == 4 {
            // send block
            self.header.decode_compressed(components[0].to_string())?;
            self.send_block = None;
            self.block_type = BlockType::Send;
            let transactions_string: Vec<&str> = components[1].split(',').collect();
            for txn_string in transactions_string {
                if txn_string != "" {
                    let mut txn_new = Transaction::default();
                    txn_new.decode_compressed(txn_string.to_string())?;
                    self.txns.push(txn_new);
                }
            }
            self.hash = components[2].to_string();
            self.signature = components[3].to_string();
        } else {
            error!(
                "Failed to decode block, expected len=5 or len=4, got len={}",
                components.len()
            );
            println!("Encoded={}, components={:#?}", encoded, components);
            return Err(format!("components wrong len: {}", components.len()).into());
        }
        Ok(())
    }
}
impl Header {
    pub fn encode_compressed(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.version_major,
            self.version_breaking,
            self.version_minor,
            self.chain_key,
            self.prev_hash,
            self.height,
            self.timestamp,
            bs58::encode(self.network.clone()).into_string()
        )
    }
    pub fn decode_compressed(&mut self, encoded: String) -> Result<(), Box<dyn Error>> {
        let components: Vec<&str> = encoded.split('|').collect();
        if components.len() != 8 {
            error!(
                "Failed to decode header, expected len=8, got len={}",
                components.len()
            );
            debug!("Encoded={}, components={:#?}", encoded, components);
            return Err(format!("components wrong len, {}", components.len()).into());
        }
        self.version_major = components[0].parse()?;
        self.version_breaking = components[1].parse()?;
        self.version_minor = components[2].parse()?;
        self.chain_key = components[3].to_string();
        self.prev_hash = components[4].to_string();
        self.height = components[5].parse()?;
        self.timestamp = components[6].parse()?;
        self.network = bs58::decode(components[7]).into_vec()?;
        Ok(())
    }
}

#[test]
fn test_encodeing() {
    use avrio_crypto::Wallet;
    println!("Testing encoding");
    println!("Forming block");
    let wall: Wallet = Wallet::gen();
    let mut block: Block = Block::default();
    for nonce in 0..10 {
        let mut txn = Transaction {
            hash: String::from(""),
            amount: 0,
            extra: String::from(""),
            flag: 'n',
            sender_key: wall.public_key.clone(),
            receive_key: wall.public_key.clone(),
            access_key: wall.public_key.clone(),
            unlock_time: 0,
            gas_price: 1,
            max_gas: 12124124,
            nonce,
            timestamp: 2352352352,
        };
        txn.hash();
        block.txns.push(txn);
    }
    block.header = Header {
        version_major: 0,
        version_breaking: 0,
        version_minor: 0,
        chain_key: wall.public_key,
        prev_hash: String::from("0"),
        height: 0,
        timestamp: 0,
        network: vec![],
    };
    block.hash();
    block.sign(&wall.private_key).unwrap();
    let block_encoded = block.encode_compressed();
    let mut block_decoded = Block::default();
    block_decoded
        .decode_compressed(block_encoded.clone())
        .unwrap();
    println!("Block {:#?}", block);
    println!("Encoded: {}", block_encoded);
    println!("Block Decoded: {:#?}", block_decoded);
    assert_eq!(block, block_decoded);
    assert_eq!(block_decoded.encode_compressed(), block_encoded);

    let mut rec_block = block.clone();
    rec_block.block_type = BlockType::Recieve;
    rec_block.send_block = Some(block.hash);
    rec_block.hash();
    rec_block.signature = String::from("");

    let block_encoded = rec_block.encode_compressed();
    let mut block_decoded = Block::default();
    block_decoded
        .decode_compressed(block_encoded.clone())
        .unwrap();
    println!("Block {:#?}", rec_block);
    println!("Encoded: {}", block_encoded);
    println!("Block Decoded: {:#?}", block_decoded);
    assert_eq!(rec_block, block_decoded);
    assert_eq!(block_decoded.encode_compressed(), block_encoded);
}
