extern crate avrio_config;
extern crate avrio_database;
use crate::{
    account::{get_account, set_account, Account},
    block::genesis::{get_genesis_block, GenesisBlockErrors},
    epoch::get_top_epoch,
    states::*,
    transaction::*,
    validate::Verifiable,
};
use avrio_config::config;
use avrio_database::*;
use serde::{Deserialize, Serialize};

extern crate bs58;

use ring::signature;
extern crate rand;

use avrio_crypto::{Hashable, Wallet};

use std::fs::File;
use std::io::prelude::*;
use thiserror::Error;
pub mod genesis {
    // This file generates the genesis block for a new network.

    extern crate avrio_config;
    use avrio_config::config;
    //use avrio_crypto::Wallet;

    extern crate hex;
    use crate::block::{Block, BlockType, Header};
    //use crate::transaction::Transaction;
    use std::time::{SystemTime, UNIX_EPOCH};
    #[derive(Debug, PartialEq)]
    pub enum GenesisBlockErrors {
        BlockNotFound,
        OtherDb,
        Other,
    }

    extern crate avrio_crypto;

    pub fn genesis_blocks() -> Vec<Block> {
        let blks: Vec<Block> = vec![];
        /*let priv_key= "GD8M1Qm17WXoukx8QqqfvXY5t8ft7APi9iUqUXAytM1dUsiZxCwaDyMhn7pNDBaybagw6QVgYkye5oosd2zmoeiFRak1MjoUSi5Nfen6PQHrzj6y3FrR".to_owned();
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
            max_gas: u64::max_value(),
            nonce: 0,
            timestamp: 0,
        };
        txn.hash();
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
            block_type: BlockType::Send,
            send_block: None,
        };
        blk.hash();
        let _ = blk.sign(&wall.private_key);
        blks.push(blk);*/
        blks
    }

    pub fn generate_genesis_block(
        chain_key: String,
        priv_key: String,
    ) -> Result<Block, GenesisBlockErrors> {
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
            txns: vec![],
            signature: "".to_string(),
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
}
#[derive(Debug, Error)]
pub enum BlockValidationErrors {
    #[error("More than 10 transactions in block")]
    TooManyTxn,
    #[error("Block version too new")]
    VersionTooNew,
    #[error("Block hash does not equal computed hash")]
    BlockHashMismatch,
    #[error("Block too big")]
    BlockTooLarge,
    #[error("Block signature invalid")]
    BadSignature,
    #[error("Index mismatch")]
    IndexMismatch,
    #[error("Invalid previous block hash")]
    InvalidPreviousBlockhash,
    #[error("Block hash collision")]
    BlockCollision,
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(Box<dyn std::error::Error>),
    #[error("Account already exists")]
    AccountExists,
    #[error("Faield to get account: {0}")]
    FailedToGetAccount(u8),
    #[error("Transaction count not zero in genesis block")]
    TransactionCountNotZero,
    #[error("Genesis block mismatch")]
    GenesisBlockMismatch,
    #[error("Failed to get hardcoded genesis block")]
    FailedToGetGenesisBlock,
    #[error("Block 0 not send block")]
    GenesisNotSendBlock,
    #[error("Block already exists")]
    BlockExists,
    #[error("Not enough signatures on accepted block")]
    TooLittleSignatures,
    #[error("Block contains invalid fullnode signature")]
    BadNodeSignature,
    #[error("bad timestamp")]
    TimestampInvalid,
    #[error("Wrong network")]
    NetworkMismatch,
    #[error("Block not genesis but account does not exist")]
    AccountDoesNotExist,
    #[error("Refrenced previous block not found")]
    PreviousBlockDoesNotExist,
    #[error("Refrenced send block not found")]
    SendBlockDoesNotExist,
    #[error("Block too far in future")]
    BlockTooFarInTheFuture,
    #[error("Claimed send block not send block")]
    SendBlockWrongType,
    #[error("Traansaction not found in referenced send block")]
    TransactionsNotInSendBlock,
    #[error("Transaction not sent by block former")]
    TransactionFromWrongChain,
    #[error("Send block not set on recieve block")]
    SendBlockEmpty,
    #[error("Send block not consensus")]
    NonConsensusSendBlock,
    #[error("Consensus block sender not round leader")]
    UnauthorisedConsensusBlock,
    #[error("Consensus block contains non consensus type txn")]
    ContainsNonConsensusTxn,
    #[error("Unknown/Other error")]
    Other,
}
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum BlockType {
    Send,
    Recieve,
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
    pub network: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Block {
    pub header: Header,
    pub block_type: BlockType,
    pub send_block: Option<String>, // the send block this recieve block is in refrence to
    pub txns: Vec<Transaction>,
    pub hash: String,
    pub signature: String,
}

impl Default for BlockType {
    fn default() -> Self {
        BlockType::Send
    }
}

/// returns the block when you know the chain and the height
pub fn get_block(chain_key: &str, height: u64) -> Block {
    let hash = get_data(
        config().db_path + "/chains/" + chain_key + "-chainindex",
        &height.to_string(),
    );
    if hash == *"-1" || hash == *"0" {
        Block::default()
    } else {
        get_block_from_raw(hash)
    }
}

/// returns the block when you only know the hash by opeining the raw blk-HASH.dat file (where hash == the block hash)
pub fn get_block_from_raw(hash: String) -> Block {
    let try_open = File::open(config().db_path + &"/blocks/blk-".to_owned() + &hash + ".dat");
    if let Ok(mut file) = try_open {
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut ret = Block::default();
        if let Ok(_) = ret.decode_compressed(contents) {
            return ret;
        } else {
            return Block::default();
        }
    } else {
        trace!(
            "Opening raw block file (hash={}) failed. Reason={}",
            hash,
            try_open.unwrap_err()
        );
        Block::default()
    }
}

/// formats the block into a .dat file and saves it under block-hash.dat
pub fn save_block(block: Block) -> std::result::Result<(), Box<dyn std::error::Error>> {
    trace!("Saving block with hash: {}", block.hash);
    let encoded: Vec<u8> = block.encode_compressed().as_bytes().to_vec();
    let mut file = File::create(config().db_path + "/blocks/blk-" + &block.hash + ".dat")?;
    file.write_all(&encoded)?;
    trace!("Saved Block");
    Ok(())
}

impl Hashable for Header {
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
}
impl Header {
    /// Returns the hash of the header bytes
    pub fn hash(&mut self) -> String {
        self.hash_item()
    }
}

impl Hashable for Block {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.header.bytes());
        for tx in self.txns.clone() {
            bytes.extend(tx.hash.as_bytes());
        }
        bytes
    }
}

impl Verifiable for Block {
    fn valid(&self) -> Result<(), Box<dyn std::error::Error>> {
        let start_time = SystemTime::now();
        let config = config();
        let block = self.clone();
        // check if the block version is supported
        match format!(
            "{}{}",
            block.header.version_major, block.header.version_breaking
        )
        .parse::<u64>()
        {
            Ok(block_version) => {
                match format!("{}{}", config.version_major, config.version_breaking).parse::<u64>()
                {
                    Ok(our_block_version) => {
                        if our_block_version < block_version {
                            return Err(Box::new(BlockValidationErrors::VersionTooNew));
                        } // else: continue
                    }
                    Err(_) => return Err(Box::new(BlockValidationErrors::Other)),
                }
            }
            Err(_) => return Err(Box::new(BlockValidationErrors::Other)),
        }
        // now if that did not return Err() check if the network tag is correct
        if config.network_id != block.header.network {
            return Err(Box::new(BlockValidationErrors::NetworkMismatch));
        }
        // Now we check the hash of the block, by recomputing it
        let computed_hash = block.hash_return();
        if computed_hash != block.hash {
            debug!(
                "Block hash mismatch, expected={}, computed={}",
                block.hash, computed_hash
            );
            return Err(Box::new(BlockValidationErrors::BlockHashMismatch));
        }
        // now see if we have the block saved, if so return err
        let got_block = get_block_from_raw(computed_hash);
        if got_block == block {
            // we have this block saved, return Ok
            debug!(
                "Already have block with hash={} in raw-block files (during validation)",
                block.hash
            );
            return Err(Box::new(BlockValidationErrors::BlockCollision));
        } else if got_block != Block::default() {
            // we have a block with the same hash saved, but it is not the same as this one!
            debug!("Block Collision during validation, found block with matching hash on disk: expected={:#?}, got={:#?}", block, got_block);
            return Err(Box::new(BlockValidationErrors::BlockCollision));
        }
        // else: we dont have this block saved; continue
        // check if the block is a consensus block (sent by the round leader of the zero committee)
        if block.header.chain_key == "0" {
            trace!("Block {} sent from consensus chain", block.hash);
            if !block.valid_signature() {
                // check signature even if block is a recieve block (unlike with non consensus blocks)
                return Err(Box::new(BlockValidationErrors::BadSignature));
            }
            if block.block_type == BlockType::Recieve {
                // check the refrenced send block is a valid consensus send block
                if let Some(send_block) = block.send_block.clone() {
                    let send_block_struct = get_block_from_raw(send_block.clone());
                    trace!(
                        "Got send block {} for consensus recieve block {}",
                        send_block_struct.hash,
                        block.hash
                    );
                    if send_block_struct.header.chain_key != "0" {
                        error!("Consensus block {} references non-consensus or non-existing send block {}", block.hash, send_block);
                        return Err(Box::new(BlockValidationErrors::NonConsensusSendBlock));
                    } else if send_block_struct.block_type != BlockType::Send {
                        error!("Consensus block {} references non-send block or non-existing block {} as send block", block.hash, send_block);
                        return Err(Box::new(BlockValidationErrors::SendBlockWrongType));
                    }
                    for txn in &block.txns {
                        if !send_block_struct.txns.contains(txn) {
                            error!("Consensus block {} contains txn {} which is not in consensus send block {}", block.hash, txn.hash, send_block);
                            return Err(Box::new(
                                BlockValidationErrors::TransactionsNotInSendBlock,
                            ));
                        }
                    }
                } else {
                    error!(
                        "Consensus block {} recieve type but does not reference a send block",
                        block.hash
                    );
                    return Err(Box::new(BlockValidationErrors::SendBlockEmpty));
                }
            }
            let curr_epoch = get_top_epoch()?;
            let round_leader = curr_epoch.committees[0].get_round_leader()?;
            // check every transaction is a consensus txn and valid
            for txn in &block.txns {
                if !txn.consensus_type() {
                    error!(
                        "Consensus block {} contains non-consensus txn {}, flag={} (type={})",
                        block.hash,
                        txn.hash,
                        txn.flag,
                        txn.type_transaction()
                    );
                    return Err(Box::new(BlockValidationErrors::ContainsNonConsensusTxn));
                }
                if txn.sender_key != round_leader {
                    error!(
                        "Consensus block {} contains txn {} not sent by round leader {} (sent by {})",
                        block.hash,
                        txn.hash,
                        round_leader,
                        txn.sender_key
                    );
                    return Err(Box::new(BlockValidationErrors::UnauthorisedConsensusBlock));
                }
                if self.block_type == BlockType::Send {
                    if let Err(e) = txn.valid() {
                        error!(
                            "Consensus block {} contains invalid txn {}, reason={}",
                            block.hash, txn.hash, e
                        );
                        return Err(Box::new(BlockValidationErrors::InvalidTransaction(e)));
                    }
                }
            }
            if block.header.height != 0 {
                // get previous block
                let got_block = *Block::get(self.header.prev_hash.clone()).unwrap_or_default();
                if got_block == Block::default() {
                    error!("Cannot find block at height={} for consensus chain with hash={} (while validating consensus block with hash={})", block.header.height - 1, block.header.prev_hash, block.hash);
                    return Err(Box::new(BlockValidationErrors::PreviousBlockDoesNotExist));
                } else if got_block.hash != block.header.prev_hash {
                    error!(
                        "Previous block hash mismatch, expected={}, got={}",
                        block.header.prev_hash, got_block.hash
                    );
                    return Err(Box::new(BlockValidationErrors::InvalidPreviousBlockhash));
                }
                // else: the previous block exists and has the correct hash
                // check timestamp of block
                if block.header.timestamp < got_block.header.timestamp {
                    error!("Block with hash={} older than parent block with hash={}, block_timestamp={}, parent_timestamp={}", block.hash, got_block.hash, block.header.timestamp, got_block.header.timestamp);
                } else if block.header.timestamp - (config.transaction_timestamp_max_offset as u64)
                    > (SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_millis() as u64)
                {
                    error!(
            "Block with hash={} is too far in the future, transaction_timestamp_max_offset={}, block_timestamp={}, delta_timestamp={}, our_time={}", 
            block.hash,
            config.transaction_timestamp_max_offset,
            block.header.timestamp, block.header.timestamp - (config.transaction_timestamp_max_offset as u64),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis()
        );
                    return Err(Box::new(BlockValidationErrors::BlockTooFarInTheFuture));
                }
            }
            //check the block has at most 3 transactions in it
            if block.txns.len() > 3 {
                return Err(Box::new(BlockValidationErrors::TooManyTxn));
            } else if std::mem::size_of_val(&block) > 5000000 {
                // check the block is no larger than 5MiB
                return Err(Box::new(BlockValidationErrors::BlockTooLarge));
            }
        } else {
            // check if this block is the first 'genesis' block
            if block.header.height == 0 {
                if block.header.prev_hash != "00000000000" {
                    debug!(
                        "Expected block at height 0 (genesis) to have previous hash of 00000000000"
                    );
                    return Err(Box::new(BlockValidationErrors::InvalidPreviousBlockhash));
                }
                // check if the genesis block is in our hardcoded  genesis blocks (for the avrio swap, please see the WIKI for more details)
                match get_genesis_block(&block.hash) {
                    Ok(_) => {
                        // We have already checked the hash of this block, so if there is a hardcoded genesis block with the same hash they must be equal
                        debug!("Found hardcoded genesis block with correct hash (hash={}) while validating block", block.hash);
                    }
                    Err(e) => {
                        // we got an error while trying to get the hardcoded genesis block
                        // if this error is GenesisBlockErrors::BlockNotFound we can safley continue and know this genesis block is dynamic (not hardcoded)
                        match e {
                            GenesisBlockErrors::BlockNotFound => {
                                debug!("Block with hash={} not found in hardcoded genesis blocks, assuming dynamic", block.hash);
                            }
                            _ => {
                                error!("Got error {:?} while trying to check hardcoded genesis blocks for hash {}", e, block.hash);
                                return Err(Box::new(
                                    BlockValidationErrors::FailedToGetGenesisBlock,
                                ));
                            }
                        }
                    }
                }
                // if we got here then the genesis block was not found in the hardcoded list BUT there was no error in checking so, continue validation
                match get_account(&block.header.chain_key) {
                    Ok(acc) => {
                        if acc != Account::default() {
                            debug!("Validating genesis block with hash={} for chain={}, account already exists (got account not default)", block.hash, block.header.chain_key);
                            return Err(Box::new(BlockValidationErrors::AccountExists));
                        }
                    }
                    Err(e) => {
                        if e != 0 {
                            // 0 = account file not found
                            error!(
                                "Failed to get account {} while checking if exists, error code={}",
                                block.header.chain_key, e
                            );
                            return Err(Box::new(BlockValidationErrors::FailedToGetAccount(e)));
                        }
                    }
                };
                // now check if the block is a send block (as height == 0) and the send_block field is None
                if block.block_type != BlockType::Send || !block.send_block.is_none() {
                    return Err(Box::new(BlockValidationErrors::GenesisNotSendBlock));
                }
                // because this is a dynamic genesis block it cannot have any transactions in, check that
                if block.txns.len() != 0 {
                    return Err(Box::new(BlockValidationErrors::TransactionCountNotZero));
                }
                // now finally as this genesis block is dynamic we need to check the signature
                if block.valid_signature() {
                    debug!(
                        "Signature={} on block with hash={} (signer={}) valid",
                        block.signature, block.hash, block.header.chain_key
                    );
                    return Ok(());
                } else {
                    error!(
                        "Signature={} on block with hash={} (signer={}) invalid",
                        block.signature, block.hash, block.header.chain_key
                    );
                    return Err(Box::new(BlockValidationErrors::BadSignature));
                }
            } else {
                // Not a genesis block
                match get_account(&block.header.chain_key) {
                    Ok(acc) => {
                        if acc == Account::default() {
                            debug!("Validating block with hash={} for chain={}, account does not exist (got account default)", block.hash, block.header.chain_key);
                            return Err(Box::new(BlockValidationErrors::AccountDoesNotExist));
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to get account {} while checking if exists, error code={}",
                            block.header.chain_key, e
                        );
                        return Err(Box::new(BlockValidationErrors::FailedToGetAccount(e)));
                    }
                };
                // get previous block
                let got_block = get_block(&block.header.chain_key, block.header.height - 1);
                if got_block == Block::default() {
                    error!("Cannot find block at height={} for chain={} with hash={} (while validating block with hash={})", block.header.height, block.header.chain_key, block.header.prev_hash, block.hash);
                    return Err(Box::new(BlockValidationErrors::PreviousBlockDoesNotExist));
                } else if got_block.hash != block.header.prev_hash {
                    error!(
                        "Previous block hash mismatch, expected={}, got={}",
                        block.header.prev_hash, got_block.hash
                    );
                    return Err(Box::new(BlockValidationErrors::InvalidPreviousBlockhash));
                }
                // else: the previous block exists and has the correct hash
                // check timestamp of block
                if block.header.timestamp < got_block.header.timestamp {
                    error!("Block with hash={} older than parent block with hash={}, block_timestamp={}, parent_timestamp={}", block.hash, got_block.hash, block.header.timestamp, got_block.header.timestamp);
                } else if block.header.timestamp - (config.transaction_timestamp_max_offset as u64)
                    > (SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_millis() as u64)
                {
                    error!(
                "Block with hash={} is too far in the future, transaction_timestamp_max_offset={}, block_timestamp={}, delta_timestamp={}, our_time={}", 
                block.hash,
                config.transaction_timestamp_max_offset,
                block.header.timestamp, block.header.timestamp - (config.transaction_timestamp_max_offset as u64),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis()
            );
                    return Err(Box::new(BlockValidationErrors::BlockTooFarInTheFuture));
                }
                //check the block has at most 10 transactions in it
                if block.txns.len() > 10 {
                    return Err(Box::new(BlockValidationErrors::TooManyTxn));
                } else if std::mem::size_of_val(&block) > 2048000 {
                    // check the block is no larger than 2mb
                    return Err(Box::new(BlockValidationErrors::BlockTooLarge));
                }
                if block.block_type == BlockType::Send {
                    // check if the block has a valid signature
                    if !block.valid_signature() {
                        return Err(Box::new(BlockValidationErrors::BadSignature));
                    }
                    // for every transaction in the block...
                    for txn in &block.txns {
                        // check if the txn is valid
                        if let Err(txn_validation_error) = txn.valid() {
                            error!(
                                "Validating transaction {} in block {} gave error {:?}",
                                txn.hash, block.hash, txn_validation_error
                            );
                            return Err(Box::new(BlockValidationErrors::InvalidTransaction(
                                txn_validation_error,
                            )));
                            // check the sender of the txn is the creator of this block
                        } else if txn.sender_key != block.header.chain_key {
                            error!("Transaction {} in block {} has sender key {} but block has a sender/chain key of {}", txn.hash, block.hash, txn.receive_key, block.header.chain_key);
                            return Err(Box::new(BlockValidationErrors::TransactionFromWrongChain));
                        }
                    }
                } else {
                    if let Some(send_block_hash) = block.send_block {
                        // get the corosponding send block for this recieve block
                        let got_send_block = get_block_from_raw(send_block_hash);
                        // If the block is default it is not found
                        if got_send_block == Block::default() {
                            error!("Cannot find send block with hash");
                            return Err(Box::new(BlockValidationErrors::SendBlockDoesNotExist));
                        } else if got_send_block.block_type != BlockType::Send {
                            // check if the claimed send block is really a send block
                            error!("Block with hash={} claims to be recieve block of {}, but it is a recieve block", block.hash, got_send_block.hash);
                            return Err(Box::new(BlockValidationErrors::SendBlockWrongType));
                        }
                        // for every transaction in the block...
                        for txn in &block.txns {
                            if !got_send_block.txns.contains(txn) {
                                // check if the transaction is in the send block for this block
                                error!(
                            "Transaction {} not found in send block {} (recieve block {} invalid)",
                            txn.hash, got_send_block.hash, block.hash
                        );
                                return Err(Box::new(
                                    BlockValidationErrors::TransactionsNotInSendBlock,
                                ));
                            } else if txn.receive_key != block.header.chain_key {
                                // check the recieve key of the transaction is the creator of this block (block.header.chain_key)
                                error!("Transaction {} in block {} has recieve key {} but block has a sender/chain key of {}", txn.hash, block.hash, txn.receive_key, block.header.chain_key);
                                return Err(Box::new(
                                    BlockValidationErrors::TransactionFromWrongChain,
                                ));
                            }
                        }
                    } else {
                        // All recieve blocks should have the send_block field set to Some() value
                        return Err(Box::new(BlockValidationErrors::SendBlockEmpty));
                    }
                }
            }
        }
        // all checks complete, this block must be valid
        debug!(
            "Block {} valid, took {} ms",
            block.hash,
            SystemTime::now()
                .duration_since(start_time)
                .expect("time went backwars ono")
                .as_millis()
        );
        Ok(())
    }

    fn get(hash: String) -> Result<Box<Self>, Box<dyn std::error::Error>> {
        let got_block = get_block_from_raw(hash);
        if got_block.is_default() {
            return Err("Block not found".into());
        } else {
            return Ok(Box::new(got_block)); // put block onto the heap and return a smart pointer (box)
        }
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        save_block(self.clone())
    }

    fn enact(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self.block_type {
            BlockType::Recieve => {
                enact_recieve(self.clone())?;
            }
            BlockType::Send => {
                enact_send(self.clone())?;
            }
        }
        Ok(())
    }
}

impl Block {
    pub fn is_default(&self) -> bool {
        self == &Block::default()
    }

    pub fn from_compressed(encoded: String) -> Result<Block, Box<dyn std::error::Error>> {
        let mut ret = Block::default();
        ret.decode_compressed(encoded)?;
        Ok(ret)
    }

    /// Sets the hash of a block
    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }

    /// Returns the hash of a block
    pub fn hash_return(&self) -> String {
        self.hash_item()
    }

    pub fn recievers(&self) -> Vec<String> {
        let mut to_return = vec![];
        for txn in &self.txns {
            to_return.push(txn.receive_key.clone());
        }
        to_return
    }

    /// Signs a block and sets the signature field on it.
    /// Returns a Result enum
    pub fn sign(&mut self, private_key: &str) -> std::result::Result<(), ring::error::KeyRejected> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key).into_vec().unwrap().as_ref(),
        )?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = bs58::encode(key_pair.sign(msg)).into_string();
        Ok(())
    }

    /// Returns true if signature on block is valid
    pub fn valid_signature(&self) -> bool {
        let msg: &[u8] = self.hash.as_bytes();
        if self.header.chain_key != "0" {
            // not a consensus block
            let peer_public_key = signature::UnparsedPublicKey::new(
                &signature::ED25519,
                bs58::decode(&self.header.chain_key)
                    .into_vec()
                    .unwrap_or_else(|e| {
                        error!(
                            "Failed to decode public key from bs58 {}, gave error {}",
                            self.header.chain_key, e
                        );
                        return vec![0, 1, 0];
                    }),
            );
            let mut res: bool = true;
            peer_public_key
                .verify(
                    msg,
                    bs58::decode(&self.signature)
                        .into_vec()
                        .unwrap_or_else(|e| {
                            error!(
                                "failed to decode signature from bs58 {}, gave error {}",
                                self.signature, e
                            );
                            return vec![0, 1, 0];
                        })
                        .as_ref(),
                )
                .unwrap_or_else(|_e| {
                    res = false;
                });
            res
        } else {
            // a consensus block
            let curr_epoch = get_top_epoch().unwrap_or_default();
            let round_leader = curr_epoch.committees[0]
                .get_round_leader()
                .unwrap_or_default();
            let peer_public_key = signature::UnparsedPublicKey::new(
                &signature::ED25519,
                bs58::decode(round_leader.clone())
                    .into_vec()
                    .unwrap_or_else(|e| {
                        error!(
                            "Failed to decode round leader's public key from bs58 {}, gave error {}",
                            round_leader, e
                        );
                        return vec![0, 1, 0];
                    }),
            );
            let mut res: bool = true;
            peer_public_key
                .verify(
                    msg,
                    bs58::decode(&self.signature)
                        .into_vec()
                        .unwrap_or_else(|e| {
                            error!(
                                "failed to decode signature from bs58 {}, gave error {}",
                                self.signature, e
                            );
                            return vec![0, 1, 0];
                        })
                        .as_ref(),
                )
                .unwrap_or_else(|_e| {
                    res = false;
                });
            res
        }
    }

    pub fn is_other_block(&self, other_block: &Block) -> bool {
        self == other_block
    }

    /// Takes in a send block and creates and returns a recive block
    pub fn form_receive_block(
        &self,
        chain_key: Option<String>,
    ) -> Result<Block, Box<dyn std::error::Error>> {
        if self.block_type == BlockType::Recieve {
            return Err("Block is recive block already".into());
        }
        // else we can get on with forming the rec block for this block
        let mut blk_clone = self.clone();
        blk_clone.block_type = BlockType::Recieve;
        blk_clone.header.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        let mut chain_key_value: String = config().chain_key; // if we were not passed a chain_key, use our one
        if let Some(key) = chain_key {
            chain_key_value = key;
        }
        if self.header.chain_key != "0" {
            let mut txn_iter = 0;
            for txn in blk_clone.clone().txns {
                if txn.receive_key != chain_key_value {
                    blk_clone.txns.remove(txn_iter);
                }
                txn_iter += 1;
            }
        }
        if chain_key_value == self.header.chain_key {
            blk_clone.header.height += 1;
            blk_clone.send_block = Some(self.hash.to_owned());
            blk_clone.header.prev_hash = self.hash.clone();
            blk_clone.hash();
            Ok(blk_clone)
        } else {
            let top_block_hash = get_data(
                config().db_path
                    + &"/chains/".to_owned()
                    + &chain_key_value
                    + &"-chainindex".to_owned(),
                "topblockhash",
            );
            let our_height: u64;
            let our_height_ = get_data(
                config().db_path
                    + &"/chains/".to_owned()
                    + &chain_key_value
                    + &"-chainindex".to_owned(),
                &"blockcount".to_owned(),
            );
            if our_height_ == "-1" {
                our_height = 0
            } else {
                our_height = our_height_.parse()?;
            }
            trace!("our_height={}", our_height);
            blk_clone.header.chain_key = chain_key_value;
            blk_clone.header.height = our_height; // we DONT need to add 1 to the blockcount as it is the COUNT of blocks on a chain which starts on 1, and block height starts from 0, this means there is already a +1 delta between the two
            blk_clone.send_block = Some(self.hash.to_owned());
            blk_clone.header.prev_hash = top_block_hash;
            blk_clone.hash();
            Ok(blk_clone)
        }
    }
    pub fn new(txns: Vec<Transaction>, private_key: String, send_block: Option<String>) -> Block {
        let mut consensus = false;
        for txn in &txns {
            if txn.consensus_type() {
                consensus = true;
                break;
            }
        }
        let wallet = Wallet::from_private_key(private_key);
        if consensus {
            let mut header = Header {
                version_major: config().version_major,
                version_breaking: config().version_breaking,
                version_minor: config().version_minor,
                chain_key: "0".to_string(),
                prev_hash: get_data(
                    config().db_path + &"/chains/0-chainindex".to_owned(),
                    "topblockhash",
                ),
                height: get_data(
                    config().db_path + &"/chains/0-chainindex".to_owned(),
                    "blockcount",
                )
                .parse()
                .unwrap_or_default(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time went backwards")
                    .as_millis() as u64,
                network: config().network_id,
            };
            if header.prev_hash == "-1" {
                trace!("No top block hash for genesis block");
                header.prev_hash = String::from("00000000000")
            }
            let mut blk: Block;
            if send_block.is_some() {
                blk = Block {
                    header,
                    block_type: BlockType::Recieve,
                    send_block,
                    txns,
                    hash: String::from(""),
                    signature: String::from(""),
                };
            } else {
                blk = Block {
                    header,
                    block_type: BlockType::Send,
                    send_block: None,
                    txns,
                    hash: String::from(""),
                    signature: String::from(""),
                };
            }
            blk.hash();
            let _ = blk.sign(&wallet.private_key);
            return blk;
        } else {
            let header = Header {
                version_major: config().version_major,
                version_breaking: config().version_breaking,
                version_minor: config().version_minor,
                chain_key: wallet.public_key.clone(),
                prev_hash: get_data(
                    config().db_path
                        + &"/chains/".to_owned()
                        + &wallet.public_key
                        + &"-chainindex".to_owned(),
                    "topblockhash",
                ),
                height: get_data(
                    config().db_path
                        + &"/chains/".to_owned()
                        + &wallet.public_key
                        + &"-chainindex".to_owned(),
                    "blockcount",
                )
                .parse()
                .unwrap_or_default(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time went backwards")
                    .as_millis() as u64,
                network: config().network_id,
            };
            let mut blk: Block;
            if send_block.is_some() {
                blk = Block {
                    header,
                    block_type: BlockType::Recieve,
                    send_block,
                    txns,
                    hash: String::from(""),
                    signature: String::from(""),
                };
            } else {
                blk = Block {
                    header,
                    block_type: BlockType::Send,
                    send_block: None,
                    txns,
                    hash: String::from(""),
                    signature: String::from(""),
                };
            }
            blk.hash();
            let _ = blk.sign(&wallet.private_key);
            return blk;
        }
    }
}

/// enacts the relevant stuff for a send block (eg creating inv registry)
fn enact_send(block: Block) -> Result<(), Box<dyn std::error::Error>> {
    if get_data(
        config().db_path
            + &"/chains/".to_owned()
            + &block.header.chain_key
            + &"-chainindex".to_owned(),
        &block.header.height.to_string(),
    ) == "-1"
    {
        let global_block_count_string = get_data(
            config().db_path + &"/globalindex".to_owned(),
            "globalblockcount",
        );
        let global_block_count: u64;
        if global_block_count_string == "-1" {
            save_data(
                "1",
                &(config().db_path + &"/globalindex".to_owned()),
                "globalblockcount".to_string(),
            );
            global_block_count = 1;
        } else {
            if let Ok(global_block_count_int) = global_block_count_string.parse::<u64>() {
                save_data(
                    &(global_block_count_int + 1).to_string(),
                    &(config().db_path + &"/globalindex".to_owned()),
                    "globalblockcount".to_string(),
                );
                debug!(
                    "Incremented global block count: old={}, new={}",
                    global_block_count_int,
                    global_block_count_int + 1
                );
                global_block_count = global_block_count_int + 1;
            } else {
                error!("Failed to parse current globalblockcount, setting to 1");
                save_data(
                    "1",
                    &(config().db_path + &"/globalindex".to_owned()),
                    "globalblockcount".to_string(),
                );
                global_block_count = 1;
            }
        }
        if get_data(
            config().db_path + "/globalindex",
            &global_block_count.to_string(),
        ) != "-1"
        {
            error!(
                "Global invetory entry already present for height={}",
                global_block_count
            );
            panic!(
                "Global invetory entry already present for height={}",
                global_block_count
            );
        } else {
            save_data(
                &block.hash,
                &(config().db_path + &"/globalindex".to_owned()),
                global_block_count.to_string(),
            );
            debug!(
                "Inserted global inventory entry, global height={}, hash={}",
                global_block_count, block.hash
            );
            save_data(
                &block.hash,
                &(config().db_path + &"/globalindex".to_owned()),
                "globaltopblockhash".to_string(),
            );
            debug!("Updated global topblockhash");
        }
        debug!("block {} not in invs", block.hash);

        let hash = block.hash.clone();
        let chain_key_copy = block.header.chain_key.to_owned();
        std::thread::spawn(move || {
            update_chain_digest(
                &hash,
                config().db_path + &"/chaindigest".to_owned(),
                &chain_key_copy,
            );
            form_state_digest(config().db_path + &"/chaindigest".to_owned()).unwrap();
        });

        save_data(
            &block.hash,
            &(config().db_path
                + &"/chains/".to_owned()
                + &block.header.chain_key
                + &"-chainindex".to_owned()),
            "topblockhash".to_string(),
        );
        save_data(
            &(block.header.height + 1).to_string(),
            &(config().db_path
                + &"/chains/".to_owned()
                + &block.header.chain_key
                + &"-chainindex".to_owned()),
            "blockcount".to_owned(),
        );

        trace!("set top block hash for sender");

        let inv_sender_res = save_data(
            &block.hash,
            &(config().db_path + "/chains/" + &block.header.chain_key + "-chainindex"),
            block.header.height.to_string(),
        );

        trace!("Saved inv for sender: {}", block.header.chain_key);

        if inv_sender_res != 1 {
            return Err("failed to save sender inv".into());
        }

        for txn in block.txns {
            txn.update_nonce()?;
        }
        if block.header.height == 0 {
            if save_data(
                &"".to_owned(),
                &(config().db_path + "/chainlist"),
                block.header.chain_key.clone(),
            ) == 0
            {
                return Err("failed to add chain to chainslist".into());
            } else {
                let newacc = Account::new(block.header.chain_key.clone());

                if set_account(&newacc) != 1 {
                    return Err("failed to save new account".into());
                }
            }

            if avrio_database::get_data(
                config().db_path
                    + &"/chains/".to_owned()
                    + &block.header.chain_key
                    + &"-chainindex".to_owned(),
                &"txncount",
            ) == *"-1"
            {
                avrio_database::save_data(
                    &"0".to_string(),
                    &(config().db_path
                        + &"/chains/".to_owned()
                        + &block.header.chain_key
                        + &"-chainindex".to_owned()),
                    "txncount".to_string(),
                );
            }
        }
    }
    Ok(())
}

/// Enacts a recieve block. Updates all relavant dbs and files
/// You should not enact a send block (this will return an error).
/// In presharding networks (eg now) use enact_send then form_receive_block and enact the outputed recieve block
/// Make sure the send block is propegated BEFORE the recieve block (to reduce processing latency)
fn enact_recieve(block: Block) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if block.block_type != BlockType::Recieve {
        // we only enact recive blocks, ignore send blocks
        return Err("tried to enact a send block".into());
    }
    let global_block_count_string = get_data(
        config().db_path + &"/globalindex".to_owned(),
        "globalblockcount",
    );
    let global_block_count: u64;
    if global_block_count_string == "-1" {
        save_data(
            "1",
            &(config().db_path + &"/globalindex".to_owned()),
            "globalblockcount".to_string(),
        );
        global_block_count = 1;
    } else {
        if let Ok(global_block_count_int) = global_block_count_string.parse::<u64>() {
            save_data(
                &(global_block_count_int + 1).to_string(),
                &(config().db_path + &"/globalindex".to_owned()),
                "globalblockcount".to_string(),
            );
            debug!(
                "Incremented global block count: old={}, new={}",
                global_block_count_int,
                global_block_count_int + 1
            );
            global_block_count = global_block_count_int + 1;
        } else {
            error!("Failed to parse current globalblockcount, setting to 1");
            save_data(
                "1",
                &(config().db_path + &"/globalindex".to_owned()),
                "globalblockcount".to_string(),
            );
            global_block_count = 1;
        }
    }
    if get_data(
        config().db_path + "/globalindex",
        &global_block_count.to_string(),
    ) != "-1"
    {
        error!(
            "Global invetory entry already present for height={}",
            global_block_count
        );
        panic!(
            "Global invetory entry already present for height={}",
            global_block_count
        );
    } else {
        save_data(
            &block.hash,
            &(config().db_path + &"/globalindex".to_owned()),
            global_block_count.to_string(),
        );
        debug!(
            "Inserted global inventory entry, global height={}, hash={}",
            global_block_count, block.hash
        );
        save_data(
            &block.hash,
            &(config().db_path + &"/globalindex".to_owned()),
            "globaltopblockhash".to_string(),
        );
        debug!("Updated global topblockhash");
    }
    if get_data(
        config().db_path
            + &"/chains/".to_owned()
            + &block.header.chain_key
            + &"-chainindex".to_owned(),
        &block.header.height.to_string(),
    ) == "-1"
    {
        debug!("block not in invs");
        let hash = block.hash.clone();

        let chain_key_copy = block.header.chain_key.to_owned();
        std::thread::spawn(move || {
            update_chain_digest(
                &hash,
                config().db_path + &"/chaindigest".to_owned(),
                &chain_key_copy,
            );
            form_state_digest(config().db_path + &"/chaindigest".to_owned()).unwrap();
        });
        save_data(
            &block.hash,
            &(config().db_path
                + &"/chains/".to_owned()
                + &block.header.chain_key
                + &"-chainindex".to_owned()),
            "topblockhash".to_string(),
        );
        save_data(
            &(block.header.height + 1).to_string(),
            &(config().db_path
                + &"/chains/".to_owned()
                + &block.header.chain_key
                + &"-chainindex".to_owned()),
            "blockcount".to_string(),
        );
        trace!("set top block hash for sender");
        let inv_sender_res = save_data(
            &block.hash,
            &(config().db_path
                + &"/chains/".to_owned()
                + &block.header.chain_key
                + &"-chainindex".to_owned()),
            block.header.height.to_string(),
        );
        trace!("Saved inv for sender: {}", block.header.chain_key);
        if inv_sender_res != 1 {
            return Err("failed to save sender inv".into());
        }
        if block.header.height == 0 {
            if save_data(
                &"".to_owned(),
                &(config().db_path + "/chainlist"),
                block.header.chain_key.clone(),
            ) == 0
            {
                return Err("failed to add chain to chainslist".into());
            } else {
                let newacc = Account::new(block.header.chain_key.clone());
                if set_account(&newacc) != 1 {
                    return Err("failed to save new account".into());
                }
            }
            if avrio_database::get_data(
                config().db_path
                    + &"/chains/".to_owned()
                    + &block.header.chain_key
                    + &"-chainindex".to_owned(),
                &"txncount",
            ) == *"-1"
            {
                avrio_database::save_data(
                    &"0".to_string(),
                    &(config().db_path
                        + &"/chains/".to_owned()
                        + &block.header.chain_key
                        + &"-chainindex".to_owned()),
                    "txncount".to_owned(),
                );
            }
        }
        for txn in block.txns {
            trace!("enacting txn with hash: {}", txn.hash);
            txn.enact()?;
            trace!("Enacted txn. Saving txn to txindex db (db_name  = transactions)");
            if save_data(
                &block.hash,
                &(config().db_path + &"/transactions".to_owned()),
                txn.hash.to_owned(),
            ) != 1
            {
                return Err("failed to save txn in transactions db".into());
            }
            trace!("Saving invs");
            if txn.sender_key != txn.receive_key && txn.sender_key != block.header.chain_key {
                let inv_receiver_res = save_data(
                    &block.hash,
                    &(config().db_path
                        + &"/chains/".to_owned()
                        + &txn.receive_key
                        + &"-chainindex".to_owned()),
                    block.header.height.to_string(),
                );
                if inv_receiver_res != 1 {
                    return Err("failed to save reciver inv".into());
                }
                let curr_block_count: String = get_data(
                    config().db_path
                        + &"/chains/".to_owned()
                        + &txn.receive_key
                        + &"-chainindex".to_owned(),
                    "blockcount",
                );
                if curr_block_count == "-1" {
                    save_data(
                        &"0".to_owned(),
                        &(config().db_path
                            + &"/chains/".to_owned()
                            + &txn.receive_key
                            + &"-chainindex".to_owned()),
                        "blockcount".to_owned(),
                    );
                } else {
                    let curr_block_count_val: u64 = curr_block_count.parse().unwrap_or_default();
                    save_data(
                        &(curr_block_count_val + 1).to_string(),
                        &(config().db_path
                            + &"/chains/".to_owned()
                            + &txn.receive_key
                            + &"-chainindex".to_owned()),
                        "blockcount".to_owned(),
                    );
                }

                save_data(
                    &block.hash,
                    &(config().db_path
                        + &"/chains/".to_owned()
                        + &txn.receive_key
                        + &"-chainindex".to_owned()),
                    "topblockhash".to_owned(),
                );
                trace!("set top block hash for reciever");
            }
        }
    } else {
        debug!("Block in invs, ignoring");
    }
    Ok(())
}
pub fn from_compact(encoded: String) -> Result<Block, Box<dyn std::error::Error>> {
    let mut ret = Block::default();
    ret.decode_compressed(encoded)?;
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use crate::block::*;
    use avrio_config::*;
    use avrio_crypto::Hashable;
    use rand::Rng;
    use ring::rand as randc;
    use ring::signature::*;
    extern crate simple_logger;
    pub struct Item {
        pub cont: String,
    }
    impl Hashable for Item {
        fn bytes(&self) -> Vec<u8> {
            self.cont.as_bytes().to_vec()
        }
    }
    pub fn hash(subject: String) -> String {
        return Item { cont: subject }.hash_item();
    }
    #[test]
    fn test_block() {
        simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Info)
            .init()
            .unwrap();
        let mut i_t: u64 = 0;
        let mut rng = rand::thread_rng();
        let rngc = randc::SystemRandom::new();
        for _i in 0..=1000 {
            let mut block = Block::default();
            block.header.network = config().network_id;

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
                    nonce: rng.gen(),
                    timestamp: 0,
                    unlock_time: 0,
                };
                txn.sender_key = bs58::encode(peer_public_key_bytes).into_string();
                txn.hash();
                block.txns.push(txn);
                i_t += 1;
            }
            block.hash();
            let msg: &[u8] = block.hash.as_bytes();
            block.signature = bs58::encode(key_pair.sign(msg)).into_string();
            block.header.chain_key = bs58::encode(peer_public_key_bytes).into_string();
            println!("constructed block: {}, checking signature...", block.hash);
            assert_eq!(block.valid_signature(), true);
            let block_clone = block.clone();
            println!("saving block");
            let conf = Config::default();
            let _ = conf.create();
            println!("Block: {:?}", block);
            save_block(block).unwrap();
            println!("reading block...");
            let block_read = get_block_from_raw(block_clone.hash.clone());
            println!("read block: {}", block_read.hash);
            assert_eq!(block_read, block_clone);
        }
    }
}
