extern crate avrio_config;
extern crate avrio_core;
extern crate avrio_database;
use crate::genesis::{genesisBlockErrors, getGenesisBlock};
use avrio_config::config;
use avrio_core::{
    account::{getAccount, setAccount, Account},
    transaction::*,
};
use avrio_database::*;
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate log;

extern crate bs58;

use ring::{
    digest::SHA256,
    rand as randc,
    signature::{self, KeyPair},
};
extern crate rand;

use avrio_crypto::Hashable;

use std::fs::File;
use std::io::prelude::*;

#[derive(Debug)]
pub enum blockValidationErrors {
    invalidBlockhash,
    badSignature,
    indexMissmatch,
    invalidPreviousBlockhash,
    invalidTransaction(TransactionValidationErrors),
    genesisBlockMissmatch,
    failedToGetGenesisBlock,
    blockExists,
    tooLittleSignatures,
    badNodeSignature,
    timestampInvalid,
    networkMissmatch,
    other,
}
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub txns: Vec<Transaction>,
    pub hash: String,
    pub signature: String,
    pub confimed: bool,
    pub node_signatures: Vec<BlockSignature>, // a block must be signed by at least 2/3*c nodes to be valid (ensures at least one honest node has signed it)
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct BlockSignature {
    /// The signature of the vote
    pub hash: String,
    /// The timestamp at which the signature was created
    pub timestamp: u64,
    /// The hash of the block this signature is about        
    pub block_hash: String,
    /// The public key of the node which created this vote
    pub signer_public_key: String,
    /// The hash of the sig signed by the voter        
    pub signature: String,
    /// A nonce to prevent sig replay attacks
    pub nonce: u64,
}

impl Hashable for BlockSignature {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        write!(bytes, "{}", self.timestamp).unwrap();
        bytes.extend(self.block_hash.as_bytes());
        bytes.extend(self.signer_public_key.as_bytes());
        write!(bytes, "{}", self.nonce).unwrap();
        bytes
    }
}

impl BlockSignature {
    pub fn enact(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // we are presuming the vote is valid - if it is not this is going to mess stuff up!
        if saveData(
            self.nonce.to_string(),
            config().db_path + "/fn-certificates",
            self.signer_public_key.clone(),
        ) != 1
        {
            return Err("failed to update nonce".into());
        } else {
            return Ok(());
        }
    }
    pub fn valid(&self) -> bool {
        if &getData(
            config().db_path + "/fn-certificates",
            &self.signer_public_key,
        ) == "-1"
        {
            return false;
        } else if self.hash != self.hash_return() {
            return false;
        } else if getData(
            config().db_path
                + "/chains/"
                + &self.signer_public_key
                + "-chainsindex",
            "sigcount",
        ) != self.nonce.to_string()
        {
            return false;
        } else if self.timestamp - (config().transactionTimestampMaxOffset as u64)
            < (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64)
            || self.timestamp + (config().transactionTimestampMaxOffset as u64)
                < (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64)
        {
            return false;
        } else if !self.signature_valid() {
            return false;
        } else {
            return true;
        }
    }
    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }
    pub fn hash_return(&self) -> String {
        return self.hash_item();
    }
    pub fn sign(
        &mut self,
        private_key: String,
    ) -> std::result::Result<(), ring::error::KeyRejected> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key)
                .into_vec()
                .unwrap_or_default()
                .as_ref(),
        )?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = bs58::encode(key_pair.sign(msg)).into_string();
        return Ok(());
    }
    pub fn bytes_all(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.hash.as_bytes());
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes.extend(self.block_hash.as_bytes());
        bytes.extend(self.signer_public_key.as_bytes());
        bytes.extend(self.nonce.to_string().as_bytes());
        bytes.extend(self.signature.as_bytes());
        bytes
    }
    pub fn signature_valid(&self) -> bool {
        let msg: &[u8] = self.hash.as_bytes();
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            bs58::decode(&self.signer_public_key)
                .into_vec()
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to decode public key from bs58 {}, gave error {}",
                        self.signer_public_key, e
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
        return res;
    }
}

pub fn generate_merkle_root_all() -> std::result::Result<String, Box<dyn std::error::Error>> {
    let mut roots: Vec<String> = vec![];
    if let Ok(db) = openDb(config().db_path + "/chainlist") {
        let mut iter = db.raw_iterator();
        iter.seek_to_first();
        while iter.valid() {
            if let Some(chain) = iter.key() {
                if let Ok(chain_string) = String::from_utf8(chain.to_vec()) {
                    if let Ok(blkdb) = openDb(
                        config().db_path
                            + "/chains/"
                            + &chain_string
                            + "-invs"
                    ) {
                        let mut blkiter = blkdb.raw_iterator();
                        blkiter.seek_to_first();
                        while blkiter.valid() {
                            if let Some(blk) = iter.value() {
                                update_chain_digest(String::from_utf8(blk.to_vec())?);
                            }
                            blkiter.next();
                        }
                    }
                }
            }
            iter.next();
        }
    }
    return Ok(getData(
        config().db_path + &"/chainsdigest",
        "master",
    ));
}

pub fn update_chain_digest(new_blk_hash: String) -> String {
    let curr = getData(
        config().db_path + &"/chainsdigest",
        "master",
    );
    let root: String;
    if &curr == "-1" {
        root = new_blk_hash;
    } else {
        root = avrio_crypto::raw_lyra(&(curr + &new_blk_hash));
    }
    let _ = saveData(
        root.clone(),
        config().db_path + "/chainsdigest",
        "master".to_owned(),
    );
    return root;
}

pub fn getBlock(chainkey: &String, height: u64) -> Block {
    // returns the block when you know the chain and the height
    let hash = getData(
        config().db_path + "/chains/" + chainkey + "-invs",
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
    if let Ok(mut file) = File::open(config().db_path + &"/blocks/blk-".to_owned() + &hash + ".dat")
    {
        let mut contents = String::new();
        file.read_to_string(&mut contents);
        return serde_json::from_str(&contents).unwrap_or_default();
    } else {
        return Block::default();
    }
}

pub fn saveBlock(block: Block) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // formats the block into a .dat file and saves it under block-hash.dat
    let encoded: Vec<u8> = serde_json::to_string(&block)?.as_bytes().to_vec();
    let mut file =
        File::create(config().db_path + "/blocks/blk-" + &block.hash + ".dat")?;
    file.write_all(&encoded)?;
    let inv_sender_res = saveData(
        block.hash.clone(),
        config().db_path + "/chains/" + &block.header.chain_key + "-invs",
        block.header.height.to_string(),
    );
    for txn in block.txns {
        let inv_receiver_res = saveData(
            block.hash.clone(),
            config().db_path + "/chains/" + &txn.receive_key + "-invs",
            block.header.height.to_string(),
        );
        if inv_receiver_res != 1 {
            return Err("failed to save reciver inv".into());
        }
        if saveData(
            block.hash.clone(),
            config().db_path + "/transactions",
            txn.hash,
        ) != 1
        {
            return Err("failed to add transaction to transaction db".into());
        }
    }
    if inv_sender_res != 1 {
        return Err("failed to save sender inv".into());
    }
    return Ok(());
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
    pub fn hash(&mut self) -> String {
        return self.hash_item();
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
impl Block {
    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }
    pub fn hash_return(&self) -> String {
        return self.hash_item();
    }
    pub fn sign(
        &mut self,
        private_key: &String,
    ) -> std::result::Result<(), ring::error::KeyRejected> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key).into_vec().unwrap().as_ref(),
        )?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = bs58::encode(key_pair.sign(msg)).into_string();
        return Ok(());
    }
    pub fn validSignature(&self) -> bool {
        let msg: &[u8] = self.hash.as_bytes();
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
        return res;
    }
    pub fn isOtherBlock(&self, OtherBlock: &Block) -> bool {
        self == OtherBlock
    }
}
// TODO: finish enact block
pub fn enact_block(block: Block) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let block_count = getData(config().db_path + "/chaindigest", "blockcount");
    if block_count == "-1".to_owned() {
        saveData("1".to_owned(), config().db_path + "/chaindigest", "blockcount".to_owned());
        trace!("set block count, prev: -1 (not set), new: 1");
    } else {
        let mut bc: u64 = block_count.parse().unwrap_or_default();
        bc += 1;
        saveData(bc.to_string(), config().db_path + "/chaindigest", "blockcount".to_owned());
        trace!("Updated non-zero block count, new count: {}", bc);
    }
    if block.header.height == 0 {
        if saveData(
            "".to_owned(),
            config().db_path + "/chainlist",
            block.header.chain_key.clone(),
        ) == 0
        {
            return Err("failed to add chain to chainslist".into());
        } else {
            let newacc = Account::new(block.header.chain_key.clone());
            if setAccount(&newacc) != 1 {
                return Err("failed to save new account".into());
            }
        }
        if avrio_database::getData(
            config().db_path
                + &"/chains/".to_owned()
                + &block.header.chain_key
                + &"-chainindex".to_owned(),
            &"txncount".to_owned(),
        ) == "-1".to_owned()
        {
            avrio_database::saveData(
                "0".to_string(),
                config().db_path
                    + &"/chains/".to_owned()
                    + &block.header.chain_key
                    + &"-chainindex".to_owned(),
                "txncount".to_owned(),
            );
        }
    }

    let bh = block.hash.clone();
    std::thread::spawn(move || {
        update_chain_digest(bh);
    });
    for txn in block.txns {
        txn.enact()?;
        if saveData(
            block.hash.clone(),
            config().db_path + &"/transactions".to_owned(),
            txn.hash.clone(),
        ) != 1
        {
            return Err("failed to save txn in transactions db".into());
        }
        if getData(config().db_path + &"/transactions".to_owned(), &txn.hash) != block.hash {
            error!("Cant save txn to db :(");
        }
    }

    return Ok(());
}
pub fn check_block(blk: Block) -> std::result::Result<(), blockValidationErrors> {
    if blk.header.network != config().network_id {
        return Err(blockValidationErrors::networkMissmatch);
    } else if blk.hash != blk.hash_return() {
        return Err(blockValidationErrors::invalidBlockhash);
    }
    if getData(config().db_path + "/checkpoints", &blk.hash) != "-1".to_owned() {
        // we have this block in our checkpoints db and we know the hash is correct and therefore the block is valid
        return Ok(());
    }
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
        if blk != genesis && genesis != Block::default() {
            return Err(blockValidationErrors::genesisBlockMissmatch);
        } else {
            if is_in_db == true {
                // if it is in the db it is guarenteed to be valid, we do not need to validate the block
                return Ok(());
            } else {
                // if it isn't it needs to be validated like any other block
                if &blk.header.prev_hash != "00000000000" {
                    return Err(blockValidationErrors::invalidPreviousBlockhash);
                } else if let Ok(_) = getAccount(&blk.header.chain_key) {
                    // this account allready exists, you can't have two genesis blocks
                    return Err(blockValidationErrors::genesisBlockMissmatch);
                } else if !blk.validSignature() {
                    return Err(blockValidationErrors::badSignature);
                } else if getBlockFromRaw(blk.hash.clone()) != Block::default() {
                    return Err(blockValidationErrors::blockExists);
                } else if blk.header.height != 0
                    && blk.header.timestamp - (config().transactionTimestampMaxOffset as u64)
                        > (SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Time went backwards")
                            .as_millis() as u64)
                {
                    return Err(blockValidationErrors::timestampInvalid);
                } else if blk.header.height != 0
                    && getBlockFromRaw(blk.header.prev_hash).header.timestamp > blk.header.timestamp
                {
                    return Err(blockValidationErrors::timestampInvalid);
                }
                return Ok(());
            }
        }
    } else {
        // not genesis block
        if blk.confimed == true
            && blk.node_signatures.len() < (2 / 3 * config().commitee_size) as usize
        {
            return Err(blockValidationErrors::tooLittleSignatures);
        } else {
            for signature in blk.clone().node_signatures {
                if !signature.valid() {
                    return Err(blockValidationErrors::badNodeSignature);
                }
            }
        }
        if blk.header.prev_hash != getBlock(&blk.header.chain_key, &blk.header.height - 1).hash {
            return Err(blockValidationErrors::invalidPreviousBlockhash);
        } else if let Err(_) = getAccount(&blk.header.chain_key) {
            // this account doesn't exist, the first block must be a genesis block
            if blk.header.height != 0 {
                return Err(blockValidationErrors::other);
            }
        } else if !blk.validSignature() {
            return Err(blockValidationErrors::badSignature);
        } else if blk.header.timestamp - (config().transactionTimestampMaxOffset as u64)
            > (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64)
        {
            return Err(blockValidationErrors::timestampInvalid);
        } else if blk.header.height != 0
            && getBlockFromRaw(blk.header.prev_hash).header.timestamp > blk.header.timestamp
        {
            return Err(blockValidationErrors::timestampInvalid);
        }
        for txn in blk.txns {
            if let Err(e) = txn.valid() {
                return Err(blockValidationErrors::invalidTransaction(e));
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
    use crate::rand::Rng;
    use crate::*;
    use avrio_config::*;
    extern crate simple_logger;
    pub struct item {
        pub cont: String,
    }
    impl Hashable for item {
        fn bytes(&self) -> Vec<u8> {
            self.cont.as_bytes().to_vec()
        }
    }
    pub fn hash(subject: String) -> String {
        return item { cont: subject }.hash_item();
    }
    #[test]
    fn test_block() {
        simple_logger::init_with_level(log::Level::Info).unwrap();
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
                    gas: rng.gen::<u16>() as u64,
                    nonce: rng.gen(),
                    signature: String::from(""),
                    timestamp: 0,
                    unlock_time: 0,
                };
                txn.sender_key = bs58::encode(peer_public_key_bytes).into_string();
                txn.hash();
                // Sign the hash
                let msg: &[u8] = txn.hash.as_bytes();
                txn.signature = bs58::encode(key_pair.sign(msg)).into_string();
                let _peer_public_key =
                    signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
                //peer_public_key.verify(msg, bs58::decode(&txn.signature.to_owned()).unwrap().as_ref()).unwrap();
                block.txns.push(txn);
                i_t += 1;
            }
            block.hash();
            let msg: &[u8] = block.hash.as_bytes();
            block.signature = bs58::encode(key_pair.sign(msg)).into_string();
            block.header.chain_key = bs58::encode(peer_public_key_bytes).into_string();
            println!("constructed block: {}, checking signature...", block.hash);
            assert_eq!(block.validSignature(), true);
            let block_clone = block.clone();
            println!("saving block");
            let conf = Config::default();
            let _ = conf.create();
            println!("Block: {:?}", block);
            saveBlock(block).unwrap();
            println!("reading block...");
            let block_read = getBlockFromRaw(block_clone.hash.clone());
            println!("read block: {}", block_read.hash);
            assert_eq!(block_read, block_clone);
        }
    }
}
