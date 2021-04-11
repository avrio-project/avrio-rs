extern crate avrio_config;
extern crate avrio_core;
extern crate avrio_database;
use crate::genesis::{get_genesis_block, GenesisBlockErrors};
use avrio_config::config;
use avrio_core::{
    account::{get_account, set_account, Account},
    transaction::*,
};
use avrio_database::*;
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate log;

extern crate bs58;

use ring::signature;
extern crate rand;

use avrio_crypto::Hashable;

use std::fs::File;
use std::io::prelude::*;

#[derive(Debug)]
pub enum BlockValidationErrors {
    TooManyTxn,
    VersionTooNew,
    InvalidBlockhash, // TODO: Rename to blockhash missmatch
    BlockTooLarge,
    BadSignature,
    IndexMissmatch,
    InvalidPreviousBlockhash,
    BlockCollision,
    InvalidTransaction(TransactionValidationErrors),
    AccountExists,
    FailedToGetAccount(u8),
    TransactionCountNotZero,
    GenesisBlockMissmatch,
    FailedToGetGenesisBlock,
    GenesisNotSendBlock,
    BlockExists,
    TooLittleSignatures,
    BadNodeSignature,
    TimestampInvalid,
    NetworkMissmatch,
    AccountDoesNotExist,
    PreviousBlockDoesNotExist,
    SendBlockDoesNotExist,
    BlockTooFarInTheFuture,
    SendBlockNotFound,
    SendBlockWrongType,
    TransactionsNotInSendBlock,
    TransactionFromWrongChain,
    SendBlockEmpty,
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
    pub confimed: bool,
    pub node_signatures: Vec<BlockSignature>, // a block must be signed by at least 2/3 of the commitee's verifyer nodes to be valid (ensures at least one honest node has signed it)
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

impl Default for BlockType {
    fn default() -> Self {
        BlockType::Send
    }
}

impl BlockSignature {
    pub fn enact(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // we are presuming the vote is valid - if it is not this is going to mess stuff up!
        if save_data(
            &self.nonce.to_string(),
            &(config().db_path + "/fn-certificates"),
            self.signer_public_key.clone(),
        ) != 1
        {
            Err("failed to update nonce".into())
        } else {
            Ok(())
        }
    }

    pub fn valid(&self) -> bool {
        // check the fullnode who signed this block is registered. TODO (for sharding v1): move to using a vector of tuples(publickey, signature) and check each fullnode fully (was part of that epoch, was a validator node for the commitee handling the shard, etc)
        !(&get_data(
            config().db_path + "/fn-certificates",
            &self.signer_public_key,
        ) == "-1"
            || self.hash != self.hash_return()
            || get_data(
                config().db_path + "/chains/" + &self.signer_public_key + "-chainindex",
                "sigcount",
            ) != self.nonce.to_string()
            || self.timestamp - (config().transaction_timestamp_max_offset as u64)
                < (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64)
            || self.timestamp + (config().transaction_timestamp_max_offset as u64)
                < (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64)
            || !self.signature_valid())
    }

    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }

    pub fn hash_return(&self) -> String {
        self.hash_item()
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
        Ok(())
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
        res
    }
}

pub fn update_chain_digest(new_blk_hash: &str, cd_db: String, chain: &str) -> String {
    trace!(target: "blockchain::chain_digest","Updating chain digest for chain={}, hash={}", chain, new_blk_hash);
    let curr = get_data(cd_db.to_owned(), chain);
    let root: String;
    if &curr == "-1" {
        trace!(target: "blockchain::chain_digest","chain digest not set");
        root = avrio_crypto::raw_lyra(new_blk_hash);
    } else {
        trace!(target: "blockchain::chain_digest","Updating set chain digest. Curr: {}", curr);
        root = avrio_crypto::raw_lyra(&(curr + new_blk_hash));
    }
    let _ = save_data(&root, &cd_db, chain.to_owned());
    trace!(target: "blockchain::chain_digest","Chain digest for chain={} updated to {}", chain, root);
    root
}

/// takes a DB object of the chains digest (chaindigest) db and a vector of chain_keys (as strings) and calculates the chain digest for each chain.
/// It then sets the value of chain digest (for each chain) in the db, and returns it in the vector of strings
pub fn form_chain_digest(
    cd_db: String,
    chains: Vec<String>,
) -> std::result::Result<Vec<String>, Box<dyn std::error::Error>> {
    // TODO: do we need to return a Result<vec, err>? Cant we just return vec as there is no unwrapping needing to be done that could be replaced with the ? operator (and hence no chance of errors)?
    let mut output: Vec<String> = vec![];
    for chain in chains {
        trace!("Chain digest: starting chain={}", chain);
        // get the genesis block
        let genesis = get_block(&chain, 0);
        // hash the hash
        let mut temp_leaf = avrio_crypto::raw_lyra(&avrio_crypto::raw_lyra(&genesis.hash));
        // set curr_height to 1
        let mut curr_height: u64 = 1;
        loop {
            // loop through, increasing curr_height by one each time. Get block with height curr_height and hash its hash with the previous temp_leaf node. Once the block we read at curr_height
            // is Default (eg there is no block at that height), break from the loop
            let temp_block = get_block(&chain, curr_height);
            if temp_block.is_default() {
                break; // we have exceeded the last block, break/return from loop
            } else {
                temp_leaf = avrio_crypto::raw_lyra(&format!("{}{}", temp_leaf, temp_block.hash));
                trace!(
                    "Chain digest: chain={}, block={}, height={}, new temp_leaf={}",
                    chain,
                    temp_block.hash,
                    curr_height,
                    &temp_leaf
                );
                curr_height += 1;
            }
        }
        // we are finished, update the chain_digest on disk and add it to the output vector
        avrio_database::save_data(&temp_leaf, &cd_db, chain.to_owned());
        output.push(temp_leaf);
        trace!(
            "Chain digest: Finished chain={}, new output={:?}",
            chain,
            output
        );
    }
    // return the output vector
    Ok(output)
}

/// Calculates the 'overall' digest of the DAG.
/// Pass it a database object of the chaindigest database. This database should contain all the chains chain digests (with the key being the publickey)
/// as well as 'master' (as a key) being the state digest.
/// Run form_chain_digest(chain) (with chain being the publickey of the chain you want, or * for every chain) first which will form a chain digest
/// from scratch (or update_chain_digest(chain, new_block_hash, cd_db)). This function will return the new state digest as a string as well as update it in the database
///
pub fn form_state_digest(cd_db: String) -> std::result::Result<String, Box<dyn std::error::Error>> {
    debug!("Updating state digest");
    let start = std::time::Instant::now();
    let current_state_digest = get_data(cd_db.to_owned(), "master"); // get the current state digest, for refrence
    if &current_state_digest == "-1" {
        trace!("State digest not set");
    } else {
        trace!("Updating set state digest. Curr: {}", current_state_digest);
    }
    // we now recursivley loop through cd_db and add every value (other than master) to a vector
    // now we have every chain digest in a vector we sort it alphabeticly
    // now the vector of chain digests is sorted alphabeticly we recursivley hash them
    // like so: (TODO: use a merkle tree not a recursive hash chain)
    // leaf_one = hash(chain_digest_one + chain_digest_two)
    // leaf_two = hash(leaf_one + chain_digest_three)
    // leaf[n] = hash(leaf[n-1] + chain_digest[n+1])
    let mut _roots: Vec<(String, String)> = vec![]; // 0: chain_key, 1: chain_digest
                                                    //iter.seek_to_first();
    let _chains_list: Vec<String> = Vec::new();
    for (chain_key_string, chain_digest_string) in open_database(cd_db.to_owned())?.iter() {
        if chain_key_string != "master"
            && chain_key_string != "blockcount"
            && chain_key_string != "topblockhash"
        {
            _roots.push((chain_key_string.to_owned(), chain_digest_string.to_owned()));
        } else {
            log::trace!(
                "found {}:{} (key, value) in chaindigest database, ignoring",
                chain_key_string,
                chain_digest_string
            );
        }
    }
    let _rootsps = _roots.clone();
    _roots.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase())); // sort to aplabetical order (based on chain key)
    log::trace!(
        "Roots presort={:#?}, roots post sort={:#?}",
        _rootsps,
        _roots
    );
    drop(_rootsps);
    let mut temp_leaf: String;
    // create the first leaf
    if _roots.len() == 1 {
        temp_leaf = avrio_crypto::raw_lyra(&_roots[0].1.to_owned());
    } else if !_roots.is_empty() {
        temp_leaf = avrio_crypto::raw_lyra(&(_roots[0].1.to_owned() + &_roots[1].1)); // Hash the first two chain digests together to make the first leaf
        let cd_one = &_roots[0].1;
        let cd_two = &_roots[1].1;
        for (chain_string, digest_string) in _roots.clone() {
            // TODO: can we put _roots in a cow (std::borrow::Cow) to prevent cloning? (micro-optimisation)
            // check that digest_string is not the first two (which we already hashed)
            if &digest_string == cd_one || &digest_string == cd_two {
            } else {
                // hash digest_string with temp_leaf
                log::trace!(
                    "Chain digest: chain={}, chain_digest={}, current_tempory_leaf={}",
                    chain_string,
                    digest_string,
                    temp_leaf
                );
                temp_leaf = avrio_crypto::raw_lyra(&(digest_string + &temp_leaf));
            }
        }
        // we have gone through every digest and hashed them together, now we save to disk
    } else {
        temp_leaf = avrio_crypto::raw_lyra(&"".to_owned());
    }
    log::debug!(
        "Finished state digest calculation, old={}, new={}, time_to_complete={}",
        current_state_digest,
        temp_leaf,
        start.elapsed().as_millis()
    );
    avrio_database::save_data(&temp_leaf, &cd_db, "master".to_string());
    Ok(temp_leaf)
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
impl Block {
    pub fn is_default(&self) -> bool {
        self == &Block::default()
    }

    /// Sets the hash of a block
    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }

    /// Returns the hash of a block
    pub fn hash_return(&self) -> String {
        self.hash_item()
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
        let mut txn_iter = 0;
        for txn in blk_clone.clone().txns {
            txn_iter += 1;
            if txn.receive_key != chain_key_value {
                blk_clone.txns.remove(txn_iter);
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
}

/// enacts the relevant stuff for a send block (eg creating inv registry)
pub fn enact_send(block: Block) -> Result<(), Box<dyn std::error::Error>> {
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

// TODO: finish enact block
/// Enacts a recieve block. Updates all relavant dbs and files
/// You should not enact a send block (this will return an error).
/// In presharding networks (eg now) use enact_send then form_receive_block and enact the outputed recieve block
/// Make sure the send block is propegated BEFORE the recieve block (to reduce processing latency)
pub fn enact_block(block: Block) -> std::result::Result<(), Box<dyn std::error::Error>> {
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
            txn.enact(
                config().db_path
                    + &"/chains/".to_owned()
                    + &txn.sender_key
                    + &"-chainindex".to_owned(),
            )?;
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

pub fn benchmark_block_test(block: Block) -> std::result::Result<(), BlockValidationErrors> {
    info!("Benchmarking new block validation code");
    let start_new = SystemTime::now();
    let _ = check_block(block.clone())?;
    let new_time = SystemTime::now()
        .duration_since(start_new)
        .expect("")
        .as_millis();
    let end_new = SystemTime::now();
    let _ = check_block_old(block)?;
    info!(
        "New validation took: {} ms, Old validation took: {} ms",
        new_time,
        SystemTime::now()
            .duration_since(end_new)
            .expect("")
            .as_millis()
    );
    Ok(())
}

pub fn check_block(block: Block) -> std::result::Result<(), BlockValidationErrors> {
    let start_time = SystemTime::now();
    let config = config();
    // check if the block version is supported
    match format!(
        "{}{}",
        block.header.version_major, block.header.version_breaking
    )
    .parse::<u64>()
    {
        Ok(block_version) => {
            match format!("{}{}", config.version_major, config.version_breaking).parse::<u64>() {
                Ok(our_block_version) => {
                    if our_block_version < block_version {
                        return Err(BlockValidationErrors::VersionTooNew);
                    } // else: continue
                }
                Err(_) => return Err(BlockValidationErrors::Other),
            }
        }
        Err(_) => return Err(BlockValidationErrors::Other),
    }
    // now if that did not return Err() check if the network tag is correct
    if config.network_id != block.header.network {
        return Err(BlockValidationErrors::NetworkMissmatch);
    }
    // Now we check the hash of the block, by recomputing it
    let computed_hash = block.hash_return();
    if computed_hash != block.hash {
        debug!(
            "Block hash missmatch, expected={}, computed={}",
            block.hash, computed_hash
        );
        return Err(BlockValidationErrors::InvalidBlockhash);
    }
    // now see if we have the block saved, if so return
    let got_block = get_block_from_raw(computed_hash);
    if got_block == block {
        // we have this block saved, return Ok
        debug!(
            "Found block with hash={} in raw-block files (during validation)",
            block.hash
        );
        return Ok(());
    } else if got_block != Block::default() {
        // we have a block with the same hash saved, but it is not the same as this one!
        debug!("Block Collision during validation, found block with matching hash on disk: expected={:#?}, got={:#?}", block, got_block);
        return Err(BlockValidationErrors::BlockCollision);
    }
    // else: we dont have this block saved; continue
    // check if this block is the first 'genesis' block
    if block.header.height == 0 {
        if block.header.prev_hash != "00000000000" {
            debug!("Expected block at height 0 (genesis) to have previous hash of 00000000000");
            return Err(BlockValidationErrors::InvalidPreviousBlockhash);
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
                        return Err(BlockValidationErrors::FailedToGetGenesisBlock);
                    }
                }
            }
        }
        // if we got here then the genesis block was not found in the hardcoded list BUT there was no error in checking so, continue validation
        match get_account(&block.header.chain_key) {
            Ok(acc) => {
                if acc != Account::default() {
                    debug!("Validating genesis block with hash={} for chain={}, account already exists (got account not default)", block.hash, block.header.chain_key);
                    return Err(BlockValidationErrors::AccountExists);
                }
            }
            Err(e) => {
                if e != 0 {
                    // 0 = account file not found
                    error!(
                        "Failed to get account {} while checking if exists, error code={}",
                        block.header.chain_key, e
                    );
                    return Err(BlockValidationErrors::FailedToGetAccount(e));
                }
            }
        };
        // now check if the block is a send block (as height == 0) and the send_block feild is None
        if block.block_type != BlockType::Send || !block.send_block.is_none() {
            return Err(BlockValidationErrors::GenesisNotSendBlock);
        }
        // because this is a dynamic genesis block it cannot have any transactions in, check that
        if block.txns.len() != 0 {
            return Err(BlockValidationErrors::TransactionCountNotZero);
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
            return Err(BlockValidationErrors::BadSignature);
        }
    } else {
        // Not a genesis block
        match get_account(&block.header.chain_key) {
            Ok(acc) => {
                if acc == Account::default() {
                    debug!("Validating block with hash={} for chain={}, account does not exist (got account default)", block.hash, block.header.chain_key);
                    return Err(BlockValidationErrors::AccountDoesNotExist);
                }
            }
            Err(e) => {
                error!(
                    "Failed to get account {} while checking if exists, error code={}",
                    block.header.chain_key, e
                );
                return Err(BlockValidationErrors::FailedToGetAccount(e));
            }
        };
        // get previous block
        let got_block = get_block(&block.header.chain_key, block.header.height - 1);
        if got_block == Block::default() {
            error!("Cannot find block at height={} for chain={} with hash={} (while validating block with hash={})", block.header.height, block.header.chain_key, block.header.prev_hash, block.hash);
            return Err(BlockValidationErrors::PreviousBlockDoesNotExist);
        } else if got_block.hash != block.header.prev_hash {
            error!(
                "Previous block hash missmatch, expected={}, got={}",
                block.header.prev_hash, got_block.hash
            );
            return Err(BlockValidationErrors::InvalidPreviousBlockhash);
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
            return Err(BlockValidationErrors::BlockTooFarInTheFuture);
        }
        //check the block has at most 10 transactions in it
        if block.txns.len() > 10 {
            return Err(BlockValidationErrors::TooManyTxn);
        } else if std::mem::size_of_val(&block) > 2048000 {
            // check the block is no larger than 2mb
            return Err(BlockValidationErrors::BlockTooLarge);
        }
        if block.block_type == BlockType::Send {
            // check if the block has a valid signature
            if !block.valid_signature() {
                return Err(BlockValidationErrors::BadSignature);
            }
            // for every transaction in the block...
            for txn in &block.txns {
                // check if the txn is valid
                if let Err(txn_validation_error) = txn.valid() {
                    error!(
                        "Validating transaction {} in block {} gave error {:?}",
                        txn.hash, block.hash, txn_validation_error
                    );
                    return Err(BlockValidationErrors::InvalidTransaction(
                        txn_validation_error,
                    ));
                    // check the sender of the txn is the creator of this block
                } else if txn.sender_key != block.header.chain_key {
                    error!("Transaction {} in block {} has sender key {} but block has a sender/chain key of {}", txn.hash, block.hash, txn.receive_key, block.header.chain_key);
                    return Err(BlockValidationErrors::TransactionFromWrongChain);
                }
            }
        } else {
            if let Some(send_block_hash) = block.send_block {
                // get the corosponding send block for this recieve block
                let got_send_block = get_block_from_raw(send_block_hash);
                // If the block is default it is not found
                if got_send_block == Block::default() {
                    error!("Cannot find send block with hash");
                    return Err(BlockValidationErrors::SendBlockNotFound);
                } else if got_send_block.block_type != BlockType::Send {
                    // check if the claimed send block is really a send block
                    error!("Block with hash={} claims to be recieve block of {}, but it is a recieve block", block.hash, got_send_block.hash);
                    return Err(BlockValidationErrors::SendBlockWrongType);
                }
                // for every transaction in the block...
                for txn in &block.txns {
                    if !got_send_block.txns.contains(txn) {
                        // check if the transaction is in the send block for this block
                        error!(
                            "Transaction {} not found in send block {} (recieve block {} invalid)",
                            txn.hash, got_send_block.hash, block.hash
                        );
                        return Err(BlockValidationErrors::TransactionsNotInSendBlock);
                    } else if txn.receive_key != block.header.chain_key {
                        // check the recieve key of the transaction is the creator of this block (block.header.chain_key)
                        error!("Transaction {} in block {} has recieve key {} but block has a sender/chain key of {}", txn.hash, block.hash, txn.receive_key, block.header.chain_key);
                        return Err(BlockValidationErrors::TransactionFromWrongChain);
                    }
                }
            } else {
                // All recieve blocks should have the send_block field set to Some() value
                return Err(BlockValidationErrors::SendBlockEmpty);
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
/// Checks if a block is valid returns a blockValidationErrors
pub fn check_block_old(blk: Block) -> std::result::Result<(), BlockValidationErrors> {
    let got_block = get_block_from_raw(blk.hash.clone()); // try to read this block from disk, if it is saved it is assumed to already have been vaildated and hence is not revalidated
    if got_block == blk {
        // we have this block stored as a raw file (its valid)
        Ok(())
    } else if got_block == Block::default() {
        // we dont have this block in raw block storage files; validate it
        if blk.header.network != config().network_id {
            // check this block originated from the same network as us
            return Err(BlockValidationErrors::NetworkMissmatch);
        } else if blk.hash != blk.hash_return() {
            // hash the block and compare it to the claimed hash of the block.
            trace!(
                "Hash missmatch block: {}, computed hash: {}",
                blk.hash,
                blk.hash_return()
            );
            return Err(BlockValidationErrors::InvalidBlockhash);
        }
        if get_data(config().db_path + "/checkpoints", &blk.hash) != *"-1" {
            // we have this block in our checkpoints db and we know the hash is correct and therefore the block is valid
            return Ok(());
        }
        if blk.header.height == 0 {
            // This is a genesis block (the first block of a chain)
            // First we will check if there is a entry for this chain in the genesis blocks db
            let genesis: Block;
            let is_in_db;
            match get_genesis_block(&blk.header.chain_key) {
                Ok(b) => {
                    // this is in our genesis block db and so is a swap block (pregenerated to swap coins from the old network)
                    trace!("found genesis block in db");
                    genesis = b;
                    is_in_db = true;
                }
                Err(e) => match e {
                    GenesisBlockErrors::BlockNotFound => {
                        // this block is not in the genesis block db therefor this is a new chain that is not from the swap
                        genesis = Block::default();
                        is_in_db = false;
                    }
                    _ => {
                        warn!(
                            "Failed to get genesis block for chain: {}, gave error: {:?}",
                            &blk.header.chain_key, e
                        );
                        return Err(BlockValidationErrors::FailedToGetGenesisBlock);
                    }
                },
            }
            if blk != genesis && genesis != Block::default() {
                trace!(
                    "Genesis blocks missmatch. Ours: {:?}, propsed: {:?}",
                    genesis,
                    blk
                );
                Err(BlockValidationErrors::GenesisBlockMissmatch)
            } else if is_in_db {
                // if it is in the genesis block db it is guarenteed to be valid (as its pregenerated), we do not need to validate the block
                Ok(())
            } else {
                // if it isn't it needs to be validated like any other block
                if &blk.header.prev_hash != "00000000000" {
                    // genesis blocks should always reference "00000000000" as a previous hash (as there is none)
                    return Err(BlockValidationErrors::InvalidPreviousBlockhash);
                } else if let Ok(acc) = get_account(&blk.header.chain_key) {
                    // this account already exists, you can't have two genesis blocks
                    trace!("Already got acccount: {:?}", acc);
                    return Err(BlockValidationErrors::GenesisBlockMissmatch);
                } else if !blk.valid_signature() {
                    return Err(BlockValidationErrors::BadSignature);
                } else if get_block_from_raw(blk.hash.clone()) != Block::default() {
                    // this block already exists; this will return if the block is enacted and saved before running this function on a genesis block. So dont. :)
                    return Err(BlockValidationErrors::BlockExists);
                } else if blk.header.height != 0 // genesis blocks are exempt from broadcast delta limmits
                        && blk.header.timestamp - (config().transaction_timestamp_max_offset as u64)
                            > (SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Time went backwards")
                                .as_millis() as u64)
                {
                    // this block is too far in the future
                    return Err(BlockValidationErrors::TimestampInvalid);
                } else if blk.header.height != 0
                    && get_block_from_raw(blk.header.prev_hash).header.timestamp
                        > blk.header.timestamp
                {
                    // this block is older than its parent (prev block hash)
                    debug!("Block: {} timestamp under previous timestamp", blk.hash);
                    return Err(BlockValidationErrors::TimestampInvalid);
                }
                // if you got here the block is valid, yay!
                Ok(())
            }
        } else {
            // not genesis block
            if blk.confimed
                && blk.node_signatures.len() < (2.0 / 3.0 * config().commitee_size as f64) as usize
            {
                // if the block is marked as confirmed (SHARDING NETWORK VERSIONS+ ONLY) there must be at least 2/3 of a comitee of signatures
                // TODO: We are now planning on using retroactive comitee size calculation. In short, the comitee size will change dependent on the
                // number of fullnodes (each epoch). Account for this and read the stored data of the epoch this block was in (or get it if its the current epoch)
                // we also need to account for delegate nodes which wont sign
                return Err(BlockValidationErrors::TooLittleSignatures);
            } else {
                for signature in blk.clone().node_signatures {
                    // check each verifyer signature, a delegate node will not include a invalid verifyer signature so this should not happen without mallicious intervention
                    if !signature.valid() {
                        return Err(BlockValidationErrors::BadNodeSignature);
                    }
                }
            }

            let prev_blk = get_block(&blk.header.chain_key, &blk.header.height - 1); // get the top block of the chain, this SHOULD be the block mentioned in prev block hash
            trace!(
                "Prev block: {:?} for chain {}",
                prev_blk,
                blk.header.chain_key
            );
            if blk.header.prev_hash != prev_blk.hash && blk.header.prev_hash != *"" {
                // the last block in this chain does not equal the previous hash of this block
                debug!(
                    "Expected prev hash to be: {}, got: {}. For block at height: {}",
                    prev_blk.hash, blk.header.prev_hash, blk.header.height
                );
                return Err(BlockValidationErrors::InvalidPreviousBlockhash);
            } else if get_account(&blk.header.chain_key).is_err() {
                // this account doesn't exist, the first block must be a genesis block
                if blk.header.height != 0 {
                    return Err(BlockValidationErrors::Other);
                }
            } else if !blk.valid_signature() && blk.block_type != BlockType::Recieve {
                // recieve blocks are not formed by the reciecver and so the signature will be invalid
                return Err(BlockValidationErrors::BadSignature);
            } else if blk.header.timestamp - (config().transaction_timestamp_max_offset as u64)
                > (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64)
            {
                // the block is too far in future
                debug!("Block: {} too far in futre. Our time: {}, block time: {}, block justifyed time: {}. Delta {}", blk.hash, (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64), blk.header.timestamp, blk.header.timestamp - (config().transaction_timestamp_max_offset as u64),
            blk.header.timestamp - (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
        .as_millis() as u64),);
                return Err(BlockValidationErrors::TimestampInvalid);
            } else if blk.header.height != 0
                && get_block_from_raw(blk.header.prev_hash).header.timestamp > blk.header.timestamp
            {
                return Err(BlockValidationErrors::TimestampInvalid);
            }
            for txn in blk.txns {
                // check each txn in the block is valid
                if let Err(e) = txn.valid() {
                    return Err(BlockValidationErrors::InvalidTransaction(e));
                }
            }
            Ok(()) // if you got here there are no issues
        }
    } else {
        Err(BlockValidationErrors::BlockExists) // this block already exists
    }
}
pub fn from_compact(encoded: String) -> Result<Block, Box<dyn std::error::Error>> {
    let mut ret = Block::default();
    ret.decode_compressed(encoded)?;
    Ok(ret)
}

//todo write commentaion/docs for tests
pub mod encode;
pub mod genesis;
#[cfg(test)]
mod tests {
    use crate::rand::Rng;
    use crate::*;
    use avrio_config::*;
    use ring::rand as randc;
    use ring::signature::KeyPair;
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
