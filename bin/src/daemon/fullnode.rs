use avrio_core::{
    account::get_nonce,
    certificate::get_fullnode_count,
    chunk::{string_to_bls_privatkey, BlockChunk},
    commitee::Comitee,
    mempool::get_blocks,
    mempool::{self, add_block, Caller as CallerM},
};
use avrio_crypto::raw_lyra;
use avrio_p2p::{
    guid::{self, form_table},
    helper::prop_block_chunk,
};
use bls_signatures::{PublicKey, Serialize, Signature};
use std::{collections::HashSet, iter::FromIterator, thread::sleep, time::Duration};
// contains functions called by the fullnode
use crate::*;
use avrio_core::mempool::MEMPOOL;
use avrio_rpc::LOCAL_CALLBACKS;
lazy_static! {
    static ref VRF_LOTTO_ENTRIES: Mutex<Vec<(String, String)>> = Mutex::new(vec![]); // the public key of sender (first element), the hash the ticket is in
    static ref COMMITEE_INDEX: Mutex<u64> = Mutex::new(1025);
    static ref VALIDATED_CHUNKS: Mutex<Vec<String>> = Mutex::new(vec![]); // holds a vector of strings of all of the chunks that we validated this epoch
    static ref PROPOSED_CHUNKS: Mutex<Vec<String>> = Mutex::new(vec![]); // holds a vector of strings of all of the chunks that we proposed this epoch
}

pub fn mark_validated(chunk: &str) {
    if let Ok(mut lock) = VALIDATED_CHUNKS.lock() {
        lock.push(chunk.to_string());
    }
}

pub fn mark_proposed(chunk: &str) {
    if let Ok(mut lock) = PROPOSED_CHUNKS.lock() {
        lock.push(chunk.to_string());
    }
}

/// # Validator Loop
/// Called at the start of the main loop, calls the correct functions (for proposing and validating block chunks) then returns either an error (if enountered) or the number of chunks proposed and validated (in a tuple)
fn validator_loop(commitee: Comitee) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    if commitee.index == 0 {
        // consensus commitee
        return Err("Cannot run validator loop on consensus commitee".into());
    }
    match FULLNODE_KEYS.lock() {
        /* 0 - ECDSA pub, 1 - ECDSA priv, 2 - BLS pub, 3 - BLS priv, 4 - secp2561k pub, 5 - secp2561k priv*/
        Ok(lock) => {
            if !commitee.members.contains(&lock[0]) {
                return Err("Not in passed commitee".into());
            }
            loop {
                let epoch = get_top_epoch()?;
                // check if we are still in the main phase of the epoch
                if epoch.stage != EpochStage::main {
                    debug!("Main stage ended, terminating validator loop");
                    break;
                }
                if commitee.get_round_leader() == lock[0] {
                    // we are round leader
                    // collect all unprocessed blocks from mempool related to our committee
                    let blocks = get_blocks()?;
                    let mut bc_blocks: Vec<Block> = vec![];

                    let addr_range = commitee.calculate_address_range(epoch.committees.len());
                    for block in blocks {
                        let wall = Wallet::new(block.sender_key, String::default());
                        let address_hex = hex::encode(bs58::decode(wall.address()).into_vec()?);
                        let address_numerical = i64::from_str_radix(&address_hex, 16)?.abs();
                        let address_bigdec = BigDecimal::from(address_numerical);
                        if addr_range.contains(&address_bigdec) {
                            bc_blocks.push(block);
                        }
                        if block.block_type == BlockType::Send {
                            for reciever in block.recievers() {
                                let wall = Wallet::new(block.sender_key.clone(), String::default());
                                let address_hex =
                                    hex::encode(bs58::decode(wall.address()).into_vec()?);
                                let address_numerical =
                                    i64::from_str_radix(&address_hex, 16)?.abs();
                                let address_bigdec = BigDecimal::from(address_numerical);
                                if addr_range.contains(&address_bigdec) {
                                    let rec_block =
                                        block.form_receive_block(Some(block.sender_key.clone()));
                                    if let Err(e) = rec_block {
                                        error!("Failed to form recieve block for {} on block {}, gave error: {}", wall.address(), block.hash, e);
                                        continue;
                                    } else {
                                        bc_blocks.push(rec_block.unwrap());
                                    }
                                }
                            }
                        }
                    }
                    if bc_blocks.len() == 0 {
                        debug!("Collected no blocks for chunk, retrying");
                        sleep(Duration::from_millis(5000))
                    } else {
                        info!(
                            "Forming block chunk with {} blocks, for round {}",
                            bc_blocks.len(),
                            commitee.round()
                        );
                        let bc = BlockChunk::form(&bc_blocks, commitee.index);
                        if let Err(e) = bc {
                            error!("Failed to form block chunk, gave error {}", e);
                            // TODO: Should we return or just try again?
                        } else {
                            let mut bc = bc.unwrap();
                            bc.hash = bc.hash_item();
                            debug!("Formed block chunk with hash {}", bc.hash);
                            // propose the block chunk
                            match propose_premade_chunk(&mut bc, &epoch) {
                                Ok(()) => {
                                    info!("Proposed block chunk {} for round {}, containing {} blocks", bc.hash, commitee.round(), bc_blocks.len());
                                    // add the hash of the chunk to proposed chunk lsit
                                    mark_proposed(&bc.hash);
                                    break;
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to propagate premade chunk {}, gave error {}",
                                        bc.hash, e
                                    );
                                }
                            }
                        }
                    }
                } else {
                    trace!("Not round leader, acting as validator instead");
                    // Nothing to do (for now)
                }
            }
        }
        Err(e) => {
            error!("Failed to get lock on fullnode keys {}", e);
            return Err("Failed to get lock on fullnode keys".into());
        }
    }
    Ok((PROPOSED_CHUNKS.lock()?.len() as u64, VALIDATED_CHUNKS.lock()?.len() as u64))
}

/// # Create salt seed
/// Creates a salt seed for the round leader to consume
/// returns the salt seed vrf proof as a string
pub fn create_salt_seed() -> Result<String, Box<dyn std::error::Error>> {
    match FULLNODE_KEYS.lock() {
        /* 0 - ECDSA pub, 1 - ECDSA priv, 2 - BLS pub, 3 - BLS priv, 4 - secp2561k pub, 5 - secp2561k priv*/
        Ok(lock) => {
            let (proof, _) = get_vrf(lock[5].clone(), String::from("genesis"))?;
            if !avrio_crypto::validate_vrf(lock[4].clone(), proof.clone(), String::from("genesis"))
            {
                error!("Created salt seed invalid");
                return Err("epoch salt seed invalid".into());
            }
            trace!("Created seed={}", proof);
            return Ok(proof);
        }
        Err(e) => {
            error!("Failed to get lock on fullnode keys{}", e);
            return Err("Failed to get lock on fullnode keys".into());
        }
    }
}

pub fn propose_premade_chunk(
    block_chunk: &mut BlockChunk,
    current_epoch: &Epoch,
) -> Result<(), Box<dyn std::error::Error>> {
    let lock = get_keys()?;
    trace!("Proposing premade chunk {:#?} to peers", block_chunk);
    let bls_key = string_to_bls_privatkey(&lock[3]).unwrap();
    let mut bc_sigs = vec![block_chunk.sign(bls_key)];

    let mut bc_signers =
        vec![PublicKey::from_bytes(&bs58::decode(&lock[2]).into_vec().unwrap()).unwrap()];
    trace!("Signed block chunk, signature={:#?}", bc_sigs[0]);
    // send this chunk to all our GUID table
    match avrio_p2p::guid::send_to_all(block_chunk.encode().unwrap(), 0x64, true, false) {
        Ok(sigs) => {
            for signature in sigs {
                if signature.message_type != 0x53 {
                    error!(
                        "Received unexpected message type={} from peer",
                        signature.message_type
                    );
                    continue;
                }
                let signatures_got: Vec<(String, String)> =
                    serde_json::from_str(&signature.message).unwrap();
                // TODO: In the future, we should use then entire vector of signatures as this will contain other block chunk signatures that the peer has got from ITS GUID ring, for now we just access 0
                match bs58::decode(&signatures_got[0].1).into_vec() {
                    Ok(sig_bytes) => {
                        // form a bls signature struct from the bytes
                        let sig = Signature::from_bytes(&sig_bytes);
                        match sig {
                            Ok(s) => {
                                trace!(
                                    "Received signature from peer={}, signature={}",
                                    signatures_got[0].0,
                                    signatures_got[0].1
                                );
                                // add the signature to the block chunk
                                bc_sigs.push(s);
                                let sig_auth = PublicKey::from_bytes(
                                    &bs58::decode(&signatures_got[0].0).into_vec().unwrap(),
                                )
                                .unwrap();
                                bc_signers.push(sig_auth);
                            }
                            Err(e) => {
                                error!("Failed to form signature from bytes, error={}", e);
                            }
                        }
                    }
                    Err(decode_error) => {
                        error!("Failed to decode base58 siganture bytes from peer={}, got error: {}, bs58 sig: {}", signatures_got[0].0, decode_error, signatures_got[0].1);
                    }
                }
            }
            info!(
                "Sent block chunk to all peers, got {} signatures",
                bc_sigs.len()
            );
            // check if we got enough signatures
            if bc_sigs.len() < (current_epoch.committees[0].members.len() * 1 / 3) {
                error!(
                    "Failed to get enough signatures from peers, got={} required={}",
                    bc_sigs.len(),
                    current_epoch.committees[0].members.len() * 1 / 3
                );
            }
            // we have enough signatures, add them to the block chunk
            block_chunk.add_signatures(&bc_sigs, bc_signers).unwrap();
            // now we have a block chunk with enough signatures, we can propagate it
            trace!("Propagating block chunk={:#?}", block_chunk);
            prop_block_chunk(&block_chunk).unwrap();
            block_chunk.enact()?;
            // Done
            return Ok(());
        }
        Err(e) => {
            error!("Failed to send block chunk to all peers, error={}", e);
            return Err(format!("Failed to send block chunk to all peers, error={}", e).into());
        }
    }
}

pub fn handle_proposed_chunk(
    chunk: BlockChunk,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    match get_keys() {
        Ok(keys_lock) => {
            /* 0 - ECDSA pub, 1 - ECDSA priv, 2 - BLS pub, 3 - BLS priv, 4 - secp2561k pub, 5 - secp2561k priv*/
            if keys_lock.len() != 6 {
                error!(
                    "Keys not loaded, expected 6 keys but have {}",
                    keys_lock.len()
                );
                return Err("Keys not loaded".into());
            }
            let chunk_proposer = chunk.proposer()?;
            trace!(
                "Handling proposed chunk {}, proposed by {} for round {}",
                chunk.hash,
                chunk_proposer,
                chunk.round
            );
            // check the chunk itself is valid
            if let Err(chunk_validation_error) = chunk.valid() {
                error!(
                    "Proposed chunk {} (proposer: {}, round: {}) invalid, reason={}",
                    chunk.hash, chunk_proposer, chunk.round, chunk_validation_error
                );
                return Err(format!("Chunk invalid {}", chunk_validation_error).into());
            }
            // the chunk is valid, check if we have all the blocks in the chunk
            let mut chunk_blocks: Vec<Block> = vec![];
            for block_hash in &chunk.blocks {
                trace!("Looking for {} in mempool", block_hash);
                if let Ok(block) = mempool::get_block(block_hash) {
                    trace!("Found block {} in mempool", block_hash);
                    chunk_blocks.push(block);
                } else {
                    trace!("Block {} contained in chunk {} not found in mempool, getting from GUID peers", block_hash, chunk.hash);
                    match guid::send_to_all(format!("{}.1", block_hash), 0x45, true, false) {
                        Err(e) => {
                            error!("Failed to ask GUID peers for block, error={}", e);
                            return Err("Failed to ask GUID peers for block".into());
                        }
                        Ok(response) => {
                            trace!("Got response from GUID peers: {:#?}", response);
                            if let Ok(block) = Block::from_compressed(response[0].message.clone()) {
                                debug!("Decoded block from compressed, block hash={}", block.hash);
                                chunk_blocks.push(block);
                            } else {
                                return Err("Failed to decode block got from GUID peers".into());
                            }
                        }
                    }
                }
            }
            if chunk_blocks.len() != chunk.blocks.len() {
                error!(
                    "Failed to get {} blocks for chunk {}",
                    chunk.blocks.len() - chunk_blocks.len(),
                    chunk.hash
                );
                return Err("Could not get all blocks".into());
            }
            // validate every block
            for block in chunk_blocks {
                if let Err(e) = block.valid() {
                    error!(
                        "Block {} contained in chunk {} invalid, reason {}",
                        block.hash, chunk.hash, e
                    );
                    return Err("Invalid block".into());
                } else {
                    debug!(
                        "Block {} contained in chunk {} valid",
                        block.hash, chunk.hash
                    );
                }
            }
            // All blocks are valid, create a BLS signature for this chunk and return it
            let sig: Signature = chunk.sign(string_to_bls_privatkey(&keys_lock[3])?);
            mark_validated(&chunk.hash);
            Ok((
                keys_lock[0].clone(),
                bs58::encode(sig.as_bytes()).into_string(),
            ))
        }
        Err(lock_error) => {
            error!(
                "Failed to get mutex lock on FULLNODE_KEYS lazy static error={}",
                lock_error
            );
            return Err(format!(
                "Failed to get mutex lock on FULLNODE_KEYS lazy static error={}",
                lock_error
            )
            .into());
        }
    }
}

pub fn should_handle_chunk(chunk: BlockChunk) -> bool {
    match get_keys() {
        /* 0 - ECDSA pub, 1 - ECDSA priv, 2 - BLS pub, 3 - BLS priv, 4 - secp2561k pub, 5 - secp2561k priv*/
        Ok(keys_lock) => {
            if let Ok(top_epoch) = get_top_epoch() {
                for commitee in top_epoch.committees {
                    if commitee.members.contains(&keys_lock[0]) {
                        // found our commitee
                        if commitee.index == chunk.committee {
                            return true;
                        }
                        break;
                    }
                }
            }
            false
        }
        Err(lock_error) => {
            error!(
                "Failed to get mutex lock on FULLNODE_KEYS lazy static error={}",
                lock_error
            );
            return false;
        }
    }
}

/// # Propose round chunk
/// Proposes the current rounds chunk, returning the proposed chunk on sucsess or any errors enountered
/// If called when the node is not the selected proposer then an error will be returned
pub fn propose_round_chunk() -> Result<String, Box<dyn std::error::Error>> {
    match get_keys() {
        /* 0 - ECDSA pub, 1 - ECDSA priv, 2 - BLS pub, 3 - BLS priv, 4 - secp2561k pub, 5 - secp2561k priv*/
        Ok(keys_lock) => {
            // get the rounds context
            let epoch = get_top_epoch()?;
            // get our commitees current state
            let ci_lock = COMMITEE_INDEX.lock()?;
            let committee_index = ci_lock.clone();
            drop(ci_lock);
            if committee_index == 1025 {
                error!("Committee index not set (eq 1025)");
                return Err("Committee index not set".into());
            } else if committee_index > (epoch.committees.len() - 1) as u64 {
                error!(
                    "Committee index overflow, index={}, commitees={}",
                    committee_index,
                    epoch.committees.len()
                );
                return Err("Committee index overflow".into());
            }
            // get the committee struct
            let committee = epoch.committees[committee_index as usize].clone();
            // get the round number
            let top_epoch = get_top_epoch()?;
            let top_round_index: u64 = get_data(
                config().db_path + "/blockchunks",
                &(committee.index.to_string() + "-round-" + &epoch.epoch_number.to_string()),
            )
            .parse()?;
            let top_chunk =
                BlockChunk::get_by_round(top_round_index, top_epoch.epoch_number, committee.index)?;
            // check we are the proposer for this round
            let selected_round_leader = committee.get_round_leader()?;
            if selected_round_leader != keys_lock[0] {
                error!(
                    "Not proposer for round {}, in commitee {}, selected proposer {}",
                    top_chunk.round, committee.index, selected_round_leader
                );
                return Err("Not proposer for round".into());
            }
            info!(
                "Proposing chunk for round {} in committee {}",
                top_chunk.round, committee.index
            );
            // collect all blocks from mempool that are awaiting validation (from our address range)
            let mut blocks: Vec<Block> = vec![];
            let map = MEMPOOL.lock()?;
            for (block, _, _) in map.values() {
                if committee.manages_address(&block.header.chain_key)? {
                    // sent by one of our managed addresses
                    trace!(
                        "Including block {} in chunk, sent by {}, new chunk size {}",
                        block.hash,
                        block.header.chain_key,
                        blocks.len() + 1
                    );
                    blocks.push(block.clone());
                } else {
                    for reciever in block.recievers() {
                        if committee.manages_address(&reciever)? {
                            // This block is sent to one of the addresses in our shard, form a recieve block
                            let recieve_block = block.form_receive_block(Some(reciever.clone()))?;
                            trace!(
                                "Formed recieve block {} for reciever {} of block {}, new chunk size {}",
                                recieve_block.hash,
                                reciever,
                                block.hash,
                                blocks.len() + 1
                            );
                            blocks.push(recieve_block);
                        }
                    }
                }
            }
            debug!("{} blocks to use in new chunk", blocks.len());
            let new_chunk = *BlockChunk::form(&blocks, committee_index)?;
            // TODO: now ask each of our GUID peers to sign our chunk, as well as send it to their GUID peers to sign
            return Ok(String::default());
        }
        Err(lock_error) => {
            error!(
                "Failed to get mutex lock on FULLNODE_KEYS lazy static error={}",
                lock_error
            );
            return Err(format!(
                "Failed to get mutex lock on FULLNODE_KEYS lazy static error={}",
                lock_error
            )
            .into());
        }
    }
}

pub fn get_keys() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    match FULLNODE_KEYS.lock() {
        /* 0 - ECDSA pub, 1 - ECDSA priv, 2 - BLS pub, 3 - BLS priv, 4 - secp2561k pub, 5 - secp2561k priv*/
        Ok(keys_lock) => Ok(keys_lock.clone()),
        Err(lock_error) => {
            error!(
                "Failed to get mutex lock on FULLNODE_KEYS lazy static error={}",
                lock_error
            );
            return Err(format!(
                "Failed to get mutex lock on FULLNODE_KEYS lazy static error={}",
                lock_error
            )
            .into());
        }
    }
}

pub fn start_genesis_epoch() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting genesis epoch");
    // create the salt from just our VRF
    match get_keys() {
        /* 0 - ECDSA pub, 1 - ECDSA priv, 2 - BLS pub, 3 - BLS priv, 4 - secp2561k pub, 5 - secp2561k priv*/
        Ok(lock) => {
            let (proof, _) = get_vrf(lock[5].clone(), String::from("genesis"))?;
            if !avrio_crypto::validate_vrf(lock[4].clone(), proof.clone(), String::from("genesis"))
            {
                error!("Created salt seed invalid");
                return Err("epoch salt seed invalid".into());
            }
            trace!("Created seed={}", proof);
            let seeds = (lock[0].clone(), proof);
            // form announce epoch seed txn
            let mut transaction = Transaction {
                hash: String::from(""),
                amount: 0,
                extra: bs58::encode(serde_json::to_string(&seeds)?).into_string(),
                flag: 'a',
                sender_key: lock[0].clone(),
                receive_key: String::from("0"),
                access_key: String::from(""),
                unlock_time: 0,
                gas_price: 1,
                max_gas: u64::MAX,
                nonce: get_nonce(lock[0].clone()),
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            };
            transaction.hash();
            let seed_block = Block::new(vec![transaction], lock[1].clone(), None);
            trace!("Created block={}", seed_block.hash);
            let mut seed_block_rec = seed_block.form_receive_block(Some(String::from("0")))?;
            let _ = seed_block_rec.sign(&lock[1]).unwrap();
            trace!("Created block={}", seed_block_rec.hash);

            if let Err(seed_error) = seed_block
                .valid()
                .and_then(|_| seed_block.save())
                .and_then(|_| seed_block.enact())
                .and_then(|_| seed_block_rec.valid())
                .and_then(|_| seed_block_rec.save())
                .and_then(|_| seed_block_rec.enact())
            {
                error!(
                    "Failed to broadcast epoch seed in block, got error={}",
                    seed_error
                );
                return Err(format!(
                    "Failed to broadcast epoch seed in block, got error={}",
                    seed_error
                )
                .into());
            }
            trace!("Enacted blocks");
            // propagate these blocks early as we need the VRF responses
            for block in &[seed_block, seed_block_rec] {
                trace!("Sending {} to peers", block.hash);
                if let Err(prop_err) = prop_block(block) {
                    error!(
                        "Failed to send block {} to peers, encounted error={}",
                        block.hash, prop_err
                    );
                    return Err(format!("Failed to prop epoch seed block {}", block.hash).into());
                }
            }
            // Now we wait for VRF tickets to come in
            // register with the announcement system, to collect all VRF lotto tickets
            let mut block_callbacks = LOCAL_CALLBACKS.lock()?;
            block_callbacks.push(Caller {
                callback: Box::new(|ann| {
                    if ann.m_type == "block" {
                        let block: Block = serde_json::from_str(&ann.content).unwrap();
                        for txn in block.txns {
                            if txn.flag == 'v' {
                                handle_vrf_submitted(txn);
                            }
                        }
                    }
                }),
            });
            drop(block_callbacks);
            sleep(Duration::from_millis(config().vrf_lottery_length)); // wait for the VRF lottery to end
                                                                       // now we can proceed
            let mut blocks: Vec<Block> = vec![];

            // create the shuffle bits
            // This is used to shuffle the fullnode list into a "random" order and form the committee lists
            let top_epoch = get_top_epoch()?;
            let new_epoch = Epoch::get(top_epoch.epoch_number + 1)?;
            let (shuffle_proof, _) = get_vrf(
                lock[5].clone(),
                raw_lyra(
                    &(new_epoch.salt.to_string() + &new_epoch.epoch_number.to_string() + &lock[0]),
                ),
            )?;

            let mut transaction = Transaction {
                hash: String::from(""),
                amount: 0,
                extra: bs58::encode(shuffle_proof).into_string(),
                flag: 'z',
                sender_key: lock[0].clone(),
                receive_key: String::from("0"),
                access_key: String::from(""),
                unlock_time: 0,
                gas_price: 1,
                max_gas: u64::MAX,
                nonce: get_nonce(lock[0].clone()),
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            };
            transaction.hash();
            let shuffle_bits_block = Block::new(vec![transaction], lock[1].clone(), None);
            let mut shuffle_bits_block_rec =
                shuffle_bits_block.form_receive_block(Some(String::from("0")))?;
            let _ = shuffle_bits_block_rec.sign(&lock[1]).unwrap();

            if let Err(shuffle_bits_error) = shuffle_bits_block
                .valid()
                .and_then(|_| shuffle_bits_block.save())
                .and_then(|_| shuffle_bits_block.enact())
                .and_then(|_| shuffle_bits_block_rec.valid())
                .and_then(|_| shuffle_bits_block_rec.save())
                .and_then(|_| shuffle_bits_block_rec.enact())
            {
                error!(
                    "Failed to broadcast shuffle bits in block, got error={}",
                    shuffle_bits_error
                );
                return Err(format!(
                    "Failed to broadcast shuffle bits in block, got error={}",
                    shuffle_bits_error
                )
                .into());
            }
            blocks.push(shuffle_bits_block);
            blocks.push(shuffle_bits_block_rec);
            //TODO: Use the collected vrf tickets to create this delta list
            // create an empty fullnode delta list txn
            // TODO: Shouldnt we be processing all the VRF tickets that came in
            let mut delta_list: ((String, String), Vec<(String, u8, String)>) = (
                (raw_lyra(&lock[0]), raw_lyra(&top_epoch.committees[0].hash)),
                vec![],
            );

            let mut transaction = Transaction {
                hash: String::from(""),
                amount: 0,
                extra: bs58::encode(serde_json::to_string(&delta_list)?).into_string(),
                flag: 'y',
                sender_key: lock[0].clone(),
                receive_key: String::from("0"),
                access_key: String::from(""),
                unlock_time: 0,
                gas_price: 1,
                max_gas: u64::MAX,
                nonce: get_nonce(lock[0].clone()),
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            };
            transaction.hash();
            let delta_list_block = Block::new(vec![transaction], lock[1].clone(), None);
            let mut delta_list_block_rec =
                delta_list_block.form_receive_block(Some(String::from("0")))?;
            let _ = delta_list_block_rec.sign(&lock[1]).unwrap();

            if let Err(delta_list_error) = delta_list_block
                .valid()
                .and_then(|_| delta_list_block.save())
                .and_then(|_| delta_list_block.enact())
                .and_then(|_| delta_list_block_rec.valid())
                .and_then(|_| delta_list_block_rec.save())
                .and_then(|_| delta_list_block_rec.enact())
            {
                error!(
                    "Failed to broadcast delta_list in block, got error={}",
                    delta_list_error
                );
                return Err(format!(
                    "Failed to broadcast delta_list in block, got error={}",
                    delta_list_error
                )
                .into());
            }
            blocks.push(delta_list_block);
            blocks.push(delta_list_block_rec);
            // send blocks to network
            for block in &blocks {
                let _ = prop_block(block)?;
            }
            return Ok(());
        }
        Err(lock_error) => {
            error!(
                "Failed to get mutex lock on FULLNODE_KEYS lazy static, error={}",
                lock_error
            );
            return Err("Could not lock FULLNODE_KEYS".into());
        }
    };
}

pub fn handle_vrf_submitted(txn: Transaction) {
    match get_keys() {
        Ok(lock) => {
            let top_epoch = get_top_epoch().unwrap();
            // check if we are the round leader for the consensus commitee
            let round_leader = top_epoch.committees[0]
                .get_round_leader()
                .unwrap_or_default();
            let ticket_hash =
                raw_hash(&format!("{}{}{}", txn.hash, txn.sender_key, txn.extra))[0..5].to_string();
            if round_leader == lock[0] {
                // TODO: iterate over the tickets and check if they are valid:
                // 1. Check if the sender has stagnated (if needed) and is therefor a viable candiate
                // 2. Check if the ticket index has breached the candidates ticket number
                // 3. Check if the ticket value fufills the eclosure criterion (for now < 1 == all tickets eclose)
                debug!(
                    "Consensus commitee round leader, handling VRF lottery ticket={}",
                    ticket_hash
                );
                // decode VRF's proof into value
                let vrf_hash = proof_to_hash(&txn.extra).unwrap_or_default();
                // turn VRF hash into bigint
                let vrf_ticket_bigint = vrf_hash_to_integer(vrf_hash);
                debug!(
                    "VRF lotto ticket={} sent by={} value={}, viable={}",
                    ticket_hash,
                    txn.sender_key,
                    vrf_ticket_bigint,
                    vrf_ticket_bigint < BigDecimal::from(1)
                );
                // check if the sender is a candidate
                let fullnode_status = get_data(config().db_path + "/candiadates", &txn.sender_key);
                if fullnode_status != "c" {
                    error!(
                        "VRF ticket={} sent by={} is not a candidate, fullnode status {}",
                        ticket_hash, txn.sender_key, fullnode_status
                    );
                    return;
                }
                match VRF_LOTTO_ENTRIES.lock() {
                    Ok(mut lock) => {
                        lock.push((txn.sender_key.clone(), txn.extra.clone()));
                    }
                    Err(lock_error) => {
                        error!(
                            "Failed to get mutex lock on VRF_LOTTO_ENTRIES lazy static, error={}",
                            lock_error
                        )
                    }
                }
            } else if top_epoch.committees[0].members.contains(&lock[0]) {
                // check if we are just a validator in the consensus commitee
                debug!(
                    "In consensus commitee, sending VRF ticket={} to round leader={} role=validator", 
                    ticket_hash,
                    round_leader
                );
                // TODO: Send the ticket to the round leader
            } else {
                debug!(
                    "Not in consensus commitee, ignoring VRF lotto ticket={}",
                    ticket_hash
                );
            }
        }
        Err(lock_error) => error!(
            "Failed to get mutex lock on FULLNODE_KEYS lazy static error={}",
            lock_error
        ),
    }
}
/// Starts the next epoch
// Returns a result, if we are in a committee this epoch and we sucsessfully started this epoch Ok(true), if we are excluded this epoch Ok(false)
/// Otherwise if there was an error return it
pub fn handle_new_epoch() -> Result<bool, Box<dyn std::error::Error>> {
    trace!("handle_new_epoch called");
    create_timer(
        Duration::from_millis(config().target_epoch_length),
        Box::new(start_vrf_lotto),
        (),
    );
    match get_keys() {
        Ok(lock) => {
            let current_epoch = get_top_epoch()?;
            let mut our_committee: Comitee = Comitee::default();
            for committee in &current_epoch.committees {
                if committee.members.contains(&lock[0]) {
                    info!("In committee {}", committee.index);
                    // set the commitee index lazy static
                    *(COMMITEE_INDEX.lock()?) = committee.index;
                    our_committee = committee.clone();
                    break;
                }
            }
            if our_committee == Comitee::default() && config().node_type == 'f' {
                info!("Not in any commitee, assuming excluded");
                return Ok(false);
            } else {
                info!("Forming GUID routing table");
                // Form GUID table
                match form_table(vec![]) {
                    Ok(size) => {
                        info!("Formed intra-committee GUID routing table, size={}", size)
                    }
                    Err(error) => {
                        error!(
                            "Failed to form GUID routing table, encountered fatal error={}",
                            error
                        );
                        return Err("Failed to form GUID routing table".into());
                    }
                }
                // Start the validator loop
                validator_loop(our_committee);
            }
        }
        Err(lock_error) => {
            error!(
                "Failed to get mutex lock on FULLNODE_KEYS lazy static, error={}",
                lock_error
            );
            return Err("Could not lock FULLNODE_KEYS".into());
        }
    }
    Ok(true)
}

pub fn start_vrf_lotto(_null: ()) {
    trace!("Starting VRF lottery");
    match get_keys() {
        Ok(lock) => {
            let current_epoch = get_top_epoch().unwrap_or_default();
            if current_epoch.committees[0]
                .get_round_leader()
                .unwrap_or_default()
                == lock[0]
            {
                info!("Consensus committee round leader, coordinating epoch salt formation");
                // ask all peers in our guid table to form an epoch salt
                match avrio_p2p::guid::send_to_all(String::default(), 0x06, true, false) {
                    Ok(salts) => {
                        info!(
                            "Sent epoch salt formation request to all peers, got {} salts",
                            salts.len()
                        );
                        let mut salt_proofs = vec![];
                        for salt in salts {
                            if salt.message_type != 0x07 {
                                error!(
                                    "Received unexpected message type={} from peer",
                                    salt.message_type
                                );
                                continue;
                            }
                            let salt_proof = salt.message.clone();
                            salt_proofs.push(salt_proof);
                        }
                        // check if we got enough salts
                        if salt_proofs.len()
                            < ((current_epoch.committees[0].members.len() - 1) * 1 / 3)
                        {
                            // len() - 1 accounts from our salt not being present
                            error!(
                                "Failed to get enough salts from peers, got={} required={}",
                                salt_proofs.len(),
                                ((current_epoch.committees[0].members.len() - 1) * 1 / 3)
                            );
                            //TODO: retry
                            return;
                        }
                        // Form our salt
                        match create_salt_seed() {
                            Ok(self_salt) => {
                                info!("Formed our salt, salt={}", self_salt);
                                salt_proofs.push(self_salt);
                                trace!("Salt proofs={:?}", salt_proofs);
                                // form the epoch salt txn
                                let mut transaction = Transaction {
                                    hash: String::from(""),
                                    amount: 0,
                                    extra: bs58::encode(
                                        serde_json::to_string(&(
                                            lock[0].clone(),
                                            salt_proofs[0].clone(),
                                        ))
                                        .unwrap(),
                                    )
                                    .into_string(),
                                    flag: 'a',
                                    sender_key: lock[0].clone(),
                                    receive_key: String::from("0"),
                                    access_key: String::from(""),
                                    unlock_time: 0,
                                    gas_price: 1,
                                    max_gas: u64::MAX,
                                    nonce: get_nonce(lock[0].clone()),
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64,
                                };
                                transaction.hash();
                                let seed_block =
                                    Block::new(vec![transaction], lock[1].clone(), None);
                                trace!("Created block={}", seed_block.hash);
                                let mut seed_block_rec = seed_block
                                    .form_receive_block(Some(String::from("0")))
                                    .unwrap();
                                let _ = seed_block_rec.sign(&lock[1]).unwrap();
                                trace!("Created block={}", seed_block_rec.hash);

                                let blocks = vec![seed_block, seed_block_rec];
                                for block in &blocks {
                                    trace!("Sending {} to peers", block.hash);
                                    if let Err(prop_err) = prop_block(block) {
                                        error!(
                                            "Failed to send block {} to peers, encounted error={}",
                                            block.hash, prop_err
                                        );
                                        return;
                                    }
                                    let _ = add_block(block, CallerM::blank());
                                }
                                // form a block chunk containing the seed block and the seed block rec
                                let mut block_chunk = *BlockChunk::form(&blocks, 0).unwrap();
                                trace!("Formed block chunk={}", block_chunk.hash);
                                propose_premade_chunk(&mut block_chunk, &current_epoch).unwrap();
                                //TODO: merge these into one chunk
                                // Now create the shuffle bits
                                let new_epoch = Epoch::get(current_epoch.epoch_number + 1).unwrap();
                                let (shuffle_proof, _) = get_vrf(
                                    lock[5].clone(),
                                    raw_lyra(
                                        &(new_epoch.salt.to_string()
                                            + &new_epoch.epoch_number.to_string()
                                            + &lock[0]),
                                    ),
                                )
                                .unwrap();
                                let mut transaction = Transaction {
                                    hash: String::from(""),
                                    amount: 0,
                                    extra: bs58::encode(shuffle_proof).into_string(),
                                    flag: 'z',
                                    sender_key: lock[0].clone(),
                                    receive_key: String::from("0"),
                                    access_key: String::from(""),
                                    unlock_time: 0,
                                    gas_price: 1,
                                    max_gas: u64::MAX,
                                    nonce: get_nonce(lock[0].clone()),
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64,
                                };
                                transaction.hash();
                                let shuffle_bits_block =
                                    Block::new(vec![transaction], lock[1].clone(), None);
                                let mut shuffle_bits_block_rec = shuffle_bits_block
                                    .form_receive_block(Some(String::from("0")))
                                    .unwrap();
                                let _ = shuffle_bits_block_rec.sign(&lock[1]).unwrap();
                                let blocks = vec![shuffle_bits_block, shuffle_bits_block_rec];
                                for block in &blocks {
                                    trace!("Sending {} to peers", block.hash);
                                    if let Err(prop_err) = prop_block(block) {
                                        error!(
                                            "Failed to send block {} to peers, encounted error={}",
                                            block.hash, prop_err
                                        );
                                        return;
                                    }
                                    add_block(block, CallerM::blank());
                                }
                                // form a block chunk containing the seed block and the seed block rec
                                let mut block_chunk = *BlockChunk::form(&blocks, 0).unwrap();
                                trace!("Formed block chunk={}", block_chunk.hash);
                                propose_premade_chunk(&mut block_chunk, &current_epoch).unwrap();
                                // Now we wait for VRF tickets to come in
                                // register with the announcement system, to collect all VRF lotto tickets
                                let mut block_callbacks = LOCAL_CALLBACKS.lock().unwrap();
                                block_callbacks.push(Caller {
                                    callback: Box::new(|ann| {
                                        if ann.m_type == "block" {
                                            let block: Block =
                                                serde_json::from_str(&ann.content).unwrap();
                                            for txn in block.txns {
                                                if txn.flag == 'v' {
                                                    handle_vrf_submitted(txn);
                                                }
                                            }
                                        }
                                    }),
                                });
                                drop(block_callbacks);
                                sleep(Duration::from_millis(60000)); // wait a single minute
                                                                     // now we can proceed
                                                                     // Form a delta list from the tickets
                                                                     // format: ((String, String), Vec<(String, u8, String)) 0.0: Preshuffle hash, 0.1: postshuffle hash, 1.0: publickey, 1.1: reason/type (0 = join via vrf everything else = leave), 1.2: proof (the hash of the block it happened in)
                                let mut delta_list: ((String, String), Vec<(String, u8, String)>) =
                                    ((String::default(), String::default()), vec![]);
                                let tickets_lock = VRF_LOTTO_ENTRIES.lock().unwrap();
                                let tickets = tickets_lock.to_vec();
                                drop(tickets_lock);
                                for (ticket_auth, block_hash) in tickets {
                                    delta_list.1.push((ticket_auth, 0, block_hash));
                                }
                                // form the hashes for the delta list
                                let mut fullnodes_hashset: HashSet<String> = HashSet::new();
                                for committee in current_epoch.committees {
                                    for fullnode in committee.members {
                                        fullnodes_hashset.insert(fullnode);
                                    }
                                }
                                for delta in &delta_list.1 {
                                    if delta.1 != 0 {
                                        // remove the fullnode
                                        // TODO: validate remove proof
                                        if fullnodes_hashset.contains(&delta.0) {
                                            trace!(
                                        "Removing {} from fullnode set, reason={}, proof={}",
                                        delta.0,
                                        delta.1,
                                        delta.2
                                    );
                                            fullnodes_hashset.remove(&delta.0);
                                        } else {
                                            error!("Fullnode set did not contain node removed by delta entry, delta entry={:?}", delta);
                                        }
                                    } else {
                                        // TODO: validate add proof before eclsoure
                                        fullnodes_hashset.insert(delta.0.clone());
                                    }
                                }
                                let mut fullnodes: Vec<String> = Vec::from_iter(fullnodes_hashset);
                                let mut preshuffle_hash = String::from("");
                                for fullnode in &fullnodes {
                                    preshuffle_hash = raw_lyra(&(preshuffle_hash + fullnode));
                                }

                                // now we shuffle the list
                                let curr_epoch =
                                    Epoch::get(current_epoch.epoch_number + 1).unwrap();
                                let shuffle_seed = vrf_hash_to_integer(raw_lyra(
                                    &(curr_epoch.shuffle_bits.to_string()
                                        + &curr_epoch.salt.to_string()
                                        + &curr_epoch.epoch_number.to_string()),
                                ));
                                let shuffle_seed = (shuffle_seed.clone()
                                    / (shuffle_seed + BigDecimal::from(1))) // map between 0-1
                                .to_string() // turn to string
                                .parse::<f64>()
                                .unwrap(); // parse as f64
                                avrio_core::commitee::sort_full_list(
                                    &mut fullnodes,
                                    (shuffle_seed * (u64::MAX as f64)) as u64,
                                );
                                // now form the committees from this shuffled list
                                let mut excluded_nodes: Vec<String> = vec![]; // will contain the publickey of any nodes not included in tis epoch
                                let number_of_committes = 1;
                                let committees: Vec<Comitee> = Comitee::form_comitees(
                                    &mut fullnodes,
                                    &mut excluded_nodes,
                                    number_of_committes,
                                );
                                let mut postshuffle_hash = String::from("");
                                for committee in &committees {
                                    postshuffle_hash =
                                        raw_lyra(&(postshuffle_hash + &committee.hash));
                                }
                                // set the hashes
                                delta_list.0 .0 = preshuffle_hash;
                                delta_list.0 .1 = postshuffle_hash;

                                let mut transaction = Transaction {
                                    hash: String::from(""),
                                    amount: 0,
                                    extra: bs58::encode(
                                        serde_json::to_string(&delta_list).unwrap(),
                                    )
                                    .into_string(),
                                    flag: 'y',
                                    sender_key: lock[0].clone(),
                                    receive_key: String::from("0"),
                                    access_key: String::from(""),
                                    unlock_time: 0,
                                    gas_price: 1,
                                    max_gas: u64::MAX,
                                    nonce: get_nonce(lock[0].clone()),
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64,
                                };
                                transaction.hash();
                                let delta_list_block =
                                    Block::new(vec![transaction], lock[1].clone(), None);
                                let mut delta_list_block_rec = delta_list_block
                                    .form_receive_block(Some(String::from("0")))
                                    .unwrap();
                                let _ = delta_list_block_rec.sign(&lock[1]).unwrap();
                                let blocks = vec![delta_list_block, delta_list_block_rec];
                                for block in &blocks {
                                    trace!("Sending {} to peers", block.hash);
                                    if let Err(prop_err) = prop_block(block) {
                                        error!(
                                            "Failed to send block {} to peers, encounted error={}",
                                            block.hash, prop_err
                                        );
                                        return;
                                    }
                                    add_block(block, CallerM::blank());
                                }
                                // form a block chunk containing the delta list blocks
                                let mut dl_chunk = BlockChunk::form(&blocks, 0).unwrap();
                                trace!("Formed block chunk {:#?}", dl_chunk);
                                propose_premade_chunk(&mut dl_chunk, &get_top_epoch().unwrap())
                                    .unwrap();
                                debug!("All tasks completed, new epoch coordinated!");
                            }
                            Err(error) => {
                                error!("Failed to create salt seed, error={}", error);
                                //TODO: handle this more gracefully
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        error!(
                            "Failed to send epoch salt formation request to all peers, error={}",
                            error
                        );
                    }
                };
            } else {
                debug!(
                    "Not consensus committee round leader, not coordinating epoch salt formation"
                )
            }
        }
        Err(lock_error) => error!(
            "Failed to get mutex lock on FULLNODE_KEYS lazy static, error={}",
            lock_error
        ),
    }
}

pub fn handle_vrf_lottery() {
    info!(
        "VRF lottery started, participating={}",
        config().node_type == 'c'
    );
    if config().node_type != 'c' {
        return;
    }
    let current_epoch = get_top_epoch().unwrap_or_default();
    let next_epoch = Epoch::get(current_epoch.epoch_number + 1).unwrap_or_default();
    let vrf_seed = raw_hash(&(format!("{}{}{}", current_epoch.salt, next_epoch.salt, "-vrflotto")));
    debug!("VRF seed: {}", vrf_seed);
    match get_keys() {
        Ok(lock) => {
            let vrf_proof = get_vrf(lock[1].clone(), vrf_seed).unwrap_or_default();
            // Now we check if the VRF fufills the criteria for eclosion
            // for now this is not done
            let vrf_value = vrf_hash_to_integer(vrf_proof.1);
            info!(
                "Created VRF lottery entry, ticket={:.4}, requirement={}, viable={}",
                vrf_value, 1, true
            );
            // now form a txn, place in block and send to network
            let mut txn = Transaction {
                hash: String::from(""),
                amount: 0,
                extra: bs58::encode(vrf_proof.0).into_string(),
                flag: 'v',
                sender_key: lock[0].clone(),
                receive_key: String::from("0"),
                access_key: String::from(""),
                unlock_time: 0,
                gas_price: 20,
                max_gas: u64::MAX,
                nonce: get_nonce(lock[0].clone()),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time went backwards")
                    .as_millis() as u64,
            };
            txn.hash();
            let block = Block::new(vec![txn], lock[1].clone(), None);
            let rec_block = block
                .form_receive_block(Some(lock[0].clone()))
                .unwrap_or_default();
            let blks = vec![block, rec_block];
            for blk in blks {
                debug!("Handling block={}", blk.hash);
                match blk.valid() {
                    std::result::Result::Ok(_) => {
                        trace!("Block valid");
                        if let Err(block_saving_error) = blk.save() {
                            error!(
                                "Failed to save formed block={}, error={}",
                                blk.hash, block_saving_error
                            );
                        } else if let Err(block_enact_error) = blk.enact() {
                            error!(
                                "Failed to enact formed block={}, error={}",
                                blk.hash, block_enact_error
                            );
                        } else if let Err(block_prop_error) = prop_block(&blk) {
                            error!(
                                "Failed to propagate formed block={}, error={}",
                                blk.hash, block_prop_error
                            );
                        } else {
                            info!("Processed & sent formed block={} to network", blk.hash);
                        }
                    }
                    std::result::Result::Err(block_validation_error) => {
                        error!(
                            "Formed block={} invalid, reason={}",
                            blk.hash, block_validation_error
                        );
                    }
                }
            }
        }
        Err(lock_error) => error!(
            "Failed to get mutex lock on FULLNODE_KEYS lazy static, error={}",
            lock_error
        ),
    }
}
