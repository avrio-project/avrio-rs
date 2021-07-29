use avrio_core::{
    account::get_nonce,
    certificate::get_fullnode_count,
    chunk::{string_to_bls_privatkey, BlockChunk},
    commitee::Comitee,
    mempool,
};
use avrio_crypto::raw_lyra;
use avrio_p2p::guid::{self, form_table};
use bls_signatures::{Serialize, Signature};
use std::{thread::sleep, time::Duration};
// contains functions called by the fullnode
use crate::*;
use avrio_core::mempool::MEMPOOL;
use avrio_rpc::LOCAL_CALLBACKS;
lazy_static! {
    static ref VRF_LOTTO_ENTRIES: Mutex<Vec<(String, String)>> = Mutex::new(vec![]);
    static ref COMMITEE_INDEX: Mutex<u64> = Mutex::new(1025);
}

/// # Validator Loop
/// Called at the start of the main loop, calls the correct functions (for proposing and validating block chunks) then returns either an error (if enountered) or the number of chunks proposed and validated (in a tuple)
pub fn validator_loop() -> Result<(u64, u64), Box<dyn std::error::Error>> {
    Ok((0, 0))
}

pub fn handle_proposed_chunk(
    chunk: BlockChunk,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    match FULLNODE_KEYS.lock() {
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
    match FULLNODE_KEYS.lock() {
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
    match FULLNODE_KEYS.lock() {
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
            // now ask each of our GUID peers to sign our chunk, as well as send it to their GUID peers to sign
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

pub fn start_genesis_epoch() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting genesis epoch");
    // create the salt from just our VRF
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
            let seeds = vec![(lock[0].clone(), proof)];
            // form txn
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
            sleep(Duration::from_millis(60000)); // wait a single minute
                                                 // now we can proceed
            let mut blocks: Vec<Block> = vec![];

            // create the shuffle bits
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

            // create an empty fullnode delta list txn
            let delta_list: ((String, String), Vec<(String, u8, String)>) = (
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
    match FULLNODE_KEYS.lock() {
        Ok(lock) => {
            let top_epoch = get_top_epoch().unwrap();
            // check if we are the round leader for the consensus commitee
            let round_leader = top_epoch.committees[0]
                .get_round_leader()
                .unwrap_or_default();
            let ticket_hash =
                raw_hash(&format!("{}{}{}", txn.hash, txn.sender_key, txn.extra))[0..5].to_string();
            if round_leader == lock[0] {
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
                match VRF_LOTTO_ENTRIES.lock() {
                    Ok(mut lock) => {
                        lock.push((txn.sender_key.clone(), txn.hash));
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
    create_timer(
        Duration::from_millis(config().target_epoch_length),
        Box::new(start_vrf_lotto),
        (),
    );
    match FULLNODE_KEYS.lock() {
        Ok(lock) => {
            let current_epoch = get_top_epoch().unwrap_or_default();
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
    match FULLNODE_KEYS.lock() {
        Ok(lock) => {
            let current_epoch = get_top_epoch().unwrap_or_default();
            if current_epoch.committees[0]
                .get_round_leader()
                .unwrap_or_default()
                == lock[0]
            {
                info!("Consensus committee round leader, coordinating epoch salt formation");
                // TODO: Send a generateEpochSalt p2p message to every peer in our GUID, collect the responses, then form a announceSaltSeeds txn and process
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
    match FULLNODE_KEYS.lock() {
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
