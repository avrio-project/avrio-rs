use avrio_core::{account::get_nonce, certificate::Certificate, commitee::Comitee};
use avrio_crypto::raw_lyra;
use avrio_p2p::guid::form_table;
use std::time::Duration;
// contains functions called by the fullnode
use crate::*;

lazy_static! {
    static ref VRF_LOTTO_ENTRIES: Mutex<Vec<(String, String)>> = Mutex::new(vec![]);
}
// calculates the reward amount for this epoch, collects the proofs and forms a reward txn before broadcasting
// Returns any errors encountered, or the atomic amount
pub fn claim_reward() -> Result<u64, Box<dyn std::error::Error>> {
    // TODO: write reward code
    Ok(0)
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
            let mut blocks: Vec<Block> = vec![seed_block, seed_block_rec];

            // create the shuffle bits
            let top_epoch = get_top_epoch()?;
            let new_epoch = Epoch::get(top_epoch.epoch_number + 1)?;
            let (shuffle_proof, _) = get_vrf(
                lock[5].clone(),
                raw_lyra(&(new_epoch.salt.to_string() + &new_epoch.epoch_number.to_string() + &lock[0])),
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
            let delta_list: ((String, String), Vec<(String, u8, String)>) =
                ((raw_lyra(&lock[0]), raw_lyra(&top_epoch.committees[0].hash)), vec![]);

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
                        let candidate_count = 0; // TODO: get candidate count
                        if lock.len() == candidate_count {
                            info!("All candidates eclosed, finishing VrfLotto stage early");
                            // TODO: Proceed to next stage
                        }
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
                // get the round leader's publickey, calculate GUID from that
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
