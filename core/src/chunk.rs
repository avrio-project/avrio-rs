use crate::{
    account::{get_account, to_atomc, Account},
    block::Block,
    epoch::get_top_epoch,
    validate::Verifiable,
};
use avrio_config::config;
use avrio_crypto::Hashable;
use avrio_database::{get_data, save_data};
use bls_signatures::{aggregate, verify_messages, PrivateKey, PublicKey, Serialize, Signature};
use std::convert::TryInto;
#[derive(Debug)]
pub struct BlockChunk {
    pub hash: String,
    pub round: u64,
    pub blocks: Vec<String>,
    pub aggregated_signature: String,
    pub committee: u64,
    pub signers: Vec<PublicKey>,
}

impl Verifiable for BlockChunk {
    fn valid(&self) -> Result<(), Box<dyn std::error::Error>> {
        // check this is not from the consensus committee
        if self.committee == 0 {
            return Err("block chunk from consensus committee".into());
        }
        // first check the hash of the BlockChunk
        if self.hash_item() != self.hash {
            error!(
                "Block chunk for round {} has hash mismatch, claimed_hash={}, calculated_hash={}",
                self.round,
                self.hash,
                self.hash_item()
            );
            return Err("Hash mismatch".into());
        }
        // check its round is correct
        if let Ok(collision) =
            BlockChunk::get_by_round(self.round, get_top_epoch()?.epoch_number, self.committee)
        {
            error!(
                "Chunk {} collides with {} at round {} (committee={}, proposer={:?}, epoch={})",
                self.hash,
                collision.hash,
                self.round,
                self.committee,
                self.signers[0],
                get_top_epoch()?.epoch_number
            );
            return Err("Chunk round collision".into());
        }
        // check there is no colliding round (hashwise)
        if let Ok(collision) = BlockChunk::get(self.hash.clone()) {
            error!(
             "Proposed chunk has collided hash {}, proposed round={}, existing chunk round={} (committee={}, proposer={:?}, epoch={})",
             self.hash,
             self.round,
             collision.round,
             self.committee,
             self.signers[0],
             get_top_epoch()?.epoch_number
         );
            return Err("Chunk hash collision".into());
        }
        // decode the aggregated signature
        match bs58::decode(&self.aggregated_signature).into_vec() {
            Ok(raw_aggregated) => match Signature::from_bytes(&raw_aggregated) {
                Ok(aggregated) => {
                    trace!("Agregated signature={:#?}", aggregated);
                    // now check the signature is valid and has been signed by all the signers
                    if verify_messages(&aggregated, &[self.hash.as_bytes()], &self.signers) {
                        debug!("Aggregated signature on blockchunk {} valid", self.hash);
                        // now check all the signers are part of the committee, and that the len(self.signers) > 2/3committee_size
                        // first get the committee
                        let mut committees = get_top_epoch()?.committees;
                        if committees.len() < (self.committee + 1).try_into().unwrap() {
                            error!("Block chunk has non existant origin committee index={}, current top committee={}", self.committee, committees.len()-1);
                        } else {
                            let committee = committees.remove(self.committee as usize);
                            drop(committees);
                            // now for each signer we get their coorosponding ECDSA publickey and check they are part of the committee
                            for (index, bls_signer) in self.signers.clone().iter().enumerate() {
                                let mut buffer = vec![];
                                if let Err(e) = bls_signer.write_bytes(&mut buffer) {
                                    error!("Failed to write bls publickey bytes to buffer, gave error={}", e);
                                    return Err("Failed to write publickey bytes to buffer".into());
                                } else {
                                    let ecdsa_publickey = get_data(
                                        config().db_path + "/blslookup",
                                        &bs58::encode(&buffer).into_string(),
                                    );
                                    if ecdsa_publickey == "-1" {
                                        error!("Cannot find corrosponding ECDSA publickey for BLS signer {}", &bs58::encode(buffer).into_string());
                                        return Err("Could not find ECDSA counterpart for signers BLS publickey".into());
                                    } else {
                                        if !committee.members.contains(&ecdsa_publickey) {
                                            error!("Committee {} (index={}) does not contain ECDSA counterpart {} of signer {:?}", committee.hash, committee.index, ecdsa_publickey, bls_signer);
                                        } else if index == 0 {
                                            // now check if the block proposer (the first signature in the vec) is the current round leader
                                            if committee.get_round_leader()? != ecdsa_publickey {
                                                return Err("Unauthorised block proposal".into());
                                            }
                                        }
                                    }
                                }
                            }
                            debug!("All signers ECDSA counterparts contained in committee {} (index={})", committee.hash, committee.index);
                        }
                    } else {
                        error!("Block chunk with hash={} (round={}, proposer={:?}) has invalid aggregated signature={}", self.hash, self.round, self.signers[0], self.aggregated_signature);
                        return Err("Invalid aggregate signature".into());
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to decode aggregated signature from bytes, gave error={}",
                        e
                    );
                    return Err("Failed to decode aggregated signature from bytes".into());
                }
            },
            Err(e) => {
                error!(
                    "Failed to decode aggregated signature bytes from base58, gave error={}",
                    e
                );
                return Err("Failed to decode aggregated signature bytes from bs58".into());
            }
        }
        Ok(())
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = self.encode()?;
        if save_data(
            &serialized,
            &(config().db_path + "/blockchunks"),
            self.hash.clone(),
        ) == 1
        {
            return Ok(());
        } else {
            return Err("Failed to save data".into());
        }
    }
    fn get(hash: String) -> Result<Box<BlockChunk>, Box<dyn std::error::Error>> {
        let got_data = get_data(config().db_path + "/blockchunks", &hash);
        if got_data != "-1" {
            return Ok(Box::new(BlockChunk::decode(got_data)?));
        } else {
            return Err("could not find epoch data on disk".into());
        }
    }

    fn enact(&self) -> Result<(), Box<dyn std::error::Error>> {
        let top_epoch = get_top_epoch()?;
        // increase current round for committee
        if save_data(
            &self.round.to_string(),
            &(config().db_path + "/blockchunks"),
            self.committee.to_string() + "-round-" + &top_epoch.epoch_number.to_string(),
        ) == 1
        {
            // save indexes
            if save_data(
                &self.hash,
                &(config().db_path + "/blockchunks"),
                self.round.to_string()
                    + "-"
                    + &top_epoch.epoch_number.to_string()
                    + "-"
                    + &self.committee.to_string(),
            ) == 1
            {
                // Now we calculate the reward for the validators and the proposer:
                // Proposer reward: txn_fees + (base_reward *  (signers_count / commitee size))
                // Validator reward: 5 / signers_count
                let base_reward: u64 = to_atomc(1.0);
                let mut txn_fees: u64 = 0;
                for block_hash in &self.blocks {
                    // get the block
                    let block = Block::get(block_hash.clone())?;
                    for txn in block.txns {
                        txn_fees += txn.fee();
                    }
                }
                // now calculate the percentage of validators who signed the chunk
                let committee = get_top_epoch()?.committees.remove(self.committee as usize);
                let signer_percent = committee.members.len() / self.signers.len();
                let proposer_reward = txn_fees + (base_reward * signer_percent as u64);
                debug!(
                    "Proposer reward for block chunk {}: {}",
                    self.hash, proposer_reward
                );

                // now the validator reward
                let validator_reward = 5 / (self.signers.len() as u64);
                debug!(
                    "Validator reward for block chunk {}: {}",
                    self.hash, validator_reward
                );
                debug!(
                    "Total mint for block chunk {} = {}",
                    self.hash,
                    (base_reward * signer_percent as u64) + 5
                );
                // now apply these rewards
                for (index, bls_signer) in self.signers.clone().iter().enumerate() {
                    let mut buffer = vec![];
                    if let Err(e) = bls_signer.write_bytes(&mut buffer) {
                        error!("Failed to write bls publickey bytes to buffer, gave error={}", e);
                        return Err("Failed to write publickey bytes to buffer".into());
                    } else {
                        let ecdsa_publickey = get_data(
                            config().db_path + "/blslookup",
                            &bs58::encode(&buffer).into_string(),
                        );
                        if ecdsa_publickey == "-1" {
                            error!("Cannot find corrosponding ECDSA publickey for BLS signer {}", &bs58::encode(buffer).into_string());
                            return Err("Could not find ECDSA counterpart for signers BLS publickey".into());
                        } else {
                            if index == 0 {
                                if let Ok(mut proposer) = get_account(&ecdsa_publickey) {
                                    proposer.balance += proposer_reward;
                                } else {
                                    error!("Failed to get proposer {} of block chunk {}'s account", ecdsa_publickey, self.hash);
                                    return Err("Failed to get proposer account".into());
                                }
                            } else {
                                if let Ok(mut validator) = get_account(&ecdsa_publickey) {
                                    validator.balance += validator_reward;
                                } else {
                                    error!("Failed to get validator {} of block chunk {}'s account", ecdsa_publickey, self.hash);
                                    return Err("Failed to get validator account".into());
                                }
                            }
                        }
                    }
                }
                debug!("Applied all rewards for chunk {}", self.hash);

                return Ok(());
            } else {
                return Err("Failed to save data".into());
            }
        } else {
            return Err("Failed to save data".into());
        }
    }
}

impl Hashable for BlockChunk {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.round.to_string().bytes());
        for block in &self.blocks {
            bytes.extend(block.bytes());
        }
        bytes.extend(self.committee.to_string().bytes());
        bytes
    }
}

impl BlockChunk {
    // forms a empty block chunk
    pub fn empty(committee: u64) -> Result<Box<BlockChunk>, Box<dyn std::error::Error>> {
        let top_epoch = get_top_epoch()?;
        let top_round_index: u64 = get_data(
            config().db_path + "/blockchunks",
            &(committee.to_string() + "-round-" + &top_epoch.epoch_number.to_string()),
        )
        .parse()?;
        let mut top = BlockChunk::get_by_round(top_round_index, top_epoch.epoch_number, committee)?;
        top.blocks = vec![];
        top.aggregated_signature = String::from("");
        top.signers = vec![];
        top.hash = top.hash_item();
        Ok(top)
    }
    pub fn form(
        blocks: &Vec<Block>,
        committee: u64,
    ) -> Result<Box<BlockChunk>, Box<dyn std::error::Error>> {
        let top_epoch = get_top_epoch()?;
        let top_round_index: u64 = get_data(
            config().db_path + "/blockchunks",
            &(committee.to_string() + "-round-" + &top_epoch.epoch_number.to_string()),
        )
        .parse()?;
        let mut top = BlockChunk::get_by_round(top_round_index, top_epoch.epoch_number, committee)?;
        top.blocks = vec![];
        top.aggregated_signature = String::from("");
        top.signers = vec![];
        for block in blocks {
            top.blocks.push(block.hash.to_string());
        }
        top.hash = top.hash_item();
        Ok(top)
    }

    pub fn sign(&self, privatekey: PrivateKey) -> Signature {
        privatekey.sign(self.hash.to_owned())
    }

    pub fn add_signatures(
        &mut self,
        signatures: &Vec<Signature>,
        signers: Vec<PublicKey>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // aggregate all sigs
        self.aggregated_signature =
            bs58::encode(aggregate(&signatures[..])?.as_bytes()).into_string();
        self.signers = signers;
        Ok(())
    }

    pub fn get_by_round(
        round: u64,
        epoch: u64,
        committee: u64,
    ) -> Result<Box<BlockChunk>, Box<dyn std::error::Error>> {
        let got_data = get_data(
            config().db_path + "/blockchunks",
            &(round.to_string() + "-" + &epoch.to_string() + "-" + &committee.to_string()),
        );
        if got_data != "-1" {
            return BlockChunk::get(got_data);
        } else {
            return Err("Chunk does not exist".into());
        }
    }
    pub fn encode(&self) -> Result<String, Box<dyn std::error::Error>> {
        Ok(bs58::encode(format!(
            "{}|{}|{}|{}|{}|{}",
            self.hash,
            self.round,
            serde_json::to_string(&self.blocks)?,
            self.committee,
            self.aggregated_signature,
            serde_json::to_string(&signers_to_string_vec(&self.signers)?)?,
        ))
        .into_string())
    }
    pub fn decode(raw: String) -> Result<BlockChunk, Box<dyn std::error::Error>> {
        let decoded = String::from_utf8(bs58::decode(raw).into_vec()?)?;
        let split: Vec<&str> = decoded.split("|").collect();
        if split.len() == 6 {
            return Ok(BlockChunk {
                hash: split[0].to_string(),
                round: split[1].parse()?,
                blocks: serde_json::from_str(&split[2])?,
                aggregated_signature: split[3].to_string(),
                committee: split[4].parse()?,
                signers: signers_string_to_vec(&serde_json::from_str(&split[5])?)?,
            });
        } else {
            return Err("Wrong split length".into());
        }
    }
}

// encode and decode helper functions
pub fn bls_publickey_to_string(key: &PublicKey) -> Result<String, Box<dyn std::error::Error>> {
    let mut buffer = vec![];
    if let Err(e) = key.write_bytes(&mut buffer) {
        error!(
            "Failed to write bls publickey bytes to buffer, gave error={}",
            e
        );
        return Err("Failed to write publickey bytes to buffer".into());
    }
    Ok(String::from(bs58::encode(buffer).into_string()))
}

pub fn signers_to_string_vec(
    signers: &Vec<PublicKey>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut res = vec![];
    for signer in signers {
        res.push(bls_publickey_to_string(signer)?);
    }
    Ok(res)
}

pub fn string_to_bls_publickey(
    as_string: &String,
) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let as_bytes = bs58::decode(as_string).into_vec()?;
    return Ok(PublicKey::from_bytes(&as_bytes)?);
}

pub fn signers_string_to_vec(
    signers: &Vec<String>,
) -> Result<Vec<PublicKey>, Box<dyn std::error::Error>> {
    let mut out: Vec<PublicKey> = vec![];
    for signer_string in signers {
        out.push(string_to_bls_publickey(signer_string)?);
    }
    return Ok(out);
}
