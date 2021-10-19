use serde::{Deserialize, Serialize};
extern crate hex;
use avrio_crypto::{raw_hash, Hashable};
extern crate avrio_config;
extern crate bs58;
use avrio_config::config;
extern crate rand;
use avrio_database::{get_data, save_data};
use thiserror::Error;
extern crate avrio_database;

use crate::{
    account::{get_account, open_or_create, Accesskey, Account},
    certificate::Certificate,
    chunk::BlockChunk,
    commitee::{sort_full_list, Comitee},
    epoch::{get_top_epoch, Epoch, EpochStage},
    gas::*,
    invite::{invite_valid, new_invite},
    validate::Verifiable,
};

use avrio_crypto::{proof_to_hash, raw_lyra, validate_vrf, vrf_hash_to_integer};
use bigdecimal::{BigDecimal, FromPrimitive};
use lazy_static::lazy_static;
use std::{
    collections::HashSet,
    iter::FromIterator,
    str::FromStr,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

lazy_static! {
    /// Called when the VRF lottery starts
    pub static ref VRF_LOTTERY_CALLBACKS: Mutex<Vec<Box<dyn Fn() + Send >>> = Mutex::new(vec![]);
    /// Called when a VRF lottery entry is submited
    pub static ref VRF_TICKET_SUBMITTED: Mutex<Vec<Box<dyn Fn(Transaction) + Send >>> = Mutex::new(vec![]);
    /// Called when a new epoch is started (when the announceFulllnodeDEltaList txn is enacted)
    pub static ref EPOCH_STARTED_CALLBACKS: Mutex<Vec<Box<dyn Fn() -> Result<bool, Box<dyn std::error::Error>> + Send  >>> = Mutex::new(vec![]);
}

#[derive(Debug, Error)]
pub enum TransactionValidationErrors {
    #[error("Tried to create an existing invite")]
    InviteAlreadyExists,
    #[error("Non fullnode tred to create invite")]
    NotFullNode,
    #[error("Transaction with hash already exists")]
    TransactionExists,
    #[error("Failed to read sender acc from disk")]
    CouldNotGetSenderAcc,
    #[error("Failed to read reciever account from disk")]
    CouldNotGetRecieverAcc,
    #[error("Involved account missing")]
    AccountMissing,
    #[error("Transaction nonce invalid")]
    BadNonce,
    #[error("Balance low")]
    InsufficentBalance,
    #[error("Involved access key missing")]
    AccesskeyMissing,
    #[error("Gas price low")]
    GasPriceLow,
    #[error("Gas used is over max gas")]
    MaxGasExpended,
    #[error("Amount too low")]
    InsufficentAmount,
    #[error("Signature invalid")]
    BadSignature,
    #[error("Publickey invalid")]
    BadPublicKey,
    #[error("Transaction too large")]
    TooLarge,
    #[error("Timestamp bad")]
    BadTimestamp,
    #[error("Burn for username lower than expected")]
    InsufficentBurnForUsername,
    #[error("Bad unlocktime")]
    BadUnlockTime,
    #[error("Certificate invalid: {0}")]
    InvalidCertificate(Box<dyn std::error::Error>),
    #[error("Hash invalid")]
    BadHash,
    #[error("Non message type, but no recipient")]
    NonMessageWithoutRecipitent,
    #[error("Transaction extra too large for type")]
    ExtraTooLarge,
    #[error("Gas too low")]
    LowGas,
    #[error("Transaction flag/type unknown")]
    UnsupportedType,
    #[error("Extra contains illegal charactor")]
    ExtraNotAlphanumeric,
    #[error("Transaction would overflow recievers balance")]
    WouldOverflowBalance,
    #[error("Invite invalid")]
    InviteInvalid,
    #[error("Not round leader, but sent consensus message")]
    UnauthorisedConsensusMessage,
    #[error("Sent consensus message has wrong reciever")]
    WrongRecieverConsensusMessage,
    #[error("Sent consensus message with non 0 amount")]
    WrongAmountRecieverConsensusMessage,
    #[error("Sent consensus message contains invalid VRF")]
    InvalidVrf,
    #[error("Could not decode VRF proof and signer from announceEpochSaltSeedTxn")]
    FailedToDecodeSaltSeeds,
    #[error("Hashed preshuffle node list does not equal expected hash")]
    BadPreshuffleHash,
    #[error("Hashed post shuffle committee list does not equal expected hash")]
    BadShuffledHash,
    #[error("Vrf lotto entry ticket sent outside of Vrf Lotto period")]
    TicketSentOutsideVrfLotto,
    #[error("Vrf lotto entry ticket sent by non-candidate wallet")]
    NotCandidate,
    #[error("Reported fullnode not in commitee")]
    NotInCommitee,
    #[error("Report role type unknown")]
    UnknownRoleType,
    #[error("Other")]
    Other,
}

impl Default for TransactionValidationErrors {
    fn default() -> TransactionValidationErrors {
        TransactionValidationErrors::Other
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Transaction {
    pub hash: String,
    pub amount: u64,
    pub extra: String,
    pub flag: char,
    pub sender_key: String,
    pub receive_key: String,
    pub access_key: String,
    pub unlock_time: u64,
    pub gas_price: u64,
    pub max_gas: u64,
    pub nonce: u64,
    pub timestamp: u64,
}

impl Hashable for Transaction {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend((self.amount.to_string()).bytes());
        bytes.extend((self.extra.to_owned()).bytes());
        bytes.extend(self.flag.to_string().bytes());
        bytes.extend(self.sender_key.bytes());
        bytes.extend(self.receive_key.bytes());
        bytes.extend(self.access_key.as_bytes());
        bytes.extend(self.unlock_time.to_string().as_bytes());
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes.extend((self.nonce.to_owned().to_string()).bytes());
        bytes
    }
}
impl Verifiable for Transaction {
    fn valid(&self) -> Result<(), Box<dyn std::error::Error>> {
        trace!("Validating txn with hash: {}", self.hash);
        let start = SystemTime::now();
        let sender_account: Account;
        if self.sender_key.len() < 44 {
            // public keys are 44 bytes long, check if sender key is a public key or a username
            match get_account(&self.sender_key) {
                Ok(got_account) => sender_account = got_account,
                Err(e) => {
                    error!(
                        "Failed to get sender's account by publickey: sender_key={}, error={}",
                        self.sender_key, e
                    );
                    return Err(Box::new(TransactionValidationErrors::CouldNotGetSenderAcc));
                }
            }
        } else {
            match get_account(&self.sender_key) {
                Ok(got_account) => sender_account = got_account,
                Err(e) => {
                    error!(
                        "Failed to get sender's account by username: sender_key={}, error={}",
                        self.sender_key, e
                    );
                    return Err(Box::new(TransactionValidationErrors::CouldNotGetSenderAcc));
                }
            }
        }
        if self.hash_return() != self.hash {
            return Err(Box::new(TransactionValidationErrors::BadHash));
        }
        let account_nonce = get_data(
            config().db_path
                + &"/chains/".to_owned()
                + &self.sender_key
                + &"-chainindex".to_owned(),
            &"txncount".to_owned(),
        );
        if self.nonce.to_string() != account_nonce && account_nonce != "-1" {
            return Err(Box::new(TransactionValidationErrors::BadNonce));
        }
        let block_txn_is_in = get_data(config().db_path + &"/transactions".to_owned(), &self.hash);
        if block_txn_is_in != *"-1" {
            error!(
                "Transaction {} already in block {}",
                self.hash, block_txn_is_in
            );
            return Err(Box::new(TransactionValidationErrors::TransactionExists));
        }
        if !['c', 'n', 'b', 'u', 'l', 'i', 'f', 'a', 'y', 'z', 'v'].contains(&self.flag) {
            error!(
                "Transaction {} has unsupported type={} ({})",
                self.hash,
                self.flag,
                self.type_transaction()
            );
            return Err(Box::new(TransactionValidationErrors::UnsupportedType));
        }
        if !self.extra.chars().all(char::is_alphanumeric) {
            error!("Transaction {} has non alphanumeric extra field", self.hash);
            return Err(Box::new(TransactionValidationErrors::ExtraNotAlphanumeric));
        }
        let gas_price_min = 1; // todo move to config
        if self.gas_price <= gas_price_min && !self.consensus_type() {
            error!(
                "Transaction {}'s gas price too low ({} < {})",
                self.hash, self.gas_price, gas_price_min
            );
            return Err(Box::new(TransactionValidationErrors::GasPriceLow));
        }
        match self.flag {
            'n' => {
                let size_of_extra = self.extra.len();
                if size_of_extra > 100 {
                    error!(
                        "Normal type transaction {}'s extra ({}) too large, {} > 100",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(Box::new(TransactionValidationErrors::ExtraTooLarge));
                }
                if self.amount < 1 {
                    error!("Transaction {} amount too small", self.hash);
                    return Err(Box::new(TransactionValidationErrors::InsufficentAmount));
                }
                if sender_account.balance < (self.amount + (self.gas() * self.gas_price)) {
                    error!("Sender {} of transaction {}'s balance too low, amount {} fee={} ({} * {}), required delta={}", sender_account.public_key, self.hash, self.amount, self.gas() * self.gas_price, self.gas() , self.gas_price, (self.amount + (self.gas() * self.gas_price)) - sender_account.balance);
                    return Err(Box::new(TransactionValidationErrors::InsufficentBalance));
                }
                let receiver_account: Account;
                if self.sender_key.len() < 44 {
                    // public keys are 44 bytes long, check if receive key is a public key or a username
                    match get_account(&self.receive_key) {
                        Ok(got_account) => receiver_account = got_account,
                        Err(e) => {
                            error!(
                                "Failed to get receiver's account by publickey: receive_key={}, error={}",
                                self.receive_key, e
                            );
                            return Err(Box::new(
                                TransactionValidationErrors::CouldNotGetSenderAcc,
                            ));
                        }
                    }
                } else {
                    match get_account(&self.receive_key) {
                        Ok(got_account) => receiver_account = got_account,
                        Err(e) => {
                            error!(
                                "Failed to get receiver's account by username: receive_key={}, error={}",
                                self.receive_key, e
                            );
                            return Err(Box::new(
                                TransactionValidationErrors::CouldNotGetSenderAcc,
                            ));
                        }
                    }
                }
                if (u64::MAX - receiver_account.balance) < self.amount {
                    // check the reciever's balance will not surpass u64::MAX after this tranaction and overflow (this is only really a concern with the testnet which has CLAIM transactions)
                    error!("Transaction {} would overflow receiver {}'s balance: Current={}, safe_left={}, txn_amount={}", self.hash, self.receive_key, receiver_account.balance, (u64::MAX - receiver_account.balance), self.amount);
                    return Err(Box::new(TransactionValidationErrors::WouldOverflowBalance));
                }
                if self.max_gas < self.gas() {
                    error!(
                        "Transaction {} max_gas expended, max_gas={}, used_gas={}",
                        self.hash,
                        self.max_gas,
                        self.gas()
                    );
                    return Err(Box::new(TransactionValidationErrors::MaxGasExpended));
                }
                if self.unlock_time != 0 {
                    return Err(Box::new(TransactionValidationErrors::UnsupportedType));
                    // TODO: Implement unlock time
                }
            }
            'c' => {
                let size_of_extra = self.extra.len();
                if size_of_extra != 0 {
                    error!(
                        "Claim type transaction {}'s extra ({}) not zero, {} != 0",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(Box::new(TransactionValidationErrors::ExtraTooLarge));
                }
                if self.amount < 1 {
                    error!("Transaction {} amount too small", self.hash);
                    return Err(Box::new(TransactionValidationErrors::InsufficentAmount));
                }
                if (u64::MAX - sender_account.balance) < self.amount {
                    // check the reciever's balance will not surpass u64::MAX after this tranaction and overflow (this is only really a concern with the testnet which has CLAIM transactions)
                    error!("Claim transaction {} would overflow sender's {}'s balance: Current={}, safe_left={}, txn_amount={}", self.hash, self.receive_key, sender_account.balance, (u64::MAX - sender_account.balance), self.amount);
                    return Err(Box::new(TransactionValidationErrors::WouldOverflowBalance));
                }
                if self.unlock_time != 0 {
                    return Err(Box::new(TransactionValidationErrors::UnsupportedType));
                    // TODO: Implement unlock time
                }
            }
            'u' => {
                let size_of_extra = self.extra.len();
                if size_of_extra > 20 {
                    error!(
                        "Username registration type transaction {}'s extra ({}) too large, {} > 20",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(Box::new(TransactionValidationErrors::ExtraTooLarge));
                }
                if self.max_gas < self.gas() {
                    error!(
                        "Transaction {} max_gas expended, max_gas={}, used_gas={}",
                        self.hash,
                        self.max_gas,
                        self.gas()
                    );
                    return Err(Box::new(TransactionValidationErrors::MaxGasExpended));
                }
                if self.unlock_time != 0 {
                    return Err(Box::new(TransactionValidationErrors::UnsupportedType));
                    // TODO: Implement unlock time
                }
            }
            'b' => {
                let size_of_extra = self.extra.len();
                if size_of_extra > 100 {
                    error!(
                        "Burn type transaction {}'s extra ({}) too large, {} > 100",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(Box::new(TransactionValidationErrors::ExtraTooLarge));
                }
                if self.amount < 1 {
                    error!("Burn transaction {} amount too small", self.hash);
                    return Err(Box::new(TransactionValidationErrors::InsufficentAmount));
                }
                if sender_account.balance < (self.amount + (self.gas() * self.gas_price)) {
                    error!("Sender {} of transaction {}'s balance too low, amount {} fee={} ({} * {}), required delta={}", sender_account.public_key, self.hash, self.amount, self.gas() * self.gas_price, self.gas() , self.gas_price, (self.amount + (self.gas() * self.gas_price)) - sender_account.balance);
                    return Err(Box::new(TransactionValidationErrors::InsufficentBalance));
                }
                if self.max_gas < self.gas() {
                    error!(
                        "Transaction {} max_gas expended, max_gas={}, used_gas={}",
                        self.hash,
                        self.max_gas,
                        self.gas()
                    );
                    return Err(Box::new(TransactionValidationErrors::MaxGasExpended));
                }
                if self.unlock_time != 0 {
                    return Err(Box::new(TransactionValidationErrors::UnsupportedType));
                }
            }
            'l' => {
                let size_of_extra = self.extra.len();
                if size_of_extra > 100 {
                    error!(
                        "Lock type transaction {}'s extra ({}) too large, {} > 100",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(Box::new(TransactionValidationErrors::ExtraTooLarge));
                }
                if self.amount < 1 {
                    error!("Lock transaction {} amount too small", self.hash);
                    return Err(Box::new(TransactionValidationErrors::InsufficentAmount));
                }
                if sender_account.balance < (self.amount + (self.gas() * self.gas_price)) {
                    error!("Sender {} of transaction {}'s balance too low, amount {} fee={} ({} * {}), required delta={}", sender_account.public_key, self.hash, self.amount, self.gas() * self.gas_price, self.gas() , self.gas_price, (self.amount + (self.gas() * self.gas_price)) - sender_account.balance);
                    return Err(Box::new(TransactionValidationErrors::InsufficentBalance));
                }

                if self.max_gas < self.gas() {
                    error!(
                        "Transaction {} max_gas expended, max_gas={}, used_gas={}",
                        self.hash,
                        self.max_gas,
                        self.gas()
                    );
                    return Err(Box::new(TransactionValidationErrors::MaxGasExpended));
                }
                if self.unlock_time != 0 {
                    return Err(Box::new(TransactionValidationErrors::UnsupportedType));
                    // TODO: Implement unlock time
                }
            }
            'i' => {
                let size_of_extra = self.extra.len();
                if size_of_extra != 44 {
                    error!(
                        "Create invite type transaction {}'s extra ({}) wrong size, {} != 44",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(Box::new(TransactionValidationErrors::ExtraTooLarge));
                }
                // check if the sender is a fullnode
                if get_data(config().db_path + "/candidates", &self.sender_key) != "f" {
                    error!("Non fullnode {} tried to create a invite", self.sender_key);
                    return Err(Box::new(TransactionValidationErrors::NotFullNode));
                }
                // check the invite does not already exist
                if get_data(config().db_path + &"/invites".to_owned(), &self.extra) != "-1" {
                    error!(
                        "Fullnode {} tried creating an invite that already exists ({})",
                        self.sender_key, self.extra
                    );
                    return Err(Box::new(TransactionValidationErrors::InviteAlreadyExists));
                }
                // check the invite is valid format (len = 44, can be decoded into a valid public key)
                if !invite_valid(&self.extra) {
                    error!(
                        "Invite: {} (created by {}) is invalid",
                        self.extra, self.sender_key
                    );
                    return Err(Box::new(TransactionValidationErrors::InviteInvalid));
                }
            }
            'o' => {
                let size_of_extra = self.extra.len();
                if size_of_extra != 0 {
                    error!(
                        "Toggle participation type transaction {}'s extra ({}) wrong size, {} > 0",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(Box::new(TransactionValidationErrors::ExtraTooLarge));
                }
                // check if the sender is a fullnode
                if get_data(config().db_path + "/candidates", &self.sender_key) != "f" {
                    error!(
                        "Non fullnode {} tried to toggle participation",
                        self.sender_key
                    );
                    return Err(Box::new(TransactionValidationErrors::NotFullNode));
                }
            }
            'o' => {
                let size_of_extra = self.extra.len();
                if size_of_extra >= 200 {
                    error!(
                        "Propose penalty type transaction {}'s extra ({}) wrong size, {} >= 200",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(Box::new(TransactionValidationErrors::ExtraTooLarge));
                }
                // check if the sender is a fullnode
                if get_data(config().db_path + "/candidates", &self.sender_key) != "f" {
                    error!(
                        "Non fullnode {} tried to report {}",
                        self.sender_key, self.receive_key
                    );
                    return Err(Box::new(TransactionValidationErrors::NotFullNode));
                }
                // check if the reciever (node being reported) is a fullnode
                if get_data(config().db_path + "/candidates", &self.receive_key) != "f" {
                    error!(
                        "Non fullnode {} reported by {}",
                        self.receive_key, self.sender_key
                    );
                    return Err(Box::new(TransactionValidationErrors::NotFullNode));
                }
                if let Some(commitee) = Comitee::find_for(&self.receive_key) {
                    // get each reported round and see if the fullnode did miss it
                    let rounds: Vec<(u64, u8)> = serde_json::from_str(&String::from_utf8(
                        bs58::decode(&self.extra).into_vec()?,
                    )?)?;
                    let mut proposal_misses = 0;
                    let mut validation_misses = 0;

                    const MAX_PROPOSAL_MISSES: u64 = 10; // each round you have a 1 in c chance of being the proposer, this means 10 missed proposals  = approx c * 100 secconds // TODO: move to config
                    const MAX_VALIDATION_MISSES: u64 = 20; // Higher because a group malice proposer could purposfully gang up on one signer and exculde them // TODO: move to config

                    for (round, role) in rounds {
                        trace!(
                            "Testing {}'s participation for round {}",
                            self.receive_key,
                            round
                        );
                        let chunk = BlockChunk::get_by_round(
                            round,
                            get_top_epoch()?.epoch_number,
                            commitee,
                        )?;
                        // role = 0: Validatior,role = 1: Proposer
                        if role == 1 {
                            // check if the node was participating at this round by getting a list of participating switches from DB

                            // check if the proposer was infact this node
                            // TODO: Check the node really was meant to propose this block
                            if chunk.proposer()? != self.receive_key {
                                trace!(
                                    "{} did miss proposal of round {} chunk ({} proposal misses out of max {})",
                                    self.receive_key,
                                    round,
                                    proposal_misses,
                                    MAX_PROPOSAL_MISSES
                                );
                                proposal_misses += 1;
                            } else {
                                trace!(
                                    "{} did not miss proposal of round {} chunk, produced {} (claimed by {})",
                                    self.receive_key,
                                    round,
                                    chunk.hash,
                                    self.sender_key
                                )
                            }
                        } else if role == 0 {
                            // check if the node signed this round
                            // TODO: Check the node really was able to sign this block
                            if chunk.proposer()? != self.receive_key {
                                trace!(
                                    "{} did miss signing during round {} ({} validation misses out of max {})",
                                    self.receive_key,
                                    round,
                                    validation_misses,
                                    MAX_VALIDATION_MISSES
                                );
                                validation_misses += 1;
                            } else {
                                trace!(
                                    "{} did not miss signing during round {}, signed {} (claimed by {})",
                                    self.receive_key,
                                    round,
                                    chunk.hash,
                                    self.sender_key
                                )
                            }
                        } else {
                            error!("Unknown role type {}", role);
                            return Err(Box::new(TransactionValidationErrors::UnknownRoleType));
                        }
                    }
                } else {
                    error!("Reported fullnode {}, not in commitee", self.receive_key);
                    return Err(Box::new(TransactionValidationErrors::NotInCommitee));
                }
            }
            'f' => {
                let base_decoded = String::from_utf8(bs58::decode(&self.extra).into_vec()?)?;
                match serde_json::from_str::<Certificate>(&base_decoded) {
                    Ok(cert) => {
                        if let Err(e) = cert.valid() {
                            error!("Invalid fullnode register certificate {} in transaction {} by sender {}, error={:#?}", cert.hash, self.hash, self.sender_key, e);
                            return Err(Box::new(TransactionValidationErrors::InvalidCertificate(
                                e,
                            )));
                        }
                    }
                    Err(e) => {
                        error!("Failed to decode certificate, gave error: {}", e);
                        return Err(Box::new(TransactionValidationErrors::InvalidCertificate(
                            Box::new(e),
                        )));
                    }
                }
            }
            'a' => {
                let top_epoch = get_top_epoch().unwrap_or_default();
                let consensus_round_leader = top_epoch.committees[0].get_round_leader().unwrap();
                if self.sender_key != consensus_round_leader {
                    return Err(Box::new(
                        TransactionValidationErrors::UnauthorisedConsensusMessage,
                    ));
                } else if self.receive_key != "0" {
                    return Err(Box::new(
                        TransactionValidationErrors::WrongRecieverConsensusMessage,
                    ));
                }
                if self.amount != 0 {
                    return Err(Box::new(
                        TransactionValidationErrors::WrongAmountRecieverConsensusMessage,
                    ));
                }
                match serde_json::from_str::<Vec<(String, String)>>(&String::from_utf8(
                    bs58::decode(&self.extra).into_vec()?,
                )?) {
                    Ok(salt_seeds) => {
                        debug!("Decoded salt_seeds={:#?}", salt_seeds);

                        let mut message = String::from("genesis");
                        if top_epoch.epoch_number != 0 {
                            message = raw_lyra(&(top_epoch.epoch_number.to_string() + "epoch"))
                        }
                        for (publickey, seed) in salt_seeds {
                            trace!("Validating seed {}", seed);
                            // get the secp256k1 publickey for this salter
                            let cert = Certificate::get(publickey)?;
                            if !validate_vrf(
                                cert.secp256k1_publickey.clone(),
                                seed.clone(),
                                message.clone(),
                            ) {
                                error!("Invalid VRF as epoch salt seed, proof={}, creator={}, message={}", seed, cert.secp256k1_publickey, message);
                                return Err(Box::new(TransactionValidationErrors::InvalidVrf));
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to decode epoch salt seeds from extra ({}) in txn {}, gave error={}", self.extra, self.hash, e);
                        return Err(Box::new(
                            TransactionValidationErrors::FailedToDecodeSaltSeeds,
                        ));
                    }
                }
            }
            'y' => {
                let consensus_round_leader = get_top_epoch().unwrap_or_default().committees[0]
                    .get_round_leader()
                    .unwrap();
                if self.sender_key != consensus_round_leader {
                    return Err(Box::new(
                        TransactionValidationErrors::UnauthorisedConsensusMessage,
                    ));
                } else if self.receive_key != "0" {
                    return Err(Box::new(
                        TransactionValidationErrors::WrongRecieverConsensusMessage,
                    ));
                }
                if self.amount != 0 {
                    return Err(Box::new(
                        TransactionValidationErrors::WrongAmountRecieverConsensusMessage,
                    ));
                }
                match serde_json::from_str::<((String, String), Vec<(String, u8, String)>)>(
                    &String::from_utf8(bs58::decode(&self.extra).into_vec()?)?,
                ) {
                    Ok((hashes, delta_list)) => {
                        debug!("Decoded fullnode delta list, len={}, expected preshuffle_hash={}, expected postshuffle_hash={}", delta_list.len(), hashes.0, hashes.1);
                        trace!(
                            "fullnode_delta_list={:#?}, hashes: {:#?}",
                            delta_list,
                            hashes
                        );
                        let top_epoch = get_top_epoch()?;
                        let mut fullnodes_hashset: HashSet<String> = HashSet::new();
                        for committee in top_epoch.committees {
                            for fullnode in committee.members {
                                fullnodes_hashset.insert(fullnode);
                            }
                        }
                        for delta in delta_list {
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
                                } else {
                                    error!("Fullnode set did not contain node removed by delta entry, delta entry={:?}", delta);
                                }
                            } else {
                                // eclose a candidate
                                fullnodes_hashset.insert(delta.0.clone());
                                // now update their on disk flag to validator, from candidate
                                if save_data(
                                    "f",
                                    &(config().db_path + "/candidates"),
                                    delta.0.clone(),
                                ) != 1
                                {
                                    return Err("failed to save new fullnode candidate".into());
                                }
                            }
                        }
                        let mut fullnodes: Vec<String> = Vec::from_iter(fullnodes_hashset);
                        let mut preshuffle_hash = String::from("");
                        for fullnode in &fullnodes {
                            preshuffle_hash = raw_lyra(&(preshuffle_hash + fullnode));
                        }
                        if preshuffle_hash != hashes.0 {
                            error!("Preshuffle hash (after delta) does not equal expected, expected={}, got={}", hashes.0, preshuffle_hash);
                            return Err(Box::new(TransactionValidationErrors::BadPreshuffleHash));
                        }
                        // now we shuffle the list
                        let curr_epoch = Epoch::get(top_epoch.epoch_number + 1)?;
                        let shuffle_seed = vrf_hash_to_integer(raw_lyra(
                            &(curr_epoch.shuffle_bits.to_string()
                                + &curr_epoch.salt.to_string()
                                + &curr_epoch.epoch_number.to_string()),
                        ));
                        let shuffle_seed = (shuffle_seed.clone()
                            / (shuffle_seed + BigDecimal::from(1))) // map between 0-1
                        .to_string() // turn to string
                        .parse::<f64>()?; // parse as f64
                        sort_full_list(&mut fullnodes, (shuffle_seed * (u64::MAX as f64)) as u64);
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
                            postshuffle_hash = raw_lyra(&(postshuffle_hash + &committee.hash));
                        }
                        if postshuffle_hash != hashes.1 {
                            error!("Post shuffle committee list hash does not equal expected, expected={}, got={}", hashes.1, postshuffle_hash);
                            return Err(Box::new(TransactionValidationErrors::BadShuffledHash));
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to decode delta list from txn extra, got error={}",
                            e
                        );
                    }
                }
            }
            'z' => {
                let consensus_round_leader = get_top_epoch().unwrap_or_default().committees[0]
                    .get_round_leader()
                    .unwrap();
                if self.sender_key != consensus_round_leader {
                    return Err(Box::new(
                        TransactionValidationErrors::UnauthorisedConsensusMessage,
                    ));
                } else if self.receive_key != "0" {
                    return Err(Box::new(
                        TransactionValidationErrors::WrongRecieverConsensusMessage,
                    ));
                }
                if self.amount != 0 {
                    return Err(Box::new(
                        TransactionValidationErrors::WrongAmountRecieverConsensusMessage,
                    ));
                }
                let top_epoch = get_top_epoch()?;
                let new_epoch = Epoch::get(top_epoch.epoch_number + 1)?;
                let round_leader = top_epoch.committees[0].get_round_leader()?;
                let message = &(new_epoch.salt.to_string()
                    + &new_epoch.epoch_number.to_string()
                    + &round_leader);
                // now get the round leaders secp256k1 publickey from their fullnode certificate
                let cert = Certificate::get(round_leader)?;
                if !validate_vrf(
                    cert.secp256k1_publickey.clone(),
                    String::from_utf8(bs58::decode(&self.extra).into_vec()?)?,
                    raw_lyra(message),
                ) {
                    error!(
                        "Invalid VRF as shufflebits, proof={}, creator={}, message={}",
                        self.extra, self.sender_key, message
                    );
                    return Err(Box::new(TransactionValidationErrors::InvalidVrf));
                }
            }
            'v' => {
                // VRF lotto ticket
                // check we are in the right epoch period (vrf lotto)
                let top_epoch = get_top_epoch()?;
                if top_epoch.stage != EpochStage::VrfLotto {
                    error!("VRF lotto ticket submited outside of VrfLotto, in transaction={}, sender={}", self.hash, self.sender_key);
                    return Err(Box::new(
                        TransactionValidationErrors::TicketSentOutsideVrfLotto,
                    ));
                }
                // check if the sender is a fullnode candidate
                if get_data(config().db_path + "/candidates", &self.sender_key) != "c" {
                    error!(
                        "Non candidate={} sent VRF lotto ticket, in transaction={}, sender_type={}",
                        self.sender_key,
                        self.hash,
                        get_data(config().db_path + "/candidates", &self.sender_key)
                    );
                    return Err(Box::new(TransactionValidationErrors::NotCandidate));
                }
                // check the vrf is valid
                let current_epoch = get_top_epoch().unwrap_or_default();
                let next_epoch = Epoch::get(current_epoch.epoch_number + 1).unwrap_or_default();
                let vrf_seed = raw_hash(
                    &(format!("{}{}{}", current_epoch.salt, next_epoch.salt, "-vrflotto")),
                );
                debug!("VRF seed: {}", vrf_seed);
                let ticket_hash =
                    raw_hash(&format!("{}{}{}", self.hash, self.sender_key, self.extra))[0..5]
                        .to_string();
                let cert = Certificate::get(self.sender_key.clone())?;
                if !validate_vrf(
                    cert.secp256k1_publickey.clone(),
                    self.extra.clone(),
                    vrf_seed.clone(),
                ) {
                    error!(
                        "Invalid VRF in VRF lotto ticket txn={}, sender={}, vrf={}, seed={}, ticket_hash={}",
                        self.hash, self.sender_key, self.extra, vrf_seed, ticket_hash
                    );
                }
                // check if the value fufills the eclosion requirments
                // TODO: calculate this ecolosion threshold, for now all tickets work
                let threshhold = BigDecimal::from(1);
                let ticket = vrf_hash_to_integer(proof_to_hash(&self.extra)?);
                if ticket > threshhold {
                    error!("VRF lotto ticket does not fufill requirement, threshold={:.4}, ticket={:.4}, ticket hash={}, transaction={}, sender={}", threshhold, ticket, ticket_hash, self.hash, self.sender_key);
                }
                // this VRF lotto ticket is valid, check default stuff like fee
                let size_of_extra = self.extra.len();
                if size_of_extra > 110 {
                    error!(
                        "VRFLottoTicket type transaction {}'s extra ({}) too large, {} > 110",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(Box::new(TransactionValidationErrors::ExtraTooLarge));
                }
                if self.amount != 0 {
                    error!(
                        "VRFLottoTicket transaction {} amount not 0 (amount={} != 0)",
                        self.hash, self.amount
                    );
                    return Err(Box::new(TransactionValidationErrors::InsufficentAmount));
                }
                if sender_account.balance < (self.amount + (self.gas() * self.gas_price)) {
                    error!("Sender {} of transaction {}'s balance too low, amount {} fee={} ({} * {}), required delta={}", sender_account.public_key, self.hash, self.amount, self.gas() * self.gas_price, self.gas() , self.gas_price, (self.amount + (self.gas() * self.gas_price)) - sender_account.balance);
                    return Err(Box::new(TransactionValidationErrors::InsufficentBalance));
                }

                if self.max_gas < self.gas() {
                    error!(
                        "Transaction {} max_gas expended, max_gas={}, used_gas={}",
                        self.hash,
                        self.max_gas,
                        self.gas()
                    );
                    return Err(Box::new(TransactionValidationErrors::MaxGasExpended));
                }
                if self.unlock_time != 0 {
                    return Err(Box::new(TransactionValidationErrors::UnsupportedType));
                }
            }
            _ => {
                error!("Transaction {} has unhandled type {}", self.hash, self.flag);
                return Err(Box::new(TransactionValidationErrors::UnsupportedType));
            }
        }
        if self.timestamp - (config().transaction_timestamp_max_offset as u64)
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
        {
            return Err(Box::new(TransactionValidationErrors::BadTimestamp));
        }
        if !self.access_key.is_empty() {
            // this txn was sent using an access key
            let mut key_to_use: Accesskey = Accesskey::default();
            for key in sender_account.access_keys {
                // try and find the access ley
                if self.access_key == key.key {
                    // TODO: Change Account.access_keys to a hashmap to allow faster key lookup
                    key_to_use = key;
                }
            }
            if key_to_use == Accesskey::default() {
                // if we did not find it, return an error
                return Err(Box::new(TransactionValidationErrors::AccesskeyMissing));
            } else if key_to_use.allowance < self.amount + (self.gas() * self.gas_price)
                && self.flag != 'c'
            {
                // check if this access keys 'allowance' is sufficent to cover this transaction (we have already checked the parent accounts balance)
                error!("Access key {} has insufficent balance to cover txn {}, allowance {}, required {}", self.access_key, self.hash, key_to_use.allowance,  self.amount + (self.gas() * self.gas_price));
                return Err(Box::new(TransactionValidationErrors::InsufficentBalance));
            }
        }
        trace!(
            "Finished validating txn, took={} ms",
            SystemTime::now()
                .duration_since(start)
                .expect("time went backwars ono")
                .as_millis()
        );
        Ok(())
    }

    fn get(_hash: String) -> Result<Box<Self>, Box<dyn std::error::Error>> {
        todo!()
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }

    fn enact(&self) -> Result<(), Box<dyn std::error::Error>> {
        let txn_type = self.flag;
        if txn_type == 'n' {
            trace!("Opening senders account");
            let mut sendacc = open_or_create(&self.sender_key);
            if self.sender_key != self.receive_key {
                trace!("Opening recievers account");
                let mut reqacc: Account = open_or_create(&self.receive_key);

                if self.sender_key != self.receive_key {
                    sendacc.balance -= self.amount;
                    reqacc.balance += self.amount;
                    trace!("saving req acc");
                    reqacc.save().unwrap();
                }
            }
            sendacc.balance -= self.fee();
            trace!("Saving sender acc");
            sendacc.save().unwrap();
            trace!("Get epoch struct");
            let mut top_epoch = get_top_epoch()?;
            top_epoch.total_coins_movement += self.amount + self.fee();
            top_epoch.hash();
            debug!(
                "Rehashed epoch struct at height={}, new hash={}",
                top_epoch.epoch_number, top_epoch.hash
            );
            top_epoch.save()?;
            trace!("Saved epoch");
        // TODO: Check we are on the testnet
        } else if txn_type == 'c' {
            // »!testnet only!«
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            acc.balance += self.amount;
            trace!("Saving acc");
            let _ = acc.save();
            trace!("Get epoch struct");
            let mut top_epoch = get_top_epoch()?;
            top_epoch.total_coins_movement += self.amount;
            top_epoch.new_coins += self.amount;
            top_epoch.hash();
            debug!(
                "Rehashed epoch struct at height={}, new hash={}",
                top_epoch.epoch_number, top_epoch.hash
            );
            top_epoch.save()?;
            trace!("Saved epoch");
        } else if txn_type == 'u' {
            trace!("Getting acc (uname reg)");
            let mut acc = get_account(&self.sender_key).unwrap_or_default();
            if acc == Account::default() {
                return Err("failed to get account for username addition".into());
            } else if acc.username != *"" {
                return Err("account has username already".into());
            } else {
                acc.username = self.extra.clone();
                acc.balance -= self.amount;
                acc.balance -= self.fee();
                trace!("Saving acc");
                if acc.save().is_err() {
                    return Err("failed to save account (after username addition)".into());
                }
            }
            trace!("Get epoch struct");
            let mut top_epoch = get_top_epoch()?;
            top_epoch.total_coins_movement += self.amount + self.fee();
            top_epoch.burnt_coins += self.amount;
            top_epoch.hash();
            debug!(
                "Rehashed epoch struct at height={}, new hash={}",
                top_epoch.epoch_number, top_epoch.hash
            );
            top_epoch.save()?;
            trace!("Saved epoch");
        } else if txn_type == 'b' {
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            if acc.balance > (self.amount + self.fee()) {
                acc.balance -= self.amount + self.fee();
            } else {
                return Err("Account balance insufficent".into());
            }
            trace!("Saving acc");
            let _ = acc.save();
            trace!("Get epoch struct");
            let mut top_epoch = get_top_epoch()?;
            top_epoch.total_coins_movement += self.amount + self.fee();
            top_epoch.burnt_coins += self.amount;
            top_epoch.hash();
            debug!(
                "Rehashed epoch struct at height={}, new hash={}",
                top_epoch.epoch_number, top_epoch.hash
            );
            top_epoch.save()?;
            trace!("Saved epoch");
        } else if txn_type == 'l' {
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            if acc.balance > (self.amount + self.fee()) {
                acc.balance -= self.amount + self.fee();
                acc.locked += self.amount;
            } else {
                return Err("Account balance insufficent".into());
            }
            trace!("Saving acc");
            let _ = acc.save();
            trace!("Get epoch struct");
            let mut top_epoch = get_top_epoch()?;
            top_epoch.total_coins_movement += self.amount + self.fee();
            top_epoch.locked_coins += self.amount;
            top_epoch.hash();
            debug!(
                "Rehashed epoch struct at height={}, new hash={}",
                top_epoch.epoch_number, top_epoch.hash
            );
            top_epoch.save()?;
            trace!("Saved epoch");
        } else if txn_type == 'i' {
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            if acc.balance > (self.amount + self.fee()) {
                acc.balance -= self.amount + self.fee();
            } else {
                return Err("Account balance insufficent".into());
            }
            trace!("Saving acc");
            let _ = acc.save();
            trace!(
                "Creating invite {}, created by {} in txn {}",
                self.extra,
                self.sender_key,
                self.hash
            );
            new_invite(&self.extra)?;
            trace!("Get epoch struct");
            let mut top_epoch = get_top_epoch()?;
            top_epoch.total_coins_movement += self.amount + self.fee();
            top_epoch.hash();
            debug!(
                "Rehashed epoch struct at height={}, new hash={}",
                top_epoch.epoch_number, top_epoch.hash
            );
            top_epoch.save()?;
            trace!("Saved epoch");
        } else if txn_type == 'f' {
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            if acc.balance > (self.amount + self.fee()) {
                acc.balance -= self.amount + self.fee();
            } else {
                return Err("Account balance insufficent".into());
            }
            trace!("Saving acc");
            let _ = acc.save();
            trace!(
                "Enacting fullnode certificate sent by {} in txn {}",
                self.sender_key,
                self.hash
            );
            // Decode the certificate into a struct, enact it and save it to disk
            let cert: Certificate =
                serde_json::from_str(&String::from_utf8(bs58::decode(&self.extra).into_vec()?)?)?;
            cert.save()?;
            cert.enact()?;
            trace!("Get epoch struct");
            let mut top_epoch = get_top_epoch()?;
            top_epoch.total_coins_movement += self.amount + self.fee();
            top_epoch.hash();
            debug!(
                "Rehashed epoch struct at height={}, new hash={}",
                top_epoch.epoch_number, top_epoch.hash
            );
            top_epoch.save()?;
            trace!("Saved epoch");
        } else if txn_type == 'a' {
            match serde_json::from_str::<Vec<(String, String)>>(&String::from_utf8(
                bs58::decode(&self.extra).into_vec()?,
            )?) {
                Ok(salt_seeds) => {
                    debug!("Decoded salt_seeds={:#?}", salt_seeds);
                    let mut salt_string = String::from("");
                    for (_, seed) in salt_seeds {
                        trace!("Validating seed {}", seed);

                        let vrf_hash = proof_to_hash(&seed).unwrap_or_default();
                        salt_string += &vrf_hash_to_integer(vrf_hash).to_string();
                    }
                    debug!("Final salt_string={}", salt_string);
                    // now parse the string into a big number
                    let salt_big = BigDecimal::from_str(&salt_string)?;
                    let salt_mod = salt_big.clone() * BigDecimal::from(u64::MAX); // now SHOULD be safe to cast to u64
                    trace!(
                        "Moduloed big salt: salt_big={}, salt_mod={}",
                        salt_big,
                        salt_mod
                    );
                    if let Ok(epoch_salt) =
                        salt_mod.to_string().split('.').collect::<Vec<&str>>()[0].parse::<u64>()
                    {
                        debug!("Calculated epoch salt: {}", epoch_salt);
                        // now we create the next epoch on disk
                        let mut top_epoch = get_top_epoch()?;
                        top_epoch.stage = EpochStage::VrfLotto;
                        top_epoch.hash();
                        let mut next_epoch = Epoch::new();
                        next_epoch.salt = epoch_salt;
                        next_epoch.stage = EpochStage::Failed; // Set to failed state till we move it to reorg

                        if let Err(e) = next_epoch.save() {
                            error!("Failed to save top_epoch to disk, error={}", e);
                        }
                        if let Err(e) = top_epoch.save() {
                            error!("Failed to save next_epoch to disk, error={}", e);
                        }
                        info!("Next epoch salt: {}", epoch_salt);
                        // dont set the top epoch until we get a announceCommiteeListDelta txn
                        // next txn should be an announceShuffleBits txn which sets the vrf used to shuffle the fullnode list for next epoch
                        // which is followed by an announceCommiteeListDelta which tells you what fullnodes have been removed or added and once enacted starts the next epoch
                        let callbacks = VRF_LOTTERY_CALLBACKS.lock()?;
                        for callback in &*callbacks {
                            (callback)();
                        }
                    } else {
                        error!("Failed to parse epoch salt as u64");
                        return Err("Failed to parse epoch salt as u64".into());
                    }
                }
                Err(e) => {
                    error!("Failed to decode epoch salt seeds from extra ({}) in txn {}, gave error={}", self.extra, self.hash, e);
                    return Err("failed to decode epoch salt seeds".into());
                }
            }
        } else if self.flag == 'z' {
            // announceShuffleBitsTxn
            let shuffle_bits_big = vrf_hash_to_integer(proof_to_hash(&String::from_utf8(
                bs58::decode(&self.extra).into_vec()?,
            )?)?);
            let shuffle_bits_mod =
                shuffle_bits_big.clone() * BigDecimal::from_u128(u128::MAX).unwrap_or_default(); // now SHOULD be safe to cast to u64
            trace!(
                "Moduloed big salt: shuffle_bits_big={}, shuffle_bits_mod={}",
                shuffle_bits_big,
                shuffle_bits_mod
            );
            if let Ok(shuffle_bits) = shuffle_bits_mod.to_string().parse::<u128>() {
                info!("Shuffle bits for next epoch: {}", shuffle_bits);
                let mut epoch = Epoch::get(get_top_epoch()?.epoch_number + 1)?;
                epoch.shuffle_bits = shuffle_bits;
                if let Err(e) = epoch.save() {
                    error!("Failed to save epoch to disk, error={}", e);
                }
            }
        } else if self.flag == 'y' {
            // fullnode list delta
            // format: ((String, String), Vec<(String, u8, String)) 0.0: Preshuffle hash, 0.1: postshuffle hash, 1.0: publickey, 1.1: reason/type (0 = join via vrf eevrythign else = leave), 1.2: proof (the hash of the block it happened in)
            match serde_json::from_str::<((String, String), Vec<(String, u8, String)>)>(
                &String::from_utf8(bs58::decode(&self.extra).into_vec()?)?,
            ) {
                Ok((hashes, delta_list)) => {
                    debug!("Decoded fullnode delta list, len={}, expected preshuffle_hash={}, expected postshuffle_hash={}", delta_list.len(), hashes.0, hashes.1);
                    trace!(
                        "fullnode_delta_list={:#?}, hashes: {:#?}",
                        delta_list,
                        hashes
                    );
                    let top_epoch = get_top_epoch()?;
                    let mut fullnodes_hashset: HashSet<String> = HashSet::new();
                    for committee in top_epoch.committees {
                        for fullnode in committee.members {
                            fullnodes_hashset.insert(fullnode);
                        }
                    }
                    let mut new_fullnodes = 0;
                    let mut removed_fullnodes = 0;
                    for delta in delta_list {
                        if delta.1 != 0 {
                            // remove the fullnode
                            if fullnodes_hashset.contains(&delta.0) {
                                trace!(
                                    "Removing {} from fullnode set, reason={}, proof={}",
                                    delta.0,
                                    delta.1,
                                    delta.2
                                );
                            } else {
                                error!("Fullnode set did not contain node removed by delta entry, delta entry={:?}", delta);
                            }
                            removed_fullnodes += 1;
                        } else {
                            // eclose a candidate
                            fullnodes_hashset.insert(delta.0.clone());
                            // now update their on disk flag to validator, from candidate
                            if save_data("f", &(config().db_path + "/candidates"), delta.0.clone())
                                != 1
                            {
                                return Err("failed to save new fullnode candidate".into());
                            }
                            new_fullnodes += 1;
                        }
                    }
                    let mut fullnodes: Vec<String> = Vec::from_iter(fullnodes_hashset);

                    // now we shuffle the list
                    let mut curr_epoch = Epoch::get(top_epoch.epoch_number + 1)?;
                    let shuffle_seed = vrf_hash_to_integer(raw_lyra(
                        &(curr_epoch.shuffle_bits.to_string()
                            + &curr_epoch.salt.to_string()
                            + &curr_epoch.epoch_number.to_string()),
                    ));
                    let shuffle_seed = (shuffle_seed.clone()
                        / (shuffle_seed + BigDecimal::from(1))) // map between 0-1
                    .to_string() // turn to string
                    .parse::<f64>()?; // parse as f64
                    sort_full_list(&mut fullnodes, (shuffle_seed * (u64::MAX as f64)) as u64);
                    // now form the committees from this shuffled list
                    let mut excluded_nodes: Vec<String> = vec![]; // will contain the publickey of any nodes not included in tis epoch
                    let number_of_committes = 1; // TODO: calculate number of committees, for now its hardcoded as 2
                    let committees: Vec<Comitee> = Comitee::form_comitees(
                        &mut fullnodes,
                        &mut excluded_nodes,
                        number_of_committes,
                    );
                    // now add the list to the current epoch data, save and set to top epoch
                    curr_epoch.committees = committees;
                    curr_epoch.total_fullnodes += new_fullnodes;
                    curr_epoch.total_fullnodes -= removed_fullnodes;
                    if curr_epoch.total_fullnodes == 0 {
                        curr_epoch.total_fullnodes = 1;
                    }
                    curr_epoch.stage = EpochStage::Reorg;
                    curr_epoch.save()?;
                    curr_epoch.set_top_epoch()?;
                    let mut top_epoch = get_top_epoch()?;
                    top_epoch.stage = EpochStage::Final;
                    top_epoch.save()?;
                    info!(
                        "New epoch number {} started, included fullnodes {}, excluded fullnodes {}",
                        curr_epoch.epoch_number,
                        curr_epoch.total_fullnodes,
                        excluded_nodes.len()
                    );
                    for callback in &*(EPOCH_STARTED_CALLBACKS.lock()?) {
                        trace!("Callback for ESC");
                        (callback)()?;
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to decode delta list from txn extra, got error={}",
                        e
                    );
                }
            }
        } else if self.flag == 'v' {
            trace!("Opening senders account");
            let mut sendacc = open_or_create(&self.sender_key);
            sendacc.balance -= self.fee();
            trace!("Saving sender acc");
            sendacc.save().unwrap();
            trace!("Get epoch struct");
            let mut top_epoch = get_top_epoch()?;
            top_epoch.total_coins_movement += self.fee();
            top_epoch.hash();
            debug!(
                "Rehashed epoch struct at height={}, new hash={}",
                top_epoch.epoch_number, top_epoch.hash
            );
            top_epoch.save()?;
            trace!("Saved epoch");
            info!(
                "Recieved new VRF entry ticket. Sender={}, ticket={}",
                self.sender_key, self.extra
            );
            let callbacks = VRF_TICKET_SUBMITTED.lock()?;
            for callback in &*callbacks {
                (callback)(self.clone());
            }
        } else {
            return Err("unsupported txn type".into());
        }
        trace!("Done");
        Ok(())
    }
}
impl Transaction {
    pub fn consensus_type(&self) -> bool {
        self.flag == 'a' || self.flag == 'y' || self.flag == 'z'
    }

    pub fn type_transaction(&self) -> String {
        match self.flag {
            'n' => "normal".to_string(),
            'r' => "reward".to_string(),
            'f' => "fullnode registration".to_string(),
            'u' => "username registraion".to_string(),
            'l' => "lock".to_string(),
            'b' => "burn".to_string(),
            'w' => "burn with return".to_string(),
            'm' => "message".to_string(),
            'c' => "claim".to_owned(), // This is only availble on the testnet it will be removed before the mainet
            'i' => "create invite".to_owned(),
            'x' => "Block/ restrict account".to_owned(), // means the account (linked via public key in the extra field) you block cannot send you transactions
            'p' => "Unblock account".to_owned(), // reverts the block transaction (linked by the txn hash in extra field)
            'v' => "Publish VRF lottery ticket".to_owned(),
            'g' => "Propose penalty".to_owned(), // Proposes, with attached proof of absence that a fullnode should recieve a penalty
            'o' => "Toggle participation".to_owned(), // Toggles the fullnodes participation status (eg if they are taking part in validation)
            // CONSENSUS ONLY
            'a' => "Announce epoch salt seed".to_owned(),
            'y' => "Announce fullnode list delta".to_owned(),
            'z' => "Announce shuffle bits".to_owned(),
            _ => "unknown".to_string(),
        }
    }
    pub fn update_nonce(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let chain_index_db = config().db_path + "/chains/" + &self.sender_key + "-chainindex";
        let txn_count: u64 =
            avrio_database::get_data(chain_index_db.to_owned(), &"txncount").parse()?;
        trace!("Setting txn count");
        if avrio_database::save_data(
            &(txn_count + 1).to_string(),
            &chain_index_db,
            "txncount".to_string(),
        ) != 1
        {
            return Err("failed to update send acc nonce".into());
        } else {
            trace!(
                "Updated account nonce (txn count) for account: {}, prev: {}, new: {}",
                self.sender_key,
                txn_count,
                txn_count + 1
            );
            return Ok(());
        };
    }
    pub fn gas(&self) -> u64 {
        return match self.flag {
            'n' => TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64),
            'u' => {
                TX_GAS as u64 + ((GAS_PER_EXTRA_BYTE_NORMAL / 2) as u64 * self.extra.len() as u64)
            }

            'b' => (TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64)),
            'l' => (TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64)),
            'i' => {
                TX_GAS as u64 + ((GAS_PER_EXTRA_BYTE_NORMAL / 2) as u64 * self.extra.len() as u64)
            }
            'v' => {
                TX_GAS as u64 + ((GAS_PER_EXTRA_BYTE_NORMAL / 2) as u64 * self.extra.len() as u64)
            }
            _ => 0, // f, c, o, g
        };
    }

    pub fn fee(&self) -> u64 {
        self.gas() * self.gas_price
    }

    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }

    pub fn hash_return(&self) -> String {
        self.hash_item()
    }
}
