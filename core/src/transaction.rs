use serde::{Deserialize, Serialize};
extern crate hex;
use avrio_crypto::Hashable;
extern crate avrio_config;
extern crate bs58;
use avrio_config::config;
extern crate rand;
use avrio_database::{get_data, save_data};
use thiserror::Error;
extern crate avrio_database;

use crate::{
    account::{get_account, open_or_create, Accesskey, Account},
    certificate::{Certificate, CertificateErrors},
    gas::*,
    invite::{invite_valid, new_invite},
    validate::Verifiable,
};

use std::time::{SystemTime, UNIX_EPOCH};

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
        if !['c', 'n', 'b', 'u', 'l', 'i', 'f'].contains(&self.flag) {
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
        if self.gas_price <= gas_price_min {
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
                if get_data(
                    config().db_path + &"/fn-certificates".to_owned(),
                    &(self.sender_key.to_owned() + &"-cert".to_owned()),
                ) == "-1"
                {
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
            'f' => match serde_json::from_str::<Certificate>(&self.extra) {
                Ok(cert) => {
                    if let Err(e) = cert.valid() {
                        error!("Invalid fullnode register certificate {} in transaction {} by sender {}, error={:#?}", cert.hash, self.hash, self.sender_key, e);
                        return Err(Box::new(TransactionValidationErrors::InvalidCertificate(e)));
                    }
                }
                Err(e) => {
                    error!("Failed to decode certificate, gave error: {}", e);
                    return Err(Box::new(TransactionValidationErrors::InvalidCertificate(
                        Box::new(e),
                    )));
                }
            },
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
            sendacc.balance -= self.gas() * self.gas_price;
            trace!("Saving sender acc");
            sendacc.save().unwrap();
            trace!("Get txn count");
        // TODO: Check we are on the testnet
        } else if txn_type == 'c' {
            // »!testnet only!«
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            acc.balance += self.amount;
            trace!("Saving acc");
            let _ = acc.save();
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
                acc.balance -= self.gas() * self.gas_price;
                trace!("Saving acc");
                if acc.save().is_err() {
                    return Err("failed to save account (after username addition)".into());
                }
            }
        } else if txn_type == 'b' {
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            if acc.balance > (self.amount + self.fee()) {
                acc.balance -= self.amount;
            } else {
                return Err("Account balance insufficent".into());
            }
            trace!("Saving acc");
            let _ = acc.save();
        } else if txn_type == 'l' {
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            if acc.balance > (self.amount + self.fee()) {
                acc.balance -= self.amount;
                acc.locked += self.amount;
            } else {
                return Err("Account balance insufficent".into());
            }
            trace!("Saving acc");
            let _ = acc.save();
        } else if txn_type == 'i' {
            trace!(
                "Creating invite {}, created by {} in txn {}",
                self.extra,
                self.sender_key,
                self.hash
            );
            new_invite(&self.extra)?;
        } else if txn_type == 'f' {
            trace!(
                "Enacting fullnode certificate sent by {} in txn {}",
                self.sender_key,
                self.hash
            );
            // Decode the certificate into a struct, enact it and save it to disk
            let cert: Certificate = serde_json::from_str(&self.extra)?;
            cert.save()?;
            cert.enact()?;
        } else {
            return Err("unsupported txn type".into());
        }
        trace!("Done");
        Ok(())
    }
}
impl Transaction {
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
            _ => 0, // f, c
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
