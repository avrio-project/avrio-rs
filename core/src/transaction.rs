use serde::{Deserialize, Serialize};
extern crate hex;
use avrio_crypto::Hashable;
extern crate avrio_config;
extern crate bs58;
use avrio_config::config;
extern crate rand;
use avrio_database::{get_data, save_data};

use ring::signature;

extern crate avrio_database;

use crate::{
    account::{get_account, get_by_username, open_or_create, Accesskey, Account},
    certificate::Certificate,
    gas::*,
};

use std::{
    error,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, PartialEq)]
pub enum TransactionValidationErrors {
    TransactionExists,
    CouldNotGetSenderAcc,
    CouldNotGetRecieverAcc,
    AccountMissing,
    BadNonce,
    InsufficentBalance,
    AccesskeyMissing,
    GasPriceLow,
    MaxGasExpended,
    InsufficentAmount,
    BadSignature,
    BadPublicKey,
    TooLarge,
    BadTimestamp,
    InsufficentBurnForUsername,
    BadUnlockTime,
    InvalidCertificate,
    BadHash,
    NonMessageWithoutRecipitent,
    ExtraTooLarge,
    LowGas,
    UnsupportedType,
    ExtraNotAlphanumeric,
    WouldOverflowBalance,
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
    pub gas: u64, // gas used
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: String,
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
        bytes.extend(((self.gas * self.gas_price.to_owned()).to_string()).bytes()); // aka fee
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes.extend((self.nonce.to_owned().to_string()).bytes());
        bytes
    }
}

impl Transaction {
    pub fn type_transaction(&self) -> String {
        match self.flag {
            'n' => "normal".to_string(),
            'r' => "reward".to_string(),
            'f' => "fullnode registration".to_string(),
            'u' => "username registraion".to_string(),
            'l' => "fund lock".to_string(),
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
    pub fn update_nonce(&self) -> std::result::Result<(), Box<dyn error::Error>> {
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

    pub fn enact(&self, _chain_index_db: String) -> std::result::Result<(), Box<dyn error::Error>> {
        let txn_type: String = self.type_transaction();
        if txn_type == *"normal" {
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
            sendacc.balance -= self.gas * self.gas_price;
            trace!("Saving sender acc");
            sendacc.save().unwrap();
            trace!("Get txn count");
        // TODO: Check we are on the testnet
        } else if txn_type == *"claim" {
            // »!testnet only!«
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            acc.balance += self.amount;
            trace!("Saving acc");
            let _ = acc.save();
        } else if txn_type == *"username registraion" {
            trace!("Getting acc (uname reg)");
            let mut acc = get_account(&self.sender_key).unwrap_or_default();
            if acc == Account::default() {
                return Err("failed to get account for username addition".into());
            } else if acc.username != *"" {
                return Err("account has username already".into());
            } else {
                acc.username = self.extra.clone();
                acc.balance -= self.amount;
                acc.balance -= self.gas * self.gas_price;
                trace!("Saving acc");
                if acc.save().is_err() {
                    return Err("failed to save account (after username addition)".into());
                }
            }
        } else if txn_type == *"burn" {
            trace!("Getting sender acc");
            let mut acc: Account = open_or_create(&self.sender_key);
            if acc.balance > (self.amount + self.fee()) {
                acc.balance -= self.amount;
            } else {
                return Err("Account balance insufficent".into());
            }
            trace!("Saving acc");
            let _ = acc.save();
        } else if txn_type == *"lock" {
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
        } else {
            return Err("unsupported txn type".into());
        }
        trace!("Done");
        Ok(())
    }
    pub fn fee(&self) -> u64 {
        self.gas * self.gas_price
    }

    pub fn valid(&self) -> Result<(), TransactionValidationErrors> {
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
                    return Err(TransactionValidationErrors::CouldNotGetSenderAcc);
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
                    return Err(TransactionValidationErrors::CouldNotGetSenderAcc);
                }
            }
        }
        if self.hash_return() != self.hash {
            return Err(TransactionValidationErrors::BadHash);
        }
        let account_nonce = get_data(
            config().db_path
                + &"/chains/".to_owned()
                + &self.sender_key
                + &"-chainindex".to_owned(),
            &"txncount".to_owned(),
        );
        if self.nonce.to_string() != account_nonce && account_nonce != "-1" {
            return Err(TransactionValidationErrors::BadNonce);
        }
        let block_txn_is_in = get_data(config().db_path + &"/transactions".to_owned(), &self.hash);
        if block_txn_is_in != *"-1" {
            error!(
                "Transaction {} already in block {}",
                self.hash, block_txn_is_in
            );
            return Err(TransactionValidationErrors::TransactionExists);
        }
        if !['c', 'n', 'b', 'u', 'l'].contains(&self.flag) {
            error!(
                "Transaction {} has unsupported type={} ({})",
                self.hash,
                self.flag,
                self.type_transaction()
            );
            return Err(TransactionValidationErrors::UnsupportedType);
        }
        if !self.extra.chars().all(char::is_alphanumeric) {
            error!("Transaction {} has non alphanumeric extra field", self.hash);
            return Err(TransactionValidationErrors::ExtraNotAlphanumeric);
        }
        let gas_price_min = 1; // todo move to config
        if self.gas_price <= gas_price_min {
            error!(
                "Transaction {}'s gas price too low ({} < {})",
                self.hash, self.gas_price, gas_price_min
            );
            return Err(TransactionValidationErrors::GasPriceLow);
        }
        match self.flag {
            'n' => {
                let size_of_extra = self.extra.len();
                if size_of_extra > 100 {
                    error!(
                        "Normal type transaction {}'s extra ({}) too large, {} > 100",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(TransactionValidationErrors::ExtraTooLarge);
                }
                if self.amount < 1 {
                    error!("Transaction {} amount too small", self.hash);
                    return Err(TransactionValidationErrors::InsufficentAmount);
                }
                if sender_account.balance < (self.amount + (self.gas * self.gas_price)) {
                    error!("Sender {} of transaction {}'s balance too low, amount {} fee={} ({} * {}), required delta={}", sender_account.public_key, self.hash, self.amount, self.gas * self.gas_price, self.gas , self.gas_price, (self.amount + (self.gas * self.gas_price)) - sender_account.balance);
                    return Err(TransactionValidationErrors::InsufficentBalance);
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
                            return Err(TransactionValidationErrors::CouldNotGetSenderAcc);
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
                            return Err(TransactionValidationErrors::CouldNotGetSenderAcc);
                        }
                    }
                }
                if (u64::MAX - receiver_account.balance) < self.amount {
                    // check the reciever's balance will not surpass u64::MAX after this tranaction and overflow (this is only really a concern with the testnet which has CLAIM transactions)
                    error!("Transaction {} would overflow receiver {}'s balance: Current={}, safe_left={}, txn_amount={}", self.hash, self.receive_key, receiver_account.balance, (u64::MAX - receiver_account.balance), self.amount);
                    return Err(TransactionValidationErrors::WouldOverflowBalance);
                }
                if self.gas
                    < (TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64))
                {
                    error!("Transaction {} gas low", self.hash);
                    return Err(TransactionValidationErrors::LowGas);
                }
                if self.max_gas < self.gas {
                    error!(
                        "Transaction {} max_gas expended, max_gas={}, used_gas={}",
                        self.hash, self.max_gas, self.gas
                    );
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
                if self.unlock_time != 0 {
                    return Err(TransactionValidationErrors::UnsupportedType); // TODO: Implement unlock time
                }
            }
            'c' => {
                let size_of_extra = self.extra.len();
                if size_of_extra != 0 {
                    error!(
                        "Claim type transaction {}'s extra ({}) not zero, {} != 0",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(TransactionValidationErrors::ExtraTooLarge);
                }
                if self.amount < 1 {
                    error!("Transaction {} amount too small", self.hash);
                    return Err(TransactionValidationErrors::InsufficentAmount);
                }
                if (u64::MAX - sender_account.balance) < self.amount {
                    // check the reciever's balance will not surpass u64::MAX after this tranaction and overflow (this is only really a concern with the testnet which has CLAIM transactions)
                    error!("Claim transaction {} would overflow sender's {}'s balance: Current={}, safe_left={}, txn_amount={}", self.hash, self.receive_key, sender_account.balance, (u64::MAX - sender_account.balance), self.amount);
                    return Err(TransactionValidationErrors::WouldOverflowBalance);
                }
                if self.unlock_time != 0 {
                    return Err(TransactionValidationErrors::UnsupportedType); // TODO: Implement unlock time
                }
            }
            'u' => {
                let size_of_extra = self.extra.len();
                if size_of_extra > 20 {
                    error!(
                        "Username registration type transaction {}'s extra ({}) too large, {} > 20",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(TransactionValidationErrors::ExtraTooLarge);
                }
                if self.gas
                    < (TX_GAS as u64
                        + ((GAS_PER_EXTRA_BYTE_NORMAL / 2) as u64 * self.extra.len() as u64))
                {
                    error!("Transaction {} gas low", self.hash);
                    return Err(TransactionValidationErrors::LowGas);
                }
                if self.max_gas < self.gas {
                    error!(
                        "Transaction {} max_gas expended, max_gas={}, used_gas={}",
                        self.hash, self.max_gas, self.gas
                    );
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
                if self.unlock_time != 0 {
                    return Err(TransactionValidationErrors::UnsupportedType); // TODO: Implement unlock time
                }
            }
            'b' => {
                let size_of_extra = std::mem::size_of_val(&self.extra);
                if size_of_extra > 100 {
                    error!(
                        "Burn type transaction {}'s extra ({}) too large, {} > 100",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(TransactionValidationErrors::ExtraTooLarge);
                }
                if self.amount < 1 {
                    error!("Burn transaction {} amount too small", self.hash);
                    return Err(TransactionValidationErrors::InsufficentAmount);
                }
                if sender_account.balance < (self.amount + (self.gas * self.gas_price)) {
                    error!("Sender {} of transaction {}'s balance too low, amount {} fee={} ({} * {}), required delta={}", sender_account.public_key, self.hash, self.amount, self.gas * self.gas_price, self.gas , self.gas_price, (self.amount + (self.gas * self.gas_price)) - sender_account.balance);
                    return Err(TransactionValidationErrors::InsufficentBalance);
                }
                if self.gas
                    < (TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64))
                {
                    error!("Transaction {} gas low", self.hash);
                    return Err(TransactionValidationErrors::LowGas);
                }
                if self.max_gas < self.gas {
                    error!(
                        "Transaction {} max_gas expended, max_gas={}, used_gas={}",
                        self.hash, self.max_gas, self.gas
                    );
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
                if self.unlock_time != 0 {
                    return Err(TransactionValidationErrors::UnsupportedType);
                }
            }
            'l' => {
                let size_of_extra = std::mem::size_of_val(&self.extra);
                if size_of_extra > 100 {
                    error!(
                        "Lock type transaction {}'s extra ({}) too large, {} > 100",
                        self.hash, self.extra, size_of_extra
                    );
                    return Err(TransactionValidationErrors::ExtraTooLarge);
                }
                if self.amount < 1 {
                    error!("Lock transaction {} amount too small", self.hash);
                    return Err(TransactionValidationErrors::InsufficentAmount);
                }
                if sender_account.balance < (self.amount + (self.gas * self.gas_price)) {
                    error!("Sender {} of transaction {}'s balance too low, amount {} fee={} ({} * {}), required delta={}", sender_account.public_key, self.hash, self.amount, self.gas * self.gas_price, self.gas , self.gas_price, (self.amount + (self.gas * self.gas_price)) - sender_account.balance);
                    return Err(TransactionValidationErrors::InsufficentBalance);
                }
                if self.gas
                    < (TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64))
                {
                    error!("Transaction {} gas low", self.hash);
                    return Err(TransactionValidationErrors::LowGas);
                }
                if self.max_gas < self.gas {
                    error!(
                        "Transaction {} max_gas expended, max_gas={}, used_gas={}",
                        self.hash, self.max_gas, self.gas
                    );
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
                if self.unlock_time != 0 {
                    return Err(TransactionValidationErrors::UnsupportedType); // TODO: Implement unlock time
                }
            }
            _ => {
                error!("Transaction {} has unhandled type {}", self.hash, self.flag);
                return Err(TransactionValidationErrors::UnsupportedType);
            }
        }
        if self.timestamp - (config().transaction_timestamp_max_offset as u64)
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
        {
            return Err(TransactionValidationErrors::BadTimestamp);
        }
        if self.access_key.is_empty() {
            // eg if it was sent using the 'main' wallet
            match bs58::decode(&sender_account.public_key.to_owned()).into_vec() {
                // decode the base58 encoded sender public key into a vec
                Ok(peer_public_key_bytes) => {
                    let peer_public_key = signature::UnparsedPublicKey::new(
                        &signature::ED25519,
                        peer_public_key_bytes,
                    );
                    match peer_public_key.verify(
                        // validate the signature
                        self.hash.as_bytes(),
                        &bs58::decode(&(self.signature).to_owned())
                            .into_vec()
                            .unwrap(),
                    ) {
                        Ok(()) => {}
                        _ => {
                            error!(
                                "Transaction {} has bad signature {} (for public_key {})",
                                self.hash, self.signature, sender_account.public_key
                            );
                            return Err(TransactionValidationErrors::BadSignature);
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Transaction {} has bad publickey {}, decoding gave error={}",
                        self.hash, sender_account.public_key, e
                    );
                    return Err(TransactionValidationErrors::BadPublicKey);
                }
            }
        } else {
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
                return Err(TransactionValidationErrors::AccesskeyMissing);
            } else if key_to_use.allowance < self.amount + (self.gas * self.gas_price)
                && self.flag != 'c'
            {
                // check if this access keys 'allowance' is sufficent to cover this transaction (we have already checked the parent accounts balance)
                error!("Access key {} has insufficent balance to cover txn {}, allowance {}, required {}", self.access_key, self.hash, key_to_use.allowance,  self.amount + (self.gas * self.gas_price));
                return Err(TransactionValidationErrors::InsufficentBalance);
            } else {
                match bs58::decode(&self.access_key.to_owned()).into_vec() {
                    Ok(peer_public_key_bytes) => {
                        let peer_public_key = signature::UnparsedPublicKey::new(
                            &signature::ED25519,
                            peer_public_key_bytes,
                        );
                        match peer_public_key.verify(
                            self.hash.as_bytes(),
                            &bs58::decode(&(self.signature).to_owned())
                                .into_vec()
                                .unwrap(),
                        ) {
                            Ok(()) => {}
                            _ => {
                                error!(
                                    "Transaction {} has bad signature {} (for access_key = {})",
                                    self.hash, self.signature, self.access_key
                                );
                                return Err(TransactionValidationErrors::BadSignature);
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "Transaction {} has bad publickey {}, deocding gave error={}",
                            self.hash, self.access_key, e
                        );
                        return Err(TransactionValidationErrors::BadPublicKey);
                    }
                }
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

    pub fn valid_old(&self, recieve: bool) -> Result<(), TransactionValidationErrors> {
        trace!("Validating txn with hash: {}", self.hash);
        let acc: Account = open_or_create(&self.sender_key);
        let txn_count = get_data(
            config().db_path
                + &"/chains/".to_owned()
                + &self.sender_key
                + &"-chainindex".to_owned(),
            &"txncount".to_owned(),
        );
        if !['c', 'n', 'b', 'u'].contains(&self.flag) {
            return Err(TransactionValidationErrors::UnsupportedType);
        } else if !self.extra.chars().all(char::is_alphanumeric) {
            return Err(TransactionValidationErrors::ExtraNotAlphanumeric);
        }
        if self.nonce.to_string() != txn_count && !recieve {
            trace!("Account nonce: expected={}, got={}", txn_count, self.nonce);
            return Err(TransactionValidationErrors::BadNonce);
        } else if self.hash_return() != self.hash {
            return Err(TransactionValidationErrors::BadHash);
        } else if self.amount < 1 && self.flag != 'm' {
            // the min amount sendable (1 miao) unless the txn is a message txn
            return Err(TransactionValidationErrors::InsufficentAmount);
        }
        if self.extra.len() > 100 && self.flag != 'f' {
            if self.flag == 'u' {
                // these cases can have a
                // longer self.extra.len() as they have to include the registration data (eg the fullnode certificate) - they pay the fee for it still
                /* username max extra len break down
                 20 bytes for the timestamp
                 20 bytes for the nonce
                 64 bytes for the hash
                 128 bytes for the signature
                 10 bytes for the username
                 64 bytes for the public key
                298 bytes in total
                */
                if self.extra.len() > 298 {
                    return Err(TransactionValidationErrors::ExtraTooLarge);
                }
            } else {
                return Err(TransactionValidationErrors::ExtraTooLarge);
            }
        }
        /* fullnode registartion certificate max len break down
         20 bytes for the timestamp
         20 bytes for the nonce
         128 bytes for the signature
         64 bytes for the hash
         64 bytes for the txn
         64 bytes for the public key
        296 bytes in total
        */
        if self.flag == 'f' {
            if self.extra.len() > 296 {
                return Err(TransactionValidationErrors::TooLarge);
            } else {
                let mut certificate: Certificate =
                    serde_json::from_str(&self.extra).unwrap_or_default();
                if certificate.validate().is_err() {
                    return Err(TransactionValidationErrors::InvalidCertificate);
                }
            }
        }
        if self.receive_key.is_empty() && self.flag != 'm' && self.flag != 'c' {
            return Err(TransactionValidationErrors::NonMessageWithoutRecipitent);
        }
        match self.flag {
            'n' => {
                if self.max_gas
                    < (TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64))
                {
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
                if self.gas
                    < (TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64))
                {
                    return Err(TransactionValidationErrors::LowGas);
                }
            }
            'm' => {
                if self.max_gas
                    < (TX_GAS as u64
                        + (GAS_PER_EXTRA_BYTE_MESSAGE as u64 * self.extra.len() as u64))
                {
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
                if self.gas
                    < (TX_GAS as u64
                        + (GAS_PER_EXTRA_BYTE_MESSAGE as u64 * self.extra.len() as u64))
                {
                    return Err(TransactionValidationErrors::LowGas);
                }
            }
            'c' => {}
            // TODO be more explicitly exhastive (check gas for each special type)
            _ => {
                if self.max_gas < TX_GAS.into() {
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
                if self.gas < TX_GAS.into() {
                    return Err(TransactionValidationErrors::LowGas);
                }
            }
        };
        if self.timestamp > self.unlock_time && self.unlock_time != 0 {
            return Err(TransactionValidationErrors::BadUnlockTime);
        }
        if self.flag == 'u' && self.amount < config().username_burn_amount {
            return Err(TransactionValidationErrors::InsufficentBurnForUsername);
        }
        if self.timestamp - (config().transaction_timestamp_max_offset as u64)
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
        {
            return Err(TransactionValidationErrors::BadTimestamp);
        }
        if self.access_key.is_empty() {
            if acc.balance < (self.amount + (self.gas * self.gas_price)) && self.flag != 'c' {
                return Err(TransactionValidationErrors::InsufficentBalance);
            } else if self.extra.len() > 100 {
                return Err(TransactionValidationErrors::TooLarge);
            } else {
                let mut peer_public_key_bytes = bs58::decode(&self.sender_key.to_owned())
                    .into_vec()
                    .unwrap_or_else(|e| {
                        debug!("Base58 decoding peer public key gave error {}", e);
                        return vec![5];
                    });
                if peer_public_key_bytes.len() == 1 && peer_public_key_bytes[0] == 5 {
                    // a public key will never be this short
                    // this is probably a username rather than a publickey
                    peer_public_key_bytes = bs58::decode(
                        get_by_username(&self.sender_key)
                            .unwrap_or_default()
                            .public_key,
                    )
                    .into_vec()
                    .unwrap_or_else(|_| vec![5]);
                    if peer_public_key_bytes.len() < 2 {
                        return Err(TransactionValidationErrors::AccountMissing);
                    }
                }
                let peer_public_key =
                    signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
                match peer_public_key.verify(
                    self.hash.as_bytes(),
                    &bs58::decode(&(self.signature).to_owned())
                        .into_vec()
                        .unwrap(),
                ) {
                    Ok(()) => {}
                    _ => return Err(TransactionValidationErrors::BadSignature),
                }
            }
        } else {
            let mut key_to_use: Accesskey = Accesskey::default();
            for key in acc.access_keys {
                if self.access_key == key.key {
                    key_to_use = key;
                }
            }
            if key_to_use == Accesskey::default() {
                return Err(TransactionValidationErrors::AccesskeyMissing);
            } else if key_to_use.allowance < self.amount && self.flag != 'c' {
                return Err(TransactionValidationErrors::InsufficentBalance);
            } else {
                let peer_public_key_bytes = bs58::decode(&self.access_key.to_owned())
                    .into_vec()
                    .unwrap_or_else(|e| {
                        debug!("Base58 decoding peer access key gave error {}", e);
                        return vec![5];
                    });
                if peer_public_key_bytes.len() == 1 && peer_public_key_bytes[0] == 5 {
                    // a access key will never be this short
                    return Err(TransactionValidationErrors::BadPublicKey);
                }
                let peer_public_key =
                    signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
                match peer_public_key.verify(
                    self.hash.as_bytes(),
                    &bs58::decode(&(self.signature).to_owned())
                        .into_vec()
                        .unwrap(),
                ) {
                    Ok(()) => {}
                    _ => return Err(TransactionValidationErrors::BadSignature),
                }
            }
        }
        trace!("Finished validating txn");
        Ok(())
    }

    pub fn encode_compressed(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
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
            self.gas,
            self.nonce,
            self.timestamp,
            self.signature
        )
    }
    pub fn decode_compressed(&mut self, encoded: String) -> Result<(), Box<dyn error::Error>> {
        let components: Vec<&str> = encoded.split(':').collect();
        if components.len() != 14 {
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
        self.gas = components[10].parse()?;
        self.nonce = components[11].parse()?;
        self.timestamp = components[12].parse()?;
        self.signature = components[13].to_string();
        Ok(())
    }

    pub fn validate_transaction(&self) -> bool {
        self.valid().is_ok()
    }

    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }

    pub fn hash_return(&self) -> String {
        self.hash_item()
    }

    pub fn sign(&mut self, private_key: &str) -> std::result::Result<(), ring::error::KeyRejected> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key).into_vec().unwrap().as_ref(),
        )?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = bs58::encode(key_pair.sign(msg)).into_string();
        Ok(())
    }
}
pub struct Item {
    pub cont: String,
}

impl Hashable for Item {
    fn bytes(&self) -> Vec<u8> {
        self.cont.as_bytes().to_vec()
    }
}

pub fn hash(subject: String) -> String {
    Item { cont: subject }.hash_item()
}
