use serde::{Deserialize, Serialize};
extern crate cryptonight;
extern crate hex;
use avrio_crypto::Hashable;
extern crate avrio_config;
extern crate bs58;
use avrio_config::config;
extern crate rand;

use ring::signature;

extern crate avrio_database;

use crate::{
    account::{deltaFunds, getAccount, getByUsername, open_or_create, Accesskey, Account},
    certificate::Certificate,
    gas::*,
};

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq)]
pub enum TransactionValidationErrors {
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
    pub fn typeTransaction(&self) -> String {
        return match self.flag {
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
            _ => "unknown".to_string(),
        };
    }

    pub fn enact(
        &self,
        chain_idex_db: &rocksdb::DB,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let txn_type: String = self.typeTransaction();
        if txn_type == "normal".to_owned() {
            let mut sendacc = open_or_create(&self.sender_key);

            let mut reqacc: Account = open_or_create(&self.receive_key);
            sendacc.balance -= self.gas * self.gas_price;
            if self.sender_key != self.receive_key {
                sendacc.balance -= self.amount;
                reqacc.balance += self.amount;
                reqacc.save().unwrap();
            }
            sendacc.save().unwrap();
            let txn_count: u64 = avrio_database::getDataDb(chain_idex_db, &"txncount").parse()?;
            if avrio_database::setDataDb(&(txn_count + 1).to_string(), chain_idex_db, &"txncount")
                != 1
            {
                return Err("failed to update send acc nonce".into());
            } else {
                trace!(
                    "Updated account nonce (txn count) for account: {}, prev: {}, new: {}",
                    self.sender_key,
                    txn_count,
                    txn_count + 1
                );
            }
        // TODO: Check we are on the testnet
        } else if txn_type == "claim".to_owned() {
            // »!testnet only!«
            let mut acc: Account = open_or_create(&self.sender_key);
            acc.balance += self.amount;
            let _ = acc.save();
        } else if txn_type == "username registraion".to_string() {
            let mut acc = getAccount(&self.sender_key).unwrap_or_default();
            if acc == Account::default() {
                return Err("failed to get account for username addition".into());
            } else if acc.username != "".to_owned() {
                return Err("account has username already".into());
            } else {
                acc.username = self.extra.clone();
                acc.balance -= self.amount;
                acc.balance -= self.gas * self.gas_price;
                if let Err(_) = acc.save() {
                    return Err("failed to save account (after username addition)".into());
                }
            }
        } else {
            return Err("unsupported txn type".into());
        }
        return Ok(());
    }

    pub fn valid(&self) -> Result<(), TransactionValidationErrors> {
        let acc: Account = open_or_create(&self.sender_key);
        let txn_count = avrio_database::getData(
            config().db_path
                + &"/chains/".to_owned()
                + &self.sender_key
                + &"-chainindex".to_owned(),
            &"txncount".to_owned(),
        );
        if self.nonce.to_string() != txn_count {
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
                if let Err(_) = certificate.validate() {
                    return Err(TransactionValidationErrors::InvalidCertificate);
                }
            }
        }
        if self.receive_key.len() == 0 && self.flag != 'm' && self.flag != 'c' {
            return Err(TransactionValidationErrors::NonMessageWithoutRecipitent);
        }
        match self.flag {
            'n' => {
                if self.max_gas
                    < (TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64))
                        .into()
                {
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
                if self.gas
                    < (TX_GAS as u64 + (GAS_PER_EXTRA_BYTE_NORMAL as u64 * self.extra.len() as u64))
                        .into()
                {
                    return Err(TransactionValidationErrors::LowGas);
                }
            }
            'm' => {
                if self.max_gas
                    < (TX_GAS as u64
                        + (GAS_PER_EXTRA_BYTE_MESSAGE as u64 * self.extra.len() as u64))
                        .into()
                {
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
                if self.gas
                    < (TX_GAS as u64
                        + (GAS_PER_EXTRA_BYTE_MESSAGE as u64 * self.extra.len() as u64))
                        .into()
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
        if self.timestamp - (config().transactionTimestampMaxOffset as u64)
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
        {
            return Err(TransactionValidationErrors::BadTimestamp);
        }
        if self.access_key == "" {
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
                        getByUsername(&self.sender_key)
                            .unwrap_or_default()
                            .public_key,
                    )
                    .into_vec()
                    .unwrap_or(vec![5]);
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
        return Ok(());
    }

    pub fn validate_transaction(&self) -> bool {
        if let Err(_) = self.valid() {
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
        private_key: &String,
    ) -> std::result::Result<(), ring::error::KeyRejected> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key).into_vec().unwrap().as_ref(),
        )?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = bs58::encode(key_pair.sign(msg)).into_string();
        return Ok(());
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
    return Item { cont: subject }.hash_item();
}
