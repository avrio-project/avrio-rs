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
    account::{deltaFunds, getAccount, getByUsername, Accesskey, Account},
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

    pub fn enact(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let txn_type: String = self.typeTransaction();
        if txn_type == "normal".to_owned() {
            let sendacc: Account;
            if let Ok(sender) = getAccount(&self.sender_key) {
                sendacc = sender;
            } else {
                if let Ok(sender_by_uname) = getByUsername(&self.sender_key) {
                    sendacc = sender_by_uname;
                } else {
                    return Err("failed to get send acc".into());
                }
            }

            let reqacc: Account;
            if let Ok(recer) = getAccount(&self.receive_key) {
                reqacc = recer;
            } else {
                if let Ok(recer_by_uname) = getByUsername(&self.receive_key) {
                    reqacc = recer_by_uname;
                } else {
                    return Err("failed to get rec acc".into());
                }
            }
            deltaFunds(&sendacc.public_key, self.amount, 0, String::from(""))?;
            deltaFunds(&reqacc.public_key, self.amount, 1, String::from(""))?;
            let txn_count: u64 = avrio_database::getData(
                config().db_path
                    + &"/chains/".to_owned()
                    + &self.sender_key
                    + &"-chainindex".to_owned(),
                &"txncount".to_owned(),
            )
            .parse()?;
            if avrio_database::saveData(
                (txn_count + 1).to_string(),
                config().db_path
                    + &"/chains/".to_owned()
                    + &self.sender_key
                    + &"-chainindex".to_owned(),
                "txncount".to_owned(),
            ) != 1
            {
                return Err("failed to update send acc nonce".into());
            }
        // TODO: Check we are on the testnet
        } else if txn_type == "claim".to_owned() {
            // »!testnet only!«
            let acc: Account;
            if let Ok(sender) = getAccount(&self.sender_key) {
                acc = sender;
            } else {
                if let Ok(sender_by_uname) = getByUsername(&self.sender_key) {
                    acc = sender_by_uname;
                } else {
                    return Err("failed to get send acc".into());
                }
            }
            deltaFunds(&acc.public_key, self.amount, 1, String::from(""))?;
        } else {
            return Err("unsuported txn type".into());
        }
        return Ok(());
    }

    pub fn valid(&self) -> Result<(), TransactionValidationErrors> {
        let acc: Account;
        let acc_try = getAccount(&self.sender_key);
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
        } else if let Ok(account) = acc_try {
            acc = account;
        } else {
            // if getting the account via self.sender_key failed it is probably a username, try that now
            let acc_try_username = getByUsername(&self.sender_key);
            if let Ok(account_from_username) = acc_try_username {
                acc = account_from_username;
            } else {
                // if that failed it wasnt a username/ the username was invalid (to us) - tell the user this and exit
                error!(
                    "Failed to Get Account, sender key: {}. Not a valid username or publickey",
                    self.sender_key
                );
                return Err(TransactionValidationErrors::AccountMissing);
            }
        }
        if self.amount < 1 && self.flag != 'm' {
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
                if self.max_gas < (TX_GAS + GAS_PER_EXTRA_BYTE_NORMAL).into() {
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
            }
            'm' => {
                if self.max_gas < GAS_PER_EXTRA_BYTE_MESSAGE.into() {
                    return Err(TransactionValidationErrors::MaxGasExpended);
                }
            }
            'c' => {}
            // TODO be more explicitly exhastive (check gas for each special type)
            _ => {
                if self.max_gas < TX_GAS.into() {
                    return Err(TransactionValidationErrors::MaxGasExpended);
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
            if acc.balance < self.amount && self.flag != 'c' {
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
