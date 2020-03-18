use serde::{Deserialize, Serialize};
extern crate cryptonight;
extern crate hex;
use cryptonight::cryptonight;
extern crate avrio_config;
use avrio_config::config;
extern crate rand;

use ring::{
    signature::{self, KeyPair},
};

extern crate avrio_database;
use crate::{
    account::{getAccount, getByUsername, Account},
    certificate::Certificate,
    gas::*,
};
use std::time::{SystemTime, UNIX_EPOCH};
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
            _ => "unknown".to_string(),
        };
    }

    pub fn validate_transaction(&self) -> bool {
        let mut acc: Account = Account::default();
        let acc_try = getAccount(self.sender_key.to_string());
        if let Ok(account) = acc_try {
            acc = account;
        } else {
            // if getting the account via self.sender_key failed it is probably a username, try that now
            let acc_try_username = getByUsername(self.sender_key.clone());
            if let Ok(account_from_username) = acc_try_username {
                acc = account_from_username;
            } else {
                // if that fialed it wasnt a username/ the username was invalid (to us) - tell the user this and exit
                debug!(
                    "Failed to Get Account, sender key: {}. Not a valid username or publickey",
                    self.sender_key
                );
                return false;
            }
        }
        if acc.balance == 0 {
            return false;
        }
        if self.amount < 1 && self.flag != 'm' {
            // the min amount sendable (1 miao) unless the txn is a message txn
            return false;
        }
        if self.extra.len() < 100 && self.flag != 'f' {
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
                    return false;
                }
            } else {
                return false;
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
                return false;
            } else {
                let mut certificate: Certificate =
                    serde_json::from_str(&self.extra).unwrap_or_default();
                if let Err(_) = certificate.validate() {
                    return false;
                }
            }
        }
        if self.receive_key.len() == 0 && self.flag != 'm' {
            return false;
        }
        match self.flag {
            'n' => {
                if self.max_gas < (TX_GAS + GAS_PER_EXTRA_BYTE_NORMAL).into() {
                    return false;
                }
            }
            'm' => {
                if self.max_gas < GAS_PER_EXTRA_BYTE_MESSAGE.into() {
                    return false;
                }
            }
            // TODO be more explicitly exhastive (check gas for each special type)
            _ => {
                if self.max_gas < TX_GAS.into() {
                    return false;
                }
            }
        };
        if self.flag == 'f' {
            if self.amount < config().fullnode_lock_amount {
                return false;
            } else if self.unlock_time - (config().transactionTimestampMaxOffset as u64)
                < (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64)
                    + (config().fullnode_lock_time * config().target_epoch_length)
                || self.unlock_time + (config().transactionTimestampMaxOffset as u64)
                    < (SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time went backwards")
                        .as_millis() as u64)
                        + (config().fullnode_lock_time * config().target_epoch_length)
            {
                return false;
            }
        }
        if self.timestamp > self.unlock_time {
            return false;
        }
        if self.flag == 'u' && self.amount < config().username_burn_amount {
            return false;
        }
        if self.timestamp - (config().transactionTimestampMaxOffset as u64)
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
            || self.timestamp + (config().transactionTimestampMaxOffset as u64)
                < SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64
        {
            return false;
        }
        if self.access_key == "" {
            if acc.balance > self.amount {
                return false;
            } else if self.hashReturn() != self.hash {
                return false;
            } else if self.extra.len() > 100 {
                return false;
            } else {
                let mut peer_public_key_bytes = hex::decode(&self.sender_key.to_owned())
                    .unwrap_or_else(|e| {
                        warn!("Hex decoding peer public key gave error {}", e);
                        return vec![5];
                    });
                if peer_public_key_bytes.len() == 1 && peer_public_key_bytes[0] == 5 {
                    // a public key will never be this short
                    // this is probably a username rather than a publickey
                    peer_public_key_bytes = hex::decode(
                        getByUsername(self.sender_key.clone())
                            .unwrap_or_default()
                            .public_key,
                    )
                    .unwrap_or(vec![5]);
                    if peer_public_key_bytes.len() < 2 {
                        return false;
                    }
                }
                let peer_public_key =
                    signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
                match peer_public_key.verify(
                    self.hash.as_bytes(),
                    &hex::decode(&(self.signature).to_owned()).unwrap(),
                ) {
                    Ok(()) => {}
                    _ => return false,
                }
            }
        } else {
            // have access key
            return true; // todo
        }
        return true;
    }

    pub fn bytes(&self) -> Vec<u8> {
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
    pub fn hash(&mut self) {
        let asbytes = self.bytes();
        let out = cryptonight(&asbytes, asbytes.len(), 0);
        self.hash = hex::encode(out);
    }
    pub fn hashReturn(&self) -> String {
        let asbytes = self.bytes();

        let out = cryptonight(&asbytes, asbytes.len(), 0);
        return hex::encode(out);
    }
}

pub fn hashBytes(asbytes: Vec<u8>) -> String {
    unsafe {
        let out = cryptonight(&asbytes, asbytes.len(), 0);
        return hex::encode(out);
    }
}

fn hash(subject: String) -> String {
    let asBytes = subject.as_bytes();
    unsafe {
        let out = cryptonight(&asBytes, asBytes.len(), 0);
        return hex::encode(out);
    }
}
