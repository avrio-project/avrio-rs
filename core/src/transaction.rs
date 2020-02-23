use serde::{Deserialize, Serialize};
extern crate hex;
extern crate cryptonight;
use cryptonight::cryptonight;
extern crate  avrio_config;
use avrio_config::config;
extern crate rand;
use rand::Rng;
use std::time::{Duration, Instant};
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};
extern crate avrio_database;
use crate::account::{getAccount, Account};
use std::time::{UNIX_EPOCH, SystemTime};
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
        let acc = getAccount(self.sender_key.to_string()).unwrap_or_else(|e| { warn!("Failed to get account, gave error: {}", e); return Account::default(); });
        if acc.balance == 0 {
            return false;
        }
        if self.amount < 1  && self.flag != 'm'{
            // the min amount sendable (1 miao) unless the txn is a message txn
            return false;
        }
        if self.receive_key.len() == 0 && self.flag != 'm' {
            return false;
        }
        if self.timestamp - (config().transactionTimestampMaxOffset as u64) > SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() as u64 || self.timestamp + (config().transactionTimestampMaxOffset as u64) < SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() as u64{
            return false;
        }
        if self.access_key == "" {
            if  acc.balance > self.amount {
                return false;
            } else if self.hashReturn() != self.hash {
                return false;
            }
            else if self.extra.len() > 100 {
                return false;
            }
             else {
                 let peer_public_key_bytes = hex::decode(&self.sender_key.to_owned()).unwrap_or_else(|e| {
                     warn!("Hex decoding peer public key gave error {}", e);
                     return vec![5];
                 });
                 if peer_public_key_bytes.len() == 1 && peer_public_key_bytes[0] == 5 { // a public key will never be this short
                     return false;
                 }
                 let peer_public_key =
                    signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
                match peer_public_key.verify(self.hash.as_bytes(), &hex::decode(&(self.signature).to_owned()).unwrap()) {
                    Ok(()) => {},
                    _ => return false,
                 }

            }
        }
        else {
            // have access key
            return true; // todo
        }
    return true;
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend((self.amount.to_string()).bytes());
        bytes.extend((self.extra.to_owned()).bytes());;
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
        unsafe {
            let out = cryptonight(&asbytes, asbytes.len(), 0);
            self.hash = hex::encode(out);
        }
    }
    pub fn hashReturn(&self) -> String {
        let asbytes = self.bytes();
        unsafe {
            let out = cryptonight(&asbytes, asbytes.len(), 0);
            return hex::encode(out);
        }
    }
}

pub fn hashBytes(asbytes: Vec<u8>) -> String{;
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
