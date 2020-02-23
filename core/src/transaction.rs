use serde::{Deserialize, Serialize};
extern crate hex;
extern crate cryptonight;
use cryptonight::cryptonight;
extern crate rand;
use rand::Rng;
use std::time::{Duration, Instant};
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};
extern crate avrio_database;
use crate::account::{getAccount, Account};

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Transaction {
    pub hash: String,
    pub amount: u64,
    pub extra: String,
    pub flag: char,
    pub sender_key: String,
    pub receive_key: String,
    pub access_key: String,
    pub gas_price: u64,
    pub max_gas: u64,
    pub gas: u64, // gas used
    pub nonce: u64,
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

    pub fn validateTransaction(&self) -> bool {
        let mut acc = getAccount(self.sender_key.to_string()).unwrap_or_else(|e| { warn!("Failed to get account, gave error: {}", e); return Account::default(); });
        if acc.balance == 0 {
            return false;
        }
        if self.amount < 1  && self.flag != 'm'{
            // the min amount sendable (1 miao) unless the txn is a message txn
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
                 let peer_public_key_bytes = hex::decode(&self.sender_key.to_owned()).unwrap();
                 let peer_public_key =
                    signature::UnparsedPublicKey::new(&signature::ED25519, peer_public_key_bytes);
                match peer_public_key.verify(self.hash.as_bytes(), &hex::decode(&(self.signature).to_owned()).unwrap()) {
                    Ok(()) => return true,
                    _ => return false,
                 }
            }
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
        bytes.extend(((self.gas * self.gas_price.to_owned()).to_string()).bytes()); // aka fee
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
