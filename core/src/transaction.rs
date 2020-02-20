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
extern crate database;
use database::getAccount;

#[derive(Serialize, Deserialize, Debug)]
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
#[derive(Serialize, Deserialize, Debug)]
pub struct TxStore {
    // remove data not needed to be stored
    hash: String,
    amount: u64,
    flag: char,
    extra: String,
    sender_key: String,
    receive_key: String,
    access_key: String,
    fee: u64, // fee in AIO (gas_used * gas_price)
    nonce: u8,
    signature: String,
}
impl Transaction {
    fn toTxStore(&self) -> TxStore {
        let n = TxStore { 
            hash: self.hash,
            amount: self.amount,
            flag: self.flag, 
            extra: self.extra, 
            sender_key: self.sender_key, 
            receive_key: self.receive_key,
            access_key: self.access_key,
            fee: self.gas_price * self.gas,
            nonce: self.nonce,
            signature: self.signature,
        };
        return n;
    }
    fn typeTransaction(&self) -> String {
        return match (self.flag) {
            'n' => "normal",
            'r' => "reward",
            'f' => "fullnode registration",
            'u' => "username registraion",
            'l' => "fund lock",
            'b' => "burn",
            'w' => "burn with return",
            'm' => "message",
            _ => "unknown",
        };
    }
    
    fn validateTransaction(&self) -> bool {
        let mut acc = getAccount(self.sender_key);
        if acc.balance == 0 {
            return false;
        }
        
        if self.amount < 1  && flag != 'm'{
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
                    ok(()) => return true,
                    _ => return false,
                 }
            }
        }
    return true;
    }
    fn bytes(&self) -> Vec<u8> {
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
    fn hash(&mut self) {
        let asbytes = self.bytes();
        unsafe {
            let out = cryptonight(&asbytes, asbytes.len(), 0);
        
            self.hash = hex::encode(out);
        }
    }
    fn hashReturn(&self) -> String {
        let asbytes = self.bytes();
        unsafe {
            let out = cryptonight(&asbytes, asbytes.len(), 0);
            return hex::encode(out);
        }
    }
}                                                                     

fn hashBytes(asbytes: Vec<u8>) -> String{;
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
