/*
This file handles the generation, validation and saving of the fullnodes certificate
*/

use std::time::{SystemTime, UNIX_EPOCH};
extern crate avrio_config;
use avrio_config::config;
extern crate avrio_database;
use crate::transaction::Transaction;
use avrio_database::getData;

use avrio_crypto::Hashable;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};
extern crate bs58;
#[derive(Debug)]

pub enum certificateErrors {
    pubtransactionNotFound,
    walletAlreadyRegistered,
    lockedFundsInsufficent,
    parsingError,
    internalError,
    signatureError,
    otherTransactionIssue,
    timestampHigh,
    transactionNotOwnedByAccount,
    transactionNotLock,
    difficultyLow,
    unknown,
}
#[derive(Deserialize, Serialize, Default, Debug)]
pub struct Certificate {
    pub hash: String,
    pub publicKey: String,
    pub txnHash: String,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: String,
}
pub fn difficulty_bytes_as_u128(v: &Vec<u8>) -> u128 {
    ((v[31] as u128) << 0xf * 8)
        | ((v[30] as u128) << 0xe * 8)
        | ((v[29] as u128) << 0xd * 8)
        | ((v[28] as u128) << 0xc * 8)
        | ((v[27] as u128) << 0xb * 8)
        | ((v[26] as u128) << 0xa * 8)
        | ((v[25] as u128) << 0x9 * 8)
        | ((v[24] as u128) << 0x8 * 8)
        | ((v[23] as u128) << 0x7 * 8)
        | ((v[22] as u128) << 0x6 * 8)
        | ((v[21] as u128) << 0x5 * 8)
        | ((v[20] as u128) << 0x4 * 8)
        | ((v[19] as u128) << 0x3 * 8)
        | ((v[18] as u128) << 0x2 * 8)
        | ((v[17] as u128) << 0x1 * 8)
        | ((v[18] as u128) << 0x0 * 8)
        | ((v[19] as u128) << 0x0 * 8)
        | ((v[20] as u128) << 0x0 * 8)
        | ((v[21] as u128) << 0x0 * 8)
        | ((v[22] as u128) << 0x0 * 8)
        | ((v[23] as u128) << 0x0 * 8)
        | ((v[24] as u128) << 0x0 * 8)
        | ((v[25] as u128) << 0x0 * 8)
}
pub fn number_of_proceding_a(s: String) -> u8 {
    let mut fufilled: u8 = 0;
    for c in s.chars() {
        if c != 'A' {
            return fufilled;
        } else {
            fufilled += 1;
        }
    }
    return fufilled;
}
#[cfg(test)]
mod tests {
    pub use crate::certificate::*;
    use avrio_config::config;
    use ring::{
        rand as randc,
        signature::{self, KeyPair},
    };
    #[test]
    fn hash_rate() {
        println!("Starting hashrate test");
        let start = SystemTime::now();
        let mut cert: Certificate = Certificate {
            hash: String::from(""),
            publicKey: String::from(""),
            txnHash: String::from(""),
            nonce: 0,
            timestamp: 0,
            signature: String::from(""),
        };
        while SystemTime::now()
            .duration_since(start)
            .expect("Time went backwards")
            .as_millis()
            < 60 * 1000
        {
            cert.nonce += 1;
            cert.hash();
        }
        let hashrate = cert.nonce / 60;
        println!("hashrate: {} h/s", hashrate);
    }

    #[test]
    fn test_cert_diff() {
        let mut conf = config();
        let diff = 4;

        conf.save();
        let rngc = randc::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let peer_public_key_bytes = key_pair.public_key().as_ref();
        let _target = 600 * 1000;
        println!(
            "generating cerificate now. Public key: {}",
            bs58::encode(peer_public_key_bytes).into_string()
        );
    
        let cert = generateCertificate(
            &bs58::encode(peer_public_key_bytes).into_string(),
            &bs58::encode(pkcs8_bytes).into_string(),
            &bs58::encode("txn hashhhh").into_string(),
            diff,
        )
        .unwrap();
        println!(
            "Generated cert: {:?} in {} secconds.",
            cert,
            (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
                - cert.timestamp) / 1000
        );
    }
}
pub fn generateCertificate(
    pk: &String,
    privateKey: &String,
    txnHash: &String,
    diff: u128,
) -> Result<Certificate, certificateErrors> {
    let mut cert: Certificate = Certificate {
        hash: String::from(""),
        publicKey: String::from(""),
        txnHash: String::from(""),
        nonce: 0,
        timestamp: 0,
        signature: String::from(""),
    };
    cert.publicKey = pk.to_owned();
    cert.txnHash = txnHash.to_owned();
    cert.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;
    let diff_cert = diff; //config().certificateDifficulty;
    for nonce in 0..u64::max_value() {
        cert.nonce = nonce;
        cert.hash();
        if cert.checkDiff(&diff_cert) {
            break;
        }
    }
    drop(diff_cert);
    if let Err(_e) = cert.sign(&privateKey) {
        return Err(certificateErrors::signatureError);
    } else {
        return Ok(cert);
    }
}
impl Hashable for Certificate {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.publicKey.bytes());
        bytes.extend(self.txnHash.bytes());
        bytes.extend(self.nonce.to_owned().to_string().bytes());
        bytes.extend(self.timestamp.to_owned().to_string().bytes());
        bytes
    }
}
impl Certificate {
    pub fn validate(&mut self) -> Result<(), certificateErrors> {
        let cert = self;
        cert.hash();
        let diff_cert = config().certificateDifficulty;
        if !cert.checkDiff(&diff_cert) {
            return Err(certificateErrors::difficultyLow);
        } else if !cert.validSignature() {
            return Err(certificateErrors::signatureError);
        } else if cert.timestamp
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
        {
            return Err(certificateErrors::timestampHigh);
        }
        let txn: Transaction = serde_json::from_str(&getData(
            config().db_path + "/transactions.db",
            &cert.txnHash,
        ))
        .unwrap_or_else(|e| {
            warn!("failed to deserilise Tx, gave error: {}", e);
            return Transaction::default();
        }); // get the txn to check if it is correct
        if txn == Transaction::default() {
            return Err(certificateErrors::otherTransactionIssue);
        }
        if txn.sender_key != cert.publicKey {
            return Err(certificateErrors::transactionNotOwnedByAccount);
        } else if txn.typeTransaction() != "lock" {
            return Err(certificateErrors::transactionNotLock);
        } else if txn.amount != config().fullnode_lock_amount {
            return Err(certificateErrors::lockedFundsInsufficent);
        } else if getData(
            config().db_path + "/certifcates.db",
            &(cert.publicKey.to_owned() + &"-cert".to_owned()),
        ) != "-1".to_string()
        {
            return Err(certificateErrors::walletAlreadyRegistered);
        } else {
            return Ok(());
        }
    }
    pub fn sign(&mut self, private_key: &String) -> Result<(), ring::error::KeyRejected> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key)
                .into_vec()
                .unwrap_or(vec![0])
                .as_ref(),
        )?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = bs58::encode(key_pair.sign(msg)).into_string();
        return Ok(());
    }
    pub fn validSignature(&self) -> bool {
        let msg: &[u8] = self.hash.as_bytes();
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            bs58::decode(self.publicKey.to_owned())
                .into_vec()
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to decode public key from base58 {}, gave error {}",
                        self.publicKey, e
                    );
                    return vec![0, 1, 0];
                }),
        );
        peer_public_key
            .verify(
                msg,
                bs58::decode(self.signature.to_owned())
                    .into_vec()
                    .unwrap_or_else(|e| {
                        error!(
                            "failed to decode signature from base58 {}, gave error {}",
                            self.signature, e
                        );
                        return vec![0, 1, 0];
                    })
                    .as_ref(),
            )
            .unwrap_or_else(|_e| {
                return ();
            });
        return true; // ^ wont unwrap if sig is invalid
    }

    pub fn checkDiff(&self, diff: &u128) -> bool {
        let fufilled: u8 = 0;
        if number_of_proceding_a(self.hash.clone()) as u128 == diff.to_owned() {
            return true;
        } else {
            return false;
        }
    }
    pub fn encodeForHashing(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.publicKey.bytes());
        bytes.extend(self.txnHash.bytes());
        bytes.extend(self.nonce.to_owned().to_string().bytes());
        bytes.extend(self.timestamp.to_owned().to_string().bytes());
        bytes
    }
    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }
    pub fn encodeForFile(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(self.hash.bytes());
        bytes.extend(self.publicKey.bytes());
        bytes.extend(self.txnHash.bytes());
        bytes.extend(self.nonce.to_owned().to_string().bytes());
        bytes.extend(self.timestamp.to_owned().to_string().bytes());
        bytes.extend(self.signature.bytes());
        bytes
    }
}
