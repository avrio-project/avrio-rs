/*
This file handles the generation, validation and saving of the fullnodes certificate
*/

extern crate hex;
use std::time::{SystemTime, UNIX_EPOCH};
extern crate avrio_config;
extern crate cryptonight;
use avrio_config::config;
extern crate avrio_database;
use crate::transaction::Transaction;
use avrio_database::{getData, saveData};
use cryptonight::cryptonight;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::error::Error;

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
#[derive(Deserialize, Serialize, Default)]
pub struct Certificate {
    pub hash: String,
    pub publicKey: String,
    pub txnHash: String,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: String,
}
pub fn difficulty_bytes_as_u64(v: &Vec<u8>) -> u64 {
    return v.clone().iter().sum::<u8>().into();
}

pub fn generateCertificate(
    pk: &String,
    privateKey: &String,
    txnHash: &String,
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
    let diff_cert = config().certificateDifficulty;
    for nonce in 0..u64::max_value() {
        cert.nonce = nonce;
        cert.hash();
        if cert.checkDiff(&diff_cert) {
            break;
        }
    }
    drop(diff_cert);
    if let Err(e) = cert.sign(&privateKey) {
        return Err(certificateErrors::signatureError);
    } else {
        return Ok(cert);
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
            cert.txnHash.to_owned(),
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
            cert.publicKey.to_owned() + &"-cert".to_owned(),
        ) != "-1".to_string()
        {
            return Err(certificateErrors::walletAlreadyRegistered);
        } else {
            return Ok(());
        }
        return Ok(());
    }
    pub fn sign(&mut self, privateKey: &String) -> Result<(), ring::error::KeyRejected> {
        let key_pair =
            signature::Ed25519KeyPair::from_pkcs8(hex::decode(privateKey).unwrap().as_ref())?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = hex::encode(key_pair.sign(msg));
        return Ok(());
    }
    pub fn validSignature(&self) -> bool {
        let msg: &[u8] = self.hash.as_bytes();
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            hex::decode(self.publicKey.to_owned()).unwrap_or_else(|e| {
                error!(
                    "Failed to decode public key from hex {}, gave error {}",
                    self.publicKey, e
                );
                return vec![0, 1, 0];
            }),
        );
        peer_public_key
            .verify(
                msg,
                hex::decode(self.signature.to_owned())
                    .unwrap_or_else(|e| {
                        error!(
                            "failed to decode signature from hex {}, gave error {}",
                            self.signature, e
                        );
                        return vec![0, 1, 0];
                    })
                    .as_ref(),
            )
            .unwrap_or_else(|e| {
                return ();
            });
        return true; // ^ wont unwrap if sig is invalid
    }

    pub fn checkDiff(&self, diff: &u64) -> bool {
        if difficulty_bytes_as_u64(&self.hash.as_bytes().to_vec()) < diff.to_owned() {
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
    fn hash(&mut self) {
        let bytes = self.encodeForHashing();
        unsafe {
            cryptonight::set_params(655360, 32768);
        }
        let hash = cryptonight::cryptonight(&bytes, bytes.len(), 0);
        self.hash = String::from(hex::encode(hash));
    }
    fn encodeForFile(&self) -> Vec<u8> {
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
