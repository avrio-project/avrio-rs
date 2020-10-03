/*
This file handles the generation, validation and saving of the fullnodes certificate
*/

use std::time::{SystemTime, UNIX_EPOCH};
extern crate avrio_config;
use avrio_config::config;
extern crate avrio_database;
use crate::{invite::valid, transaction::Transaction};
use avrio_database::get_data;

use avrio_crypto::Hashable;
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
extern crate bs58;

#[derive(Debug)]

pub enum CertificateErrors {
    TransactionNotFound,
    WalletAlreadyRegistered,
    LockedFundsInsufficent,
    FundLockTimeInsufficent,
    ParsingError,
    InternalError,
    SignatureError,
    OtherTransactionIssue,
    TimestampHigh,
    TransactionNotOwnedByAccount,
    TransactionNotLock,
    DifficultyLow,
    InvalidInvite,
    Unknown,
}

#[derive(Deserialize, Serialize, Default, Debug)]

pub struct Certificate {
    pub hash: String,
    pub public_key: String,
    pub txn_hash: String,
    pub nonce: u64,
    pub timestamp: u64,
    pub valid_until: u64,
    pub invite: String,
    pub invite_sig: String,
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
            break;
        } else {
            fufilled += 1;
        }
    }

    fufilled
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
            public_key: String::from(""),
            txn_hash: String::from(""),
            nonce: 0,
            timestamp: 0,
            valid_until: 0,
            invite: "inv".into(),
            invite_sig: "inv_sig".into(),
            signature: String::from(""),
        };

        while SystemTime::now()
            .duration_since(start)
            .expect("Time went backwards")
            .as_millis()
            < 120 * 1000
        {
            cert.nonce += 1;
            cert.hash();
        }

        let hashrate = cert.nonce / 120;

        println!("hashrate: {} h/s", hashrate);
    }

    #[test]
    fn test_cert_diff() {
        let conf = config();
        let diff = 4;

        let _ = conf.save();
        let rngc = randc::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let peer_public_key_bytes = key_pair.public_key().as_ref();
        let _target = 600 * 1000;

        println!(
            "Generating cerificate with public key {}...",
            bs58::encode(peer_public_key_bytes).into_string()
        );

        let cert = generate_certificate(
            &bs58::encode(peer_public_key_bytes).into_string(),
            &bs58::encode(pkcs8_bytes).into_string(),
            &bs58::encode("txn hashhhh").into_string(),
            diff,
            "inv".into(),
        )
        .unwrap();

        println!(
            "Generated certificate {:?} in {} secconds.",
            cert,
            (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
                - cert.timestamp)
                / 1000
        );
    }
}

pub fn generate_certificate(
    pk: &String,
    private_key: &String,
    txn_hash: &String,
    diff: u128,
    invite: String,
) -> Result<Certificate, CertificateErrors> {
    let key_pair =
        signature::Ed25519KeyPair::from_pkcs8(bs58::decode(&invite).into_vec().unwrap().as_ref())
            .unwrap();

    let peer_public_key_bytes = key_pair.public_key().as_ref();

    let mut cert: Certificate = Certificate {
        hash: String::from(""),
        public_key: String::from(""),
        txn_hash: String::from(""),
        nonce: 0,
        valid_until: 0,
        invite: bs58::encode(peer_public_key_bytes).into_string(),
        invite_sig: "inv_sig".into(),
        timestamp: 0,
        signature: String::from(""),
    };

    cert.public_key = pk.to_owned();
    cert.txn_hash = txn_hash.to_owned();
    cert.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    let diff_cert = diff; //config().certificate_difficulty;
    let block_hash = get_data(config().db_path + "/transactions.db", &cert.txn_hash);
    let blk = get_block_from_raw(block_hash); // get the txn to check if it is correct
    let mut txn: Transaction = Default::default();

    for transaction in blk.txns {
        if transaction.hash == cert.txn_hash {
            txn = transaction;
        }
    }

    if txn == Transaction::default() {
        return Err(CertificateErrors::OtherTransactionIssue);
    }

    cert.valid_until = txn.unlock_time;

    for nonce in 0..u64::max_value() {
        cert.nonce = nonce;
        cert.hash();
        if cert.check_diff(&diff_cert) {
            break;
        }
    }

    drop(diff_cert);
    if let Err(_e) = cert.sign(&private_key, invite) {
        return Err(CertificateErrors::SignatureError);
    } else {
        return Ok(cert);
    }
}

impl Hashable for Certificate {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.public_key.bytes());
        bytes.extend(self.txn_hash.bytes());
        bytes.extend(self.nonce.to_owned().to_string().bytes());
        bytes.extend(self.invite.bytes());
        bytes.extend(self.invite_sig.bytes());
        bytes.extend(self.timestamp.to_owned().to_string().bytes());
        bytes.extend(self.valid_until.to_owned().to_string().bytes());

        bytes
    }
}

impl Certificate {
    pub fn validate(&mut self) -> Result<(), CertificateErrors> {
        let cert = self;

        cert.hash();

        let diff_cert = config().certificate_difficulty;

        if !cert.check_diff(&diff_cert) {
            return Err(CertificateErrors::DifficultyLow);
        } else if !cert.valid_signature() {
            return Err(CertificateErrors::SignatureError);
        } else if cert.timestamp
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
        {
            return Err(CertificateErrors::TimestampHigh);
        }

        let block_hash = get_data(config().db_path + "/transactions.db", &cert.txn_hash);
        let blk = get_block_from_raw(block_hash); // get the txn to check if it is correct
        let mut txn: Transaction = Default::default();

        for transaction in blk.txns {
            if transaction.hash == cert.txn_hash {
                txn = transaction;
            }
        }

        if txn == Transaction::default() {
            return Err(CertificateErrors::OtherTransactionIssue);
        }

        if txn.sender_key != cert.public_key {
            return Err(CertificateErrors::TransactionNotOwnedByAccount);
        } else if txn.typeTransaction() != "lock" {
            return Err(CertificateErrors::TransactionNotLock);
        } else if txn.amount != config().fullnode_lock_amount {
            return Err(CertificateErrors::LockedFundsInsufficent);
        }

        let got_data = get_data(
            config().db_path + &"/fn-certificates".to_owned(),
            &(cert.public_key.to_owned() + &"-cert".to_owned()),
        );

        if got_data != "-1".to_string() {
            let exisiting_cert: Certificate = serde_json::from_str(&got_data).unwrap_or_default();
            if exisiting_cert.valid_until
                > (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64)
            {
                return Err(CertificateErrors::WalletAlreadyRegistered);
            }
        }

        if txn.unlock_time - (config().transaction_timestamp_max_offset as u64)
            < (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64)
                + (config().fullnode_lock_time * config().target_epoch_length)
            || txn.unlock_time + (config().transaction_timestamp_max_offset as u64)
                < (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64)
                    + (config().fullnode_lock_time * config().target_epoch_length)
        {
            Err(CertificateErrors::FundLockTimeInsufficent)
        } else if !valid(&cert.invite) {
            Err(CertificateErrors::InvalidInvite)
        } else {
            Ok(())
        }
    }

    pub fn sign(
        &mut self,
        private_key: &String,
        invite: String,
    ) -> Result<(), ring::error::KeyRejected> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key)
                .into_vec()
                .unwrap_or(vec![0])
                .as_ref(),
        )?;

        let msg: &[u8] = self.hash.as_bytes();

        self.signature = bs58::encode(key_pair.sign(msg)).into_string();

        // now sign with the invite
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(invite).into_vec().unwrap_or(vec![0]).as_ref(),
        )?;

        let msg: &[u8] = self.public_key.as_bytes();

        self.invite_sig = bs58::encode(key_pair.sign(msg)).into_string();

        return Ok(());
    }

    pub fn valid_signature(&self) -> bool {
        let msg: &[u8] = self.hash.as_bytes();

        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            bs58::decode(self.public_key.to_owned())
                .into_vec()
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to decode public key from base58 {}, gave error {}",
                        self.public_key, e
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

        // now invite sig

        let msg: &[u8] = self.public_key.as_bytes();

        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            bs58::decode(self.invite.to_owned())
                .into_vec()
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to decode public key from base58 {}, gave error {}",
                        self.public_key, e
                    );

                    return vec![0, 1, 0];
                }),
        );

        peer_public_key
            .verify(
                msg,
                bs58::decode(self.invite_sig.to_owned())
                    .into_vec()
                    .unwrap_or_else(|e| {
                        error!(
                            "failed to decode signature from base58 {}, gave error {}",
                            self.invite_sig, e
                        );

                        return vec![0, 1, 0];
                    })
                    .as_ref(),
            )
            .unwrap_or_else(|_e| {
                return ();
            });
        // ^ wont unwrap if sig is invalid

        return true;
    }

    pub fn check_diff(&self, diff: &u128) -> bool {
        let _fufilled: u8 = 0;

        if number_of_proceding_a(self.hash.clone()) as u128 == diff.to_owned() {
            true
        } else {
            false
        }
    }

    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }
}

/// irelavant clone from blockchain lib to preven cylic dependencys
#[derive(Serialize, Deserialize, Default)]
pub struct HeaderClone {
    pub version_major: u8,
    pub version_breaking: u8,
    pub version_minor: u8,
    pub chain_key: String,
    pub prev_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub network: Vec<u8>,
}

/// irelavant clone from blockchain lib to preven cylic dependencys
#[derive(Serialize, Deserialize, Default)]
pub struct BlockClone {
    pub header: HeaderClone,
    pub txns: Vec<Transaction>,
    pub hash: String,
    pub signature: String,
    pub confimed: bool,
    pub node_signatures: Vec<BlockSignatureClone>,
}

/// irelavant clone from blockchain lib to preven cylic dependencys
#[derive(Serialize, Deserialize, Default)]
pub struct BlockSignatureClone {
    pub hash: String,
    pub timestamp: u64,
    pub block_hash: String,
    pub signer_public_key: String,
    pub signature: String,
    pub nonce: u64,
}

use std::fs::File;
use std::io::prelude::*;

/// irelavant clone from blockchain lib to preven cylic dependencys
fn get_block_from_raw(hash: String) -> BlockClone {
    // returns the block when you only know the hash by opeining the raw blk-HASH.dat file (where hash == the block hash)
    let mut file =
        File::open(config().db_path + &"/blocks/blk-".to_owned() + &hash + ".dat").unwrap();
    let mut contents = String::new();

    let _ = file.read_to_string(&mut contents);

    return serde_json::from_str(&contents).unwrap_or_default();
}
