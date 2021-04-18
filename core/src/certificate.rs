/*
This file handles the generation, validation and saving of the fullnodes certificate
*/

use std::time::{SystemTime, UNIX_EPOCH};
extern crate avrio_config;
use avrio_config::config;
extern crate avrio_database;
use crate::{
    block::get_block_from_raw, invite::invite_valid, transaction::Transaction, validate::Verifiable,
};
use avrio_database::{get_data, save_data};

use avrio_crypto::Hashable;
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use thiserror::Error;
extern crate bs58;

#[derive(Debug, PartialEq, Error)]
pub enum CertificateErrors {
    #[error("Lock transaction not found")]
    TransactionNotFound,
    #[error("Already a fullnode")]
    WalletAlreadyRegistered,
    #[error("Locked funds too low")]
    LockedFundsInsufficent,
    #[error("Lock transaction unlocks too early")]
    FundLockTimeInsufficent,
    #[error("Failed to parse certificate")]
    ParsingError,
    #[error("Internal error while processing certificate")]
    InternalError,
    #[error("Signature invalid")]
    SignatureError,
    #[error("Transaction other issue")]
    OtherTransactionIssue,
    #[error("Timestamp too far in future")]
    TimestampHigh,
    #[error("Lock transaction not sent by registering party")]
    TransactionNotOwnedByAccount,
    #[error("Transaction wrong type")]
    TransactionNotLock,
    #[error("Bad PoW")]
    DifficultyLow,
    #[error("Invite invalid")]
    InvalidInvite,
    #[error("Certificate hash mismatch")]
    HashMissmatch,
    #[error("Unknown/Other error")]
    Unknown,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct Certificate {
    pub hash: String,
    pub public_key: String,
    pub txn_hash: String,
    pub timestamp: u64,
    pub valid_until: u64,
    pub invite: String,
    pub invite_sig: String,
    pub signature: String,
}

pub fn generate_certificate(
    pk: &str,
    private_key: &str,
    txn_hash: &str,
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
    let block_hash = get_data(config().db_path + "/transactions", &cert.txn_hash);
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

    cert.hash();

    if let Err(_e) = cert.sign(&private_key, invite) {
        Err(CertificateErrors::SignatureError)
    } else {
        Ok(cert)
    }
}

impl Hashable for Certificate {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.public_key.bytes());
        bytes.extend(self.txn_hash.bytes());
        bytes.extend(self.invite.bytes());
        bytes.extend(self.timestamp.to_owned().to_string().bytes());
        bytes.extend(self.valid_until.to_owned().to_string().bytes());

        bytes
    }
}

impl Verifiable for Certificate {
    fn valid(&self) -> Result<(), Box<dyn std::error::Error>> {
        let cert = self;

        if cert.hash != cert.hash_item() {
            return Err(Box::new(CertificateErrors::HashMissmatch));
        }
        if !cert.valid_signature() {
            return Err(Box::new(CertificateErrors::SignatureError));
        } else if cert.timestamp
            > SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64
        {
            return Err(Box::new(CertificateErrors::TimestampHigh));
        }
        let block_hash = get_data(config().db_path + "/transactions", &cert.txn_hash);
        let blk = get_block_from_raw(block_hash); // get the txn to check if it is correct
        let mut txn: Transaction = Default::default();

        for transaction in blk.txns {
            if transaction.hash == cert.txn_hash {
                txn = transaction;
            }
        }

        if txn == Transaction::default() {
            return Err(Box::new(CertificateErrors::OtherTransactionIssue));
        }

        if txn.sender_key != cert.public_key {
            return Err(Box::new(CertificateErrors::TransactionNotOwnedByAccount));
        } else if txn.type_transaction() != "lock" {
            return Err(Box::new(CertificateErrors::TransactionNotLock));
        } else if txn.amount != config().fullnode_lock_amount {
            return Err(Box::new(CertificateErrors::LockedFundsInsufficent));
        }

        if let Ok(exisiting_cert) = Certificate::get(cert.public_key.clone()) {
            if exisiting_cert.valid_until
                > (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64)
            {
                return Err(Box::new(CertificateErrors::WalletAlreadyRegistered));
            }
        }
        /*if txn.unlock_time - (config().transaction_timestamp_max_offset as u64)
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
            Err(Box::new(CertificateErrors::FundLockTimeInsufficent))
        } else */
        if !invite_valid(&cert.invite) {
            Err(Box::new(CertificateErrors::InvalidInvite))
        } else {
            Ok(())
        }
    }

    fn get(public_key: String) -> Result<Box<Self>, Box<dyn std::error::Error>> {
        let got_data = get_data(
            config().db_path + &"/fn-certificates".to_owned(),
            &(public_key + &"-cert".to_owned()),
        );
        if got_data != "-1" {
            let decoded: Certificate = serde_json::from_str(&got_data)?;
            return Ok(Box::new(decoded));
        } else {
            return Err("Certificate not found".into());
        }
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        if save_data(
            &serde_json::to_string(self)?,
            &(config().db_path + &"/fn-certificates".to_owned()),
            self.public_key.clone() + &"-cert".to_owned(),
        ) == 1
        {
            return Ok(());
        } else {
            return Err("Certificate not found".into());
        }
    }

    fn enact(&self) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}

impl Certificate {
    pub fn sign(
        &mut self,
        private_key: &str,
        invite: String,
    ) -> Result<(), ring::error::KeyRejected> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key)
                .into_vec()
                .unwrap_or_else(|_| vec![0])
                .as_ref(),
        )?;

        let msg: &[u8] = self.hash.as_bytes();

        self.signature = bs58::encode(key_pair.sign(msg)).into_string();

        // now sign with the invite
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(invite)
                .into_vec()
                .unwrap_or_else(|_| vec![0])
                .as_ref(),
        )?;

        let msg: &[u8] = self.public_key.as_bytes();

        self.invite_sig = bs58::encode(key_pair.sign(msg)).into_string();

        Ok(())
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
            .unwrap_or_else(|_e| {});

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
            .unwrap_or_else(|_e| {});
        // ^ wont unwrap if sig is invalid

        true
    }

    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }
}
