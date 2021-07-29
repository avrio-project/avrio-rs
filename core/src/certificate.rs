/*
This file handles the generation, validation and saving of the fullnodes certificate
*/

use std::time::{SystemTime, UNIX_EPOCH};
extern crate avrio_config;
use avrio_config::config;
extern crate avrio_database;
use crate::{
    block::get_block_from_raw,
    commitee::Comitee,
    epoch::get_top_epoch,
    invite::{invite_valid, mark_spent},
    transaction::Transaction,
    validate::Verifiable,
};
use avrio_crypto::{public_key_to_address, sign_secp256k1, valid_signature_secp256k1, Hashable};
use avrio_database::{get_data, save_data};
use ring::signature::{self, KeyPair};
use secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
extern crate bs58;
use bls_signatures::{
    verify_messages, PrivateKey, PublicKey, Serialize as blsSerialize, Signature,
};
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
    #[error("Bad Secp256k1 Privatekey")]
    BadSecp256k1PrivateKey,
    #[error("Unknown/Other error")]
    Unknown,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct Certificate {
    pub hash: String,
    pub public_key: String, // base58 encoded, must be a valid account
    pub txn_hash: String,
    pub timestamp: u64,
    pub valid_until: u64,
    pub invite: String,     // base58, should be the publickey of a valid invite
    pub invite_sig: String, // base58, signature using the privatekey of above invite publickey
    pub bls_public_key: String, // base58 encoded, used for aggregate signatures on block chunks
    pub bls_signature: String,
    pub secp256k1_publickey: String, // base58 encoded, used for VRF's
    pub secp256k1_signature: String, // base58 encoded, used to prove ownership of publickey
    pub signature: String,
}

pub fn get_fullnode_count() -> u64 {
    return get_data(config().db_path + "/candidates", "count")
        .parse::<u64>()
        .unwrap_or(0);
}

pub fn generate_certificate(
    pk: &str,
    private_key: &str,
    txn_hash: &str,
    invite: String,
    bls_private_key_string: String,
    secp256k1_privatekey: String,
) -> Result<Certificate, CertificateErrors> {
    let key_pair =
        signature::Ed25519KeyPair::from_pkcs8(bs58::decode(&invite).into_vec().unwrap().as_ref())
            .unwrap();

    let peer_public_key_bytes = key_pair.public_key().as_ref();
    if let Ok(secp256k1_secretkey) = SecretKey::from_slice(
        &bs58::decode(secp256k1_privatekey)
            .into_vec()
            .unwrap_or(vec![]),
    ) {
        let secp = Secp256k1::new();
        let secp256k1_publickey = SecpPublicKey::from_secret_key(&secp, &secp256k1_secretkey);

        let mut cert: Certificate = Certificate {
            hash: String::from(""),
            public_key: String::from(""),
            txn_hash: String::from(""),
            valid_until: 0,
            invite: bs58::encode(peer_public_key_bytes).into_string(),
            invite_sig: "inv_sig".into(),
            timestamp: 0,
            bls_public_key: String::from(""),
            bls_signature: String::from(""),
            secp256k1_publickey: bs58::encode(secp256k1_publickey.serialize()).into_string(),
            secp256k1_signature: String::from(""),
            signature: String::from(""),
        };
        let bls_private_key =
            PrivateKey::from_bytes(&bs58::decode(bls_private_key_string).into_vec().unwrap())
                .unwrap();
        let bls_public_key = bls_private_key.public_key();
        cert.bls_public_key = bs58::encode(bls_public_key.as_bytes()).into_string();

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

        if let Err(_e) = cert.sign(&private_key, invite, &bls_private_key, secp256k1_secretkey) {
            Err(CertificateErrors::SignatureError)
        } else {
            Ok(cert)
        }
    } else {
        return Err(CertificateErrors::BadSecp256k1PrivateKey);
    }
}

impl Hashable for Certificate {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend(self.public_key.bytes());
        bytes.extend(self.txn_hash.bytes());
        bytes.extend(self.invite.bytes());
        bytes.extend(self.timestamp.to_string().bytes());
        bytes.extend(self.valid_until.to_string().bytes());
        bytes.extend(self.bls_public_key.bytes());

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
            // TODO: Check BLS & secp256k1 publickey valid and does not exist
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
        mark_spent(&self.invite)?;
        // now save the BLS publickey to the ECDSA key lookup table
        if save_data(
            &self.public_key,
            &(config().db_path + "/blslookup"),
            self.bls_public_key.clone(),
        ) != 1
        {
            return Err("failed to save ECDSA-BLS looukup entry".into());
        }
        let candidate_count = get_fullnode_count();
        if candidate_count == 0 {
            // there are no candidates registered, this must be the god address (TODO: check this was sent by config().god_account)
            // ecolse this candidate fully
            if save_data(
                "f",
                &(config().db_path + "/candidates"),
                self.public_key.clone(),
            ) != 1
            {
                return Err("failed to save new fullnode candidate".into());
            }
            let mut top_epoch = get_top_epoch()?;
            top_epoch.committees.push(
                Comitee::form_comitees(&mut vec![self.public_key.clone()], &mut vec![], 1)[0]
                    .clone(),
            );
            top_epoch.save()?;
            info!(
                "God account eclosed {}!",
                public_key_to_address(&self.public_key)
            );
        } else {
            if save_data(
                "c",
                &(config().db_path + "/candidates"),
                self.public_key.clone(),
            ) != 1
            {
                return Err("failed to save new fullnode candidate".into());
            }

            info!(
                "New fullnode candidate {}!",
                public_key_to_address(&self.public_key)
            );
        }
        if save_data(
            "count",
            &(config().db_path + "/candidates"),
            (candidate_count + 1).to_string(),
        ) != 1
        {
            return Err("failed to save candidate count".into());
        }
        Ok(())
    }
}

impl Certificate {
    pub fn sign(
        &mut self,
        private_key: &str,
        invite: String,
        bls_private_key: &PrivateKey,
        secp256k1_privatekey: SecretKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // sign with wallet key
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key)
                .into_vec()
                .unwrap_or_else(|_| vec![0])
                .as_ref(),
        );
        if let Err(e) = key_pair {
            return Err(e.description_().into());
        }
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = bs58::encode(key_pair.unwrap().sign(msg)).into_string();

        // sign with bls key
        self.bls_signature = bs58::encode(bls_private_key.sign(msg).as_bytes()).into_string();

        // now sign with the invite
        let invite_key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(invite)
                .into_vec()
                .unwrap_or_else(|_| vec![0])
                .as_ref(),
        );
        if let Err(e) = invite_key_pair {
            return Err(e.description_().into());
        }
        let msg: &[u8] = self.public_key.as_bytes();
        self.invite_sig = bs58::encode(invite_key_pair.unwrap().sign(msg)).into_string();

        // sign with secp256k1 key
        self.secp256k1_signature = sign_secp256k1(
            &bs58::encode(secp256k1_privatekey.as_ref()).into_string(),
            &self.hash,
        )?;
        Ok(())
    }

    pub fn valid_signature(&self) -> bool {
        let msg: &[u8] = self.hash.as_bytes();
        if let Ok(bls_publickey) = PublicKey::from_bytes(
            &bs58::decode(&self.bls_public_key)
                .into_vec()
                .unwrap_or_default(),
        ) {
            if let Ok(signature) = Signature::from_bytes(
                &bs58::decode(&self.bls_signature)
                    .into_vec()
                    .unwrap_or_default(),
            ) {
                if !verify_messages(&signature, &[self.hash.as_bytes()], &[bls_publickey]) {
                    return false;
                }
            } else {
                return false;
            }
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

                        return vec![0];
                    }),
            );

            if let Err(_) = peer_public_key.verify(
                msg,
                bs58::decode(self.invite_sig.to_owned())
                    .into_vec()
                    .unwrap_or_else(|e| {
                        error!(
                            "failed to decode signature from base58 {}, gave error {}",
                            self.invite_sig, e
                        );

                        return vec![];
                    })
                    .as_ref(),
            ) {
                debug!("Invalid invite sig");
                return false;
            }
            // now check the secp256k1 signature
            if let Ok(res) = valid_signature_secp256k1(
                &self.secp256k1_publickey,
                &self.hash,
                &self.secp256k1_signature,
            ) {
                return res;
            } else {
                debug!(
                    "Invalid secp256k1 sig, error={:#?}",
                    valid_signature_secp256k1(
                        &self.secp256k1_publickey,
                        &self.hash,
                        &self.secp256k1_signature
                    )
                    .err()
                );
                return false;
            }
        } else {
            return false;
        }
    }

    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }
}
