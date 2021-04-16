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

pub fn difficulty_bytes_as_u128(v: &[u8]) -> u128 {
    ((v[31] as u128) << (0xf * 8))
        | ((v[30] as u128) << (0xe * 8))
        | ((v[29] as u128) << (0xd * 8))
        | ((v[28] as u128) << (0xc * 8))
        | ((v[27] as u128) << (0xb * 8))
        | ((v[26] as u128) << (0xa * 8))
        | ((v[25] as u128) << (0x9 * 8))
        | ((v[24] as u128) << (0x8 * 8))
        | ((v[23] as u128) << (0x7 * 8))
        | ((v[22] as u128) << (0x6 * 8))
        | ((v[21] as u128) << (0x5 * 8))
        | ((v[20] as u128) << (0x4 * 8))
        | ((v[19] as u128) << (0x3 * 8))
        | ((v[18] as u128) << (0x2 * 8))
        | ((v[17] as u128) << 8)
        | v[18] as u128
        | v[19] as u128
        | v[20] as u128
        | v[21] as u128
        | v[22] as u128
        | v[23] as u128
        | v[24] as u128
        | v[25] as u128
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
        let pkcs8_bytes_invite = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
        //let key_pair_invite = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
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
            bs58::encode(pkcs8_bytes_invite).into_string(),
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
    pk: &str,
    private_key: &str,
    txn_hash: &str,
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
        } else if txn.type_transaction() != "lock" {
            return Err(CertificateErrors::TransactionNotLock);
        } else if txn.amount != config().fullnode_lock_amount {
            return Err(CertificateErrors::LockedFundsInsufficent);
        }
        let got_data = get_data(
            config().db_path + &"/fn-certificates".to_owned(),
            &(cert.public_key.to_owned() + &"-cert".to_owned()),
        );

        if got_data != *"-1" {
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

    pub fn check_diff(&self, diff: &u128) -> bool {
        let _fufilled: u8 = 0;

        number_of_proceding_a(self.hash.clone()) as u128 == *diff
    }

    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }
}

/// irelavant clone from blockchain lib to preven cylic dependencys
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
enum BlockTypeClone {
    Send,
    Recieve,
}
impl Default for BlockTypeClone {
    fn default() -> Self {
        BlockTypeClone::Recieve
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
struct HeaderClone {
    pub version_major: u8,
    pub version_breaking: u8,
    pub version_minor: u8,
    pub chain_key: String,
    pub prev_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub network: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
struct BlockClone {
    pub header: HeaderClone,
    pub block_type: BlockTypeClone,
    pub send_block: Option<String>, // the send block this recieve block is in refrence to
    pub txns: Vec<Transaction>,
    pub hash: String,
    pub signature: String,
    pub confimed: bool,
    pub node_signatures: Vec<BlockSignatureClone>, // a block must be signed by at least 2/3 of the commitee's verifyer nodes to be valid (ensures at least one honest node has signed it)
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
struct BlockSignatureClone {
    /// The signature of the vote
    pub hash: String,
    /// The timestamp at which the signature was created
    pub timestamp: u64,
    /// The hash of the block this signature is about        
    pub block_hash: String,
    /// The public key of the node which created this vote
    pub signer_public_key: String,
    /// The hash of the sig signed by the voter        
    pub signature: String,
    /// A nonce to prevent sig replay attacks
    pub nonce: u64,
}

use std::fs::File;
use std::io::prelude::*;

/// irelavant clone from blockchain lib to preven cylic dependencys
fn get_block_from_raw(hash: String) -> BlockClone {
    let try_open = File::open(config().db_path + &"/blocks/blk-".to_owned() + &hash + ".dat");
    if let Ok(mut file) = try_open {
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        let mut ret = BlockClone::default();
        if let Ok(_) = ret.decode_compressed(contents) {
            return ret;
        } else {
            return BlockClone::default();
        }
    } else {
        trace!(
            "Opening raw block file (hash={}) failed. Reason={}",
            hash,
            try_open.unwrap_err()
        );
        BlockClone::default()
    }
}

impl BlockClone {
    pub fn encode_compressed(&self) -> String {
        match self.block_type {
            BlockTypeClone::Recieve => {
                let mut transactions: String = String::from("");
                for txn in &self.txns {
                    transactions += &(txn.encode_compressed() + ","); // TODO: replace with a vector of txn hashes
                }
                return format!(
                    "{}│{}│{}│{}│{}│0│[]",
                    self.header.encode_compressed(),
                    self.send_block.clone().unwrap_or_default(),
                    transactions,
                    self.hash,
                    self.signature,
                );
            }
            BlockTypeClone::Send => {
                let mut transactions: String = String::from("");
                for txn in &self.txns {
                    transactions += &(txn.encode_compressed() + ",");
                }
                return format!(
                    "{}│{}│{}│{}│0│[]",
                    self.header.encode_compressed(),
                    transactions,
                    self.hash,
                    self.signature,
                );
            }
        }
    }

    pub fn decode_compressed(&mut self, encoded: String) -> Result<(), Box<dyn std::error::Error>> {
        let components: Vec<&str> = encoded.split('│').collect();

        if components.len() == 7 {
            // rec block
            self.header.decode_compressed(components[0].to_string())?;
            self.send_block = Some(components[1].to_string());
            self.block_type = BlockTypeClone::Recieve;
            let transactions_string: Vec<&str> = components[2].split(',').collect();
            for txn_string in transactions_string {
                if txn_string != "" {
                    let mut txn_new = Transaction::default();
                    txn_new.decode_compressed(txn_string.to_string())?;
                    self.txns.push(txn_new);
                }
            }
            self.hash = components[3].to_string();
            self.signature = components[4].to_string();
            if components[4] == "0" {
                self.confimed = false;
            } else {
                self.confimed = false;
            }
            self.node_signatures = vec![]; // TODO: read from the encoded string (currently unneeded)
        } else if components.len() == 6 {
            // send block
            self.header.decode_compressed(components[0].to_string())?;
            self.send_block = None;
            self.block_type = BlockTypeClone::Send;
            let transactions_string: Vec<&str> = components[1].split(',').collect();
            for txn_string in transactions_string {
                if txn_string != "" {
                    let mut txn_new = Transaction::default();
                    txn_new.decode_compressed(txn_string.to_string())?;
                    self.txns.push(txn_new);
                }
            }
            self.hash = components[2].to_string();
            self.signature = components[3].to_string();
            if components[4] == "0" {
                self.confimed = false;
            } else {
                self.confimed = false;
            }
            self.node_signatures = vec![]; // TODO: read from the encoded string (currently unneeded)
        } else {
            error!(
                "Failed to decode block, expected len=7 or len=6, got len={}",
                components.len()
            );
            println!("Encoded={}, components={:#?}", encoded, components);
            return Err(format!("components wrong len: {}", components.len()).into());
        }
        Ok(())
    }
}
impl HeaderClone {
    pub fn encode_compressed(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            self.version_major,
            self.version_breaking,
            self.version_minor,
            self.chain_key,
            self.prev_hash,
            self.height,
            self.timestamp,
            bs58::encode(self.network.clone()).into_string()
        )
    }
    pub fn decode_compressed(&mut self, encoded: String) -> Result<(), Box<dyn std::error::Error>> {
        let components: Vec<&str> = encoded.split('|').collect();
        if components.len() != 8 {
            error!(
                "Failed to decode header, expected len=8, got len={}",
                components.len()
            );
            debug!("Encoded={}, components={:#?}", encoded, components);
            return Err(format!("components wrong len, {}", components.len()).into());
        }
        self.version_major = components[0].parse()?;
        self.version_breaking = components[1].parse()?;
        self.version_minor = components[2].parse()?;
        self.chain_key = components[3].to_string();
        self.prev_hash = components[4].to_string();
        self.height = components[5].parse()?;
        self.timestamp = components[6].parse()?;
        self.network = bs58::decode(components[7]).into_vec()?;
        Ok(())
    }
}
