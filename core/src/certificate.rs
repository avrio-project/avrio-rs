/* 
This file handles the generation, validation and saving of the fullnodes certificate
*/

extern crate hex;
use std::time::{UNIX_EPOCH, SystemTime};
extern crate cryptonight;
extern crate avrio_config;
use avrio_config::config;
extern crate avrio_database;
use avrio_database::{getData, saveData};
use cryptonight::cryptonight;
use crate::transaction::{TxStore};
use ring::{
  rand as randc,
  signature::{self, KeyPair},
};
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

pub struct Certificate {
  pub hash: String, 
  pub publicKey: String,
  pub txnHash: String,
  pub nonce: u64,
  pub timestamp: u64,
  pub signature: String,
}
pub fn difficulty_bytes_as_u128(v: &Vec<u8>) -> u64 {
    ((v[63] as u64) << 0xf * 8)
        | ((v[62] as u64) << 0xe * 8)
        | ((v[61] as u64) << 0xd * 8)
        | ((v[60] as u64) << 0xc * 8)
        | ((v[59] as u64) << 0xb * 8)
        | ((v[58] as u64) << 0xa * 8)
        | ((v[57] as u64) << 0x9 * 8)
        | ((v[56] as u64) << 0x8 * 8)
        | ((v[55] as u64) << 0x7 * 8)
        | ((v[54] as u64) << 0x6 * 8)
        | ((v[53] as u64) << 0x5 * 8)
        | ((v[52] as u64) << 0x4 * 8)
        | ((v[51] as u64) << 0x3 * 8)
        | ((v[50] as u64) << 0x2 * 8)
        | ((v[49] as u64) << 0x1 * 8)
        | ((v[48] as u64) << 0x0 * 8)
}

pub fn generateCertificate(pk: &String, privateKey: &String, txnHash: &String) -> Result<Certificate, certificateErrors> {
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
  cert.timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
  .expect("Time went backwards").as_millis() as u64;
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
    }
    else if !cert.validSignature() {
      return Err(certificateErrors::signatureError);
    }
    else if cert.timestamp > SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() as u64 {
      return Err(certificateErrors::timestampHigh);
    }
    let txn: TxStore = serde_json::from_str(&getData(config().db_path+"/transactions.db", cert.txnHash.to_owned())).unwrap_or_else(|e| {warn!("failed to deserilise Tx, gave error: {}", e); return TxStore::default(); } ); // get the txn to check if it is correct
    if txn == TxStore::default() {
      return Err(certificateErrors::otherTransactionIssue);
    }
    if txn.sender_key != cert.publicKey {
      return Err(certificateErrors::transactionNotOwnedByAccount);
    }
    else if txn.typeTransaction() != "lock" {
      return Err(certificateErrors::transactionNotLock);
    }
    else if txn.amount != config().fullnode_lock_amount {
      return Err(certificateErrors::lockedFundsInsufficent);
    }
    else if getData(config().db_path + "/certifcates.db", cert.publicKey.to_owned() + &"-cert".to_owned()) != "-1".to_string() {
      return Err(certificateErrors::walletAlreadyRegistered);
    }
    else {
      return Ok(());
    }
    return Ok(());
  }
  pub fn sign(&mut self, privateKey: &String) -> Result<(), ring::error::KeyRejected> {
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(hex::decode(privateKey).unwrap().as_ref())?;
    let msg: &[u8] = self.hash.as_bytes();
    self.signature = hex::encode(key_pair.sign(msg));
    return Ok(());
  }
  pub fn validSignature(&self) -> bool {
     let msg: &[u8] = self.hash.as_bytes();
     let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, hex::decode(self.publicKey.to_owned()).unwrap_or_else(|e| { error!("Failed to decode public key from hex {}, gave error {}", self.publicKey,e); return vec![0,1,0];}));
     peer_public_key.verify(msg, hex::decode(self.signature.to_owned()).unwrap_or_else(|e| { error!("failed to decode signature from hex {}, gave error {}", self.signature,e); return vec![0,1,0];}).as_ref()).unwrap_or_else(|e| {return ();});
     return true; // ^ wont unwrap if sig is invalid
  }

  pub fn checkDiff(&self, diff: &u64) -> bool {
    if difficulty_bytes_as_u128(&self.hash.as_bytes().to_vec()) < diff.to_owned() {
      return true;
    }
    else {
      return false;
    }
  }
  pub fn encodeForHashing(&self) -> Vec<u8>{
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
  fn encodeForFile(&self) -> Vec<u8>{
    let mut bytes = vec![];
    bytes.extend(self.hash.bytes());
    bytes.extend(self.publicKey.bytes());
    bytes.extend(self.txnHash.bytes());
    bytes.extend(self.nonce.to_owned().to_string().bytes());
    bytes.extend(self.timestamp.to_owned().to_string().bytes());
    bytes.extend(self.signature.bytes());
    bytes
  }

  fn encodeForHash(&self) -> Vec<u8>{
    let mut bytes = vec![];
    bytes.extend(self.publicKey.bytes());
    bytes.extend(self.txnHash.bytes());
    bytes.extend(self.nonce.to_owned().to_string().bytes());
    bytes.extend(self.timestamp.to_owned().to_string().bytes());
    bytes
  }
}