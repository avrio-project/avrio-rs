/* 
This file handles the generation, validation and saving of the fullnodes certificate
/*

extern crate hex;
use std::time::{Duration, SystemTime};

enum certificateGenerationErrors {
  transactionNotFound,
  walletAlreadyRegistered,
  lockedFundsInsufficent,
  parsingError,
  internalError,
  signatureError,
  otherTransactionIssue,
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
pub fn generateCertificate(pk: &String, privateKey: &String, txnHash: &String) -> Result<certificateGenerationErrors> {
  let mut cert: Certificate = Certificate { };
  cert.publicKey = pk;
  cert.txnHash = txnHash;
  cert.timestamp = SystemTime::now();
  for nonce in u64::maxValue() {
    //
  }
}
impl Certificate {
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
