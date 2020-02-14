/* 
This file handles the generation, validation and saving of the fullnodes certificate
/*

extern crate hex;
use std::time::{Duration, SystemTime};
extern crate cryptonight;
use cryptonight::cryptonight;

enum certificateErrors {
  transactionNotFound,
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
pub fn generateCertificate(pk: &String, privateKey: &String, txnHash: &String) -> Result<Certificate, certificateErrors> {
  let mut cert: Certificate = Certificate { };
  cert.publicKey = pk;
  cert.txnHash = txnHash;
  cert.timestamp = SystemTime::now();
  let config = config();
  let diff_cert = config.certificateDifficulty
  for nonce in u64::maxValue() {
    cert.nonce = nonce;
    cert.hash();
    if cert.checkDiff(&diff_cert) {
      break ;
    }
  }
  if !cert.sign(&privateKey) {
    Err(certificateErrors::signatureError);
  else {
    Ok(cert);
  }
}
impl Certificate {
  fn validate(&self) -> Result<(), certificateErrors> {
    cert.hash();
    let config = config();
    let diff_cert = config.certificateDifficulty;
    if !cert.checkDiff(diff_cert) {
      Err(certificateErrors::difficultyLow)
    }
    else if !cert.validSignature() {
      Err(certificateErrrors::signatureError)
    }
    else if cert.timestamp > SystemTime::now() {
      Err(certificateErrors::timestampHigh);
    } 
    let txn: String = database::getData(&cert.txnHash); // get the txn to check if it is correct
    if txn.sender_key != cert.publicKey {
      Err(certificateErrors::transactionNotOwnedByAccount);
    }
    else if txn.type() != 'lock' {
      Err(certificateError::transactionNotLock)
    }
    else if txn.amount != lock_amount {
      Err(certificate::lockedFundsInsufficent);
    }
    else if getData(&cert.publicKey + "-cert") {
      Err(certificateError::walletAlreadyRegistered);
    }
    else {
      ok(());
    }
  }
  fn sign(&self, &privateKey) -> bool {
     if !cert.hash {
       return false;
     }
    // fancy cryptographic signature code goes here
    cert.sign = sign(cert.hash, privateKey); 
    return true;
  }
  fn checkDiff(&self, diff: &u64) -> bool {
    if self.hash < diff {
      return true;
    } 
    else {
      return false;
    }
  }
  fn encodeForHashing(&self) -> Vec<u8>{
    let mut bytes = vec![];
    bytes.extend(self.publicKey.bytes());
    bytes.extend(self.txnHash.bytes());
    bytes.extend(self.nonce.to_owned().to_string().bytes());
    bytes.extend(self.timestamp.to_owned().to_string().bytes());
    bytes
  }
  fn hash(&self) {
    let bytes = self.encodeForHashing();
    cryptonight::set_params(655360, 32768);
    let hash = cryptonight::cryptonight(&bytes, bytes.len(), 0);
    cert.hash = String::from(hex::encode(hash));
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
