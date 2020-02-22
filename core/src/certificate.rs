/* 
This file handles the generation, validation and saving of the fullnodes certificate
*/

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
  cert.publicKey = pk;
  cert.txnHash = txnHash;
  cert.timestamp = SystemTime::now();
  let diff_cert = config().certificateDifficulty;
  for nonce in u64::maxValue() {
    cert.nonce = nonce;
    cert.hash();
    if cert.checkDiff(&diff_cert) {
      break;
    }
  }
  drop(diff_cert);
  if !cert.sign(&privateKey) {
    Err(certificateErrors::signatureError);
  else {
    Ok(cert);
  }
}
impl Certificate {
  fn validate(&self) -> Result<(), certificateErrors> {
    let cert = self;
    cert.hash();
    let diff_cert = config().certificateDifficulty;
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
    else if txn.type() != "lock" {
      Err(certificateError::transactionNotLock)
    }
    else if txn.amount != lock_amount {
      Err(certificate::lockedFundsInsufficent);
    }
    else if getData(&cert.publicKey + "-cert".to_owned()) {
      Err(certificateError::walletAlreadyRegistered);
    }
    else {
      ok(());
    }
  }
  fn sign(&self, privateKey: &String) -> bool {
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(hex::decode(privateKey).unwrap_or_else(|e| { error!("Failed to decode privatekey {}, gave error {}", privateKey, e); return false; }).as_ref()).unwrap_or_else(|e| { error!("Failed to parse keypair from private key {}, gave error {}", privatekey, e); return false;});
    let msg: &[u8] = cert.hash.as_bytes();
    cert.signature = hex::encode(key_pair.sign(msg));
    return true;
  }
  fn validSignature(&self) -> bool {
     let msg: &[u8] = cert.hash.as_bytes();
     let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, hex::decode(self.publicKey).unwrap_or_else(|e| { error!("Failed to decode public key from hex {}, gave error {}", self.publicKey,e); return false;});
     peer_public_key.verify(msg, hex::decode(self.signature).unwrap_or_else(|e| { error!("failed to decode signature from hex {}, gave error {}", self.signature,e); return false;}).as_ref()).unwrap_or_else(|e| {return false;});
     return true; // ^ wont unwrap if sig is invalid
  }
    
  fn checkDiff(&self, diff: &u64) -> bool {
    if difficulty_bytes_as_u128(self.hash.as_bytes()) < diff {
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
