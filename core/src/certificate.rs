/* 
This file handles the generation, validation and saving of the fullnodes certificate
/*

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

pub struct certificate {
  pub hash: String,
  pub publicKey: String,
  pub txnHash: String,
  pub nonce: u64,
  pub timestamp: u64,
  pub signature: String,
}

impl certificate {
  fn encodeForFile(&self) {
    let mut bytes = vec![];
    bytes.extend(self.hash);
    bytes.extend(self.publicKey);
    bytes.extend(self.txnHash);
    bytes.extend(self.nonce);
    bytes.extend(self.timestamp);
    bytes.extend(self.signature);
    bytes
  }
}
