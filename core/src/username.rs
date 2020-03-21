/*
Copyright 2020 The Avrio Core Developers
This file handles the registartion and validation of txns.
*/

use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, PartialEq, PartialOrd, Ord, Eq, Deserialize, Serialize)]
pub struct UsernameRegistation {
    pub hash: String,
    pub public_key: String,
    pub username: String,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: String,
}

impl UsernameRegistation {
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.public_key.as_bytes());
        bytes.extend(self.username.as_bytes());
        bytes.extend(self.nonce.to_string().as_bytes());
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes
    }
    pub fn hash(&mut self) {
        let as_bytes = self.bytes();
        self.hash = hex::encode(cryptonight::cryptonight(&as_bytes, as_bytes.len(), 0));
    }
    pub fn hash_return(&self) -> String {
        let as_bytes = self.bytes();
        return hex::encode(cryptonight::cryptonight(&as_bytes, as_bytes.len(), 0));
    }
    pub fn sign(
        &mut self,
        private_key: &String,
    ) -> std::result::Result<(), ring::error::KeyRejected> {
        let key_pair =
            signature::Ed25519KeyPair::from_pkcs8(hex::decode(private_key).unwrap().as_ref())?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = hex::encode(key_pair.sign(msg));
        return Ok(());
    }
    pub fn verify_signature(&self) -> bool {
        let public_key_bytes = hex::decode(self.public_key.clone()).unwrap_or(vec![5]);
        if public_key_bytes.len() == 1 && public_key_bytes[0] == 5 {
            return false;
        }
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        match peer_public_key.verify(
            self.hash.as_bytes(),
            &hex::decode(&(self.signature).to_owned()).unwrap(),
        ) {
            Ok(()) => {
                return true;
            }
            _ => return false,
        }
    }
}
