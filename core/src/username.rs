/*
Copyright 2020 The Avrio Core Developers
This file handles the registartion and validation of txns.
*/

use avrio_crypto::Hashable;
use ring::signature::{self};
use serde::{Deserialize, Serialize};
extern crate bs58;
#[derive(Debug, Default, PartialEq, PartialOrd, Ord, Eq, Deserialize, Serialize)]
pub struct UsernameRegistation {
    pub hash: String,
    pub public_key: String,
    pub username: String,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: String,
}
impl Hashable for UsernameRegistation {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.public_key.as_bytes());
        bytes.extend(self.username.as_bytes());
        bytes.extend(self.nonce.to_string().as_bytes());
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes
    }
}
impl UsernameRegistation {
    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }

    pub fn hash_return(&self) -> String {
        self.hash_item()
    }

    pub fn sign(&mut self, private_key: &str) -> std::result::Result<(), ring::error::KeyRejected> {
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            bs58::decode(private_key)
                .into_vec()
                .unwrap_or_else(|_| vec![0])
                .as_ref(),
        )?;
        let msg: &[u8] = self.hash.as_bytes();
        self.signature = bs58::encode(key_pair.sign(msg)).into_string();
        Ok(())
    }

    pub fn verify_signature(&self) -> bool {
        let public_key_bytes = bs58::decode(self.public_key.clone())
            .into_vec()
            .unwrap_or_else(|_| vec![5]);
        if public_key_bytes.len() == 1 && public_key_bytes[0] == 5 {
            return false;
        }
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        matches!(
            peer_public_key.verify(
                self.hash.as_bytes(),
                &bs58::decode(&(self.signature).to_owned())
                    .into_vec()
                    .unwrap_or_else(|_| vec![0]),
            ),
            Ok(())
        )
    }
}
