/*
Copyright the Avrio Core Developers 2020

This file handles the creation/ calculation and validation of node votes
*/
use avrio_crypto::Hashable;
extern crate bs58;
use std::time::Instant;
extern crate hex;
use ring::signature::{self};
use std::error::Error;
extern crate avrio_config;
use avrio_config::config;
pub struct Vote {
    /// The hash of the vote
    pub hash: String,
    /// The timestamp at which the vote was created
    pub timestamp: u64,
    /// The public key of the node this vote is about        
    pub subject_public_key: String,
    /// The public key of the node which created this vote
    pub voter_public_key: String,
    /// The vote (0-100)
    pub vote: u8,
    /// The hash of the vote signed by the voter        
    pub signature: String,
    /// A nonce to prevent vote replay attacks
    pub nonce: u64,
}
impl Hashable for Vote {
    // Concaticates all hash inclusive (anything that should be in the hash, eg not signature and not the hash) into a vector of bytes. Needed for hashable trait
    fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes.extend(self.subject_public_key.as_bytes());
        bytes.extend(self.voter_public_key.as_bytes());
        bytes.extend(self.vote.to_string().as_bytes());
        bytes.extend(self.nonce.to_string().as_bytes());
        bytes
    }
}
impl Vote {
    /// Handles the creation of votes. Takes in assessed parameters and outputs a Vote class ready for hashing, signing etc
    pub fn calculate(prt: u64, ttl: u64, tvt: u64, tvc: u32, attl: u64) -> u8 {
        let config = config();
        let mut vote: u8 = 0;
        let mttl = config.max_time_to_live;
        if ttl <= attl {
            vote += 30; // max
        } else if ttl > mttl {
            return 0;
        } else {
            vote += 50 - ((attl - ttl) / 5) as u8;
        }
        match prt {
            0..=200 => vote += 50, // max
            201..=700 => vote += 50 - (prt / 10) as u8,
            _ => return 0,
        }
        let mut tpt = tvt / tvc as u64;
        if tpt < prt {
            vote += 20; // max
        } else {
            tpt -= prt;
            vote += 50 - (tpt as u8);
        }
        if vote > 100 {
            // how would happen i have no idea but it is worth catching just incase
            vote = 100;
        }
        vote
    }

    /// hashes this object and sets the hash value to the computed hash.
    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }

    /// hashes this object (without modifying the hash value) and returns it as a string
    pub fn hash_return(&self) -> String {
        self.hash_item()
    }

    /// signs this vote object, takes in a mutable refrence to self and a private key (as a String)
    pub fn sign(&mut self, private_key: String) -> Result<(), ring::error::KeyRejected> {
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

    /// concaticates and returns entire object into a Vector of bytes, no delimmiter token (so its one way) but used for hashing. Order important
    pub fn bytes_all(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.hash.as_bytes());
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes.extend(self.subject_public_key.as_bytes());
        bytes.extend(self.voter_public_key.as_bytes());
        bytes.extend(self.vote.to_string().as_bytes());
        bytes.extend(self.nonce.to_string().as_bytes());
        bytes.extend(self.signature.as_bytes());
        bytes
    }

    /// Constructer, takes in subject (publickey, string), voter: (pubilickey, String), vote (int, 0-100 inclusive), private_key (corrosponding priv key to voter, string) and nonce (cryptographic salt please, u64)
    /// Returns a result containing the new class object (in casees of succsess), or a heap allocated Error trait, in most cases it will be a String err (Box<dyn Error>)
    pub fn new(
        subject: String,
        voter: String,
        vote: u8,
        private_key: String,
        nonce: u64,
    ) -> Result<Vote, Box<dyn Error>> {
        let time = Instant::now().elapsed().as_millis() as u64;
        let mut vote = Vote {
            hash: "".to_string(),
            signature: "".to_string(),
            timestamp: time,
            voter_public_key: voter,
            subject_public_key: subject,
            vote,
            nonce,
        }; // Create a new object containing parameters then hash and sign said object with private key
        vote.hash();
        let res = vote.sign(private_key);
        if res.is_err() {
            Err("Signature Failed".into()) // signing failed return a error type
        } else {
            Ok(vote) // signing worked, return object
        }
    }

    /// Takes a reference to self and verifies contained signature, returns a bool (true=valid signature, false=signature_invalid or error)
    pub fn signature_valid(&self) -> bool {
        let msg: &[u8] = self.hash.as_bytes(); // turn the hash into a array of bytes (utf8 format)
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            bs58::decode(self.voter_public_key.to_owned()) // try to decode public key from base58
                .into_vec()
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to decode public key from hex {}, gave error {}",
                        self.voter_public_key, e
                    );
                    return vec![0, 1, 0];
                }),
        );
        let mut res: bool = true;
        peer_public_key
            .verify(
                // verify signature
                msg,
                bs58::decode(self.signature.to_owned()) // decode signature from base58
                    .into_vec()
                    .unwrap_or_else(|e| {
                        error!(
                            "failed to decode signature from hex {}, gave error {}",
                            self.signature, e
                        );
                        return vec![0, 1, 0];
                    })
                    .as_ref(),
            )
            .unwrap_or_else(|_e| {
                res = false;
            });
        res
    }
}
