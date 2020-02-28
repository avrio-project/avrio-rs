/*
Copyright the Avrio Core Developers 2020

This file handles the creation/ calculation and validation of node votes
*/
extern crate cryptonight;
use cryptonight::cryptonight;
use std::time::Instant;
extern crate hex;
use std::error::Error;
extern crate avrio_config;
use avrio_config::config;
pub struct Vote {
    pub hash: String,               // The hash of the vote
    pub timestamp: u64,             // The timestamp at which the vote was created
    pub subject_public_key: String, // The public key of the node this vote is about
    pub voter_public_key: String,   // The public key of the node which created this vote
    pub vote: u8,                   // The vote (0-100)
    pub signature: String,          // The hash of the vote signed by the voter
}

impl Vote {
    pub fn calculate(prt: u64, ttl: u64, tvt: u64, tvc: u32, attl: u64) -> u8 {
        let config = config();
        let mut vote: u8 = 0;
        let mttl = config.max_time_to_live;
        if ttl <= attl {
            vote += 30; // max
        } else if ttl > mttl {
            return 0;
        } else {
            vote += (50 - ((attl - ttl) / 5) as u8);
        }
        match prt {
            0..=200 => vote += 50, // max
            201..=700 => vote += (50 - (prt / 10) as u8),
            _ => return 0,
        }
        drop(mttl);
        let mut tpt = (tvt / tvc as u64);
        if tpt < prt {
            vote += 20; // max
        } else {
            tpt -= prt;
            vote += (50 - (tpt as u8));
        }
        if vote > 100 {
            // how would happen i have no idea but it is worth catching just incase
            vote = 100;
        }
        return vote;
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes.extend(self.subject_public_key.as_bytes());
        bytes.extend(self.voter_public_key.as_bytes());
        bytes.extend(self.vote.to_string().as_bytes());
        bytes
    }
    pub fn hash(&mut self) {
        let as_bytes = self.bytes();
        unsafe {
            self.hash = hex::encode(cryptonight(&as_bytes, as_bytes.len(), 0));
        }
    }
    pub fn hash_return(&self) -> String {
        let as_bytes = self.bytes();
        unsafe {
            return hex::encode(cryptonight(&as_bytes, as_bytes.len(), 0));
        }
    }
    pub fn sign(&mut self) {
        return (); // TODO
    }
    pub fn bytes_all(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.hash.as_bytes());
        bytes.extend(self.timestamp.to_string().as_bytes());
        bytes.extend(self.subject_public_key.as_bytes());
        bytes.extend(self.voter_public_key.as_bytes());
        bytes.extend(self.vote.to_string().as_bytes());
        bytes.extend(self.signature.as_bytes());
        bytes
    }
    pub fn new(
        subject: String,
        voter: String,
        vote: u8,
        privateKey: String,
    ) -> Result<Vote, Box<dyn Error>> {
        let time = Instant::now().elapsed().as_millis() as u64;
        let mut vote = Vote {
            hash: "".to_string(),
            signature: "".to_string(),
            timestamp: time,
            voter_public_key: voter,
            subject_public_key: subject,
            vote,
        };
        vote.hash();
        vote.sign();
        return Ok(vote);
    }
}
