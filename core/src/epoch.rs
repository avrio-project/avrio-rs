// This file handles the saving of epoch details.
extern crate avrio_database;

extern crate avrio_config;

extern crate rand;

use rand::Rng;
use serde::{Deserialize, Serialize};
use avrio_crypto::Hashable;
extern crate bs58;
#[derive(Default, PartialEq, Serialize, Deserialize, Debug)]
pub struct Epoch {
    pub hash: String,
    pub height: u64,
    pub fullnodes_online: u64,
    pub total_coins_movement: u64,
    pub new_coins: u64,
    pub burnt_coins: u64,
    pub locked_coins: u64,
    pub blocks: u64,
    pub average_ttl: u64,
    pub average_vote: u8,
    pub nonce: u64,
}
impl Hashable for Epoch {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.height.to_string().bytes());
        bytes.extend(self.fullnodes_online.to_string().bytes());
        bytes.extend(self.total_coins_movement.to_string().bytes());
        bytes.extend(self.new_coins.to_string().bytes());
        bytes.extend(self.burnt_coins.to_string().bytes());
        bytes.extend(self.locked_coins.to_string().bytes());
        bytes.extend(self.blocks.to_string().bytes());
        bytes.extend(self.average_ttl.to_string().bytes());
        bytes.extend(self.average_vote.to_string().bytes());
        bytes.extend(self.nonce.to_string().bytes());
        bytes
    }
}
impl Epoch {
    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }
    pub fn hash_return(&self) -> String {
        return self.hash_item();
    }
    pub fn new() -> Epoch {
        let mut rng = rand::thread_rng();
        Epoch {
            hash: "".to_owned(),
            height: get_top_epoch().height + 1,
            fullnodes_online: 0,
            total_coins_movement: 0,
            new_coins: 0,
            burnt_coins: 0,
            locked_coins: 0,
            blocks: 0,
            average_ttl: 0,
            average_vote: 0,
            nonce: rng.gen::<u64>(),
        }
    }
}

pub fn get_top_epoch() -> Epoch {
    return Epoch::default();
}
