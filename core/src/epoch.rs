// This file handles the saving of epoch details.
extern crate avrio_database;
use avrio_database::{getData, saveData};
extern crate avrio_config;
use avrio_config::config;
extern crate rand;

use rand::Rng;
use serde::{Serialize, Deserialize};

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

impl Epoch {
    pub fn generate() -> Epoch {
        let mut rng = rand::thread_rng();
        Epoch {
            hash: "".to_owned(),
            height: getTopEpoch().height + 1,
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

pub fn getTopEpoch() -> Epoch {
    return Epoch::default();
}