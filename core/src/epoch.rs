// This file handles the saving of epoch details.
extern crate avrio_database;
use avrio_database::{getData, saveData};
extern crate avrio_config;
use avrio_config::config;
extern crate rand;

use rand::Rng;
use serde::{Serialize, Deserialize};

#[derive(Defualt, PartialEq, PartialOrq, Serialize, Deserialize, Debug)]
struct Epoch {
    hash: String,
    height: u64,
    fullnodes_online: u64,
    total_coins_movement: u64,
    new_coins: u64,
    burnt_coins: u64,
    locked_coins: u64,
    blocks: u64,
    average_ttl: u64,
    average_vote: u8,
    nonce: u64,
}

impl Epoch {
    fn generate() -> Epoch {
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

fn getTopEpoch() -> Epoch {
    return Epoch::default();
}