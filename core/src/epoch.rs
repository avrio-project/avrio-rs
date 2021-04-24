// This file handles the saving of epoch details.
extern crate avrio_database;

extern crate avrio_config;

extern crate rand;

use avrio_config::config;
use avrio_crypto::Hashable;
use avrio_database::{get_data, save_data};
use serde::{Deserialize, Serialize};

use crate::commitee::Comitee;
extern crate bs58;
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct Epoch {
    pub hash: String,
    pub epoch_number: u64,
    pub total_fullnodes: u64,
    pub new_candidates: u64,
    pub total_coins_movement: u64,
    pub new_coins: u64,
    pub burnt_coins: u64,
    pub locked_coins: u64,
    pub blocks: u64,
    pub salt: u64,
    pub committees: Vec<Comitee>,
    pub shuffle_bits: u128,
}
impl Hashable for Epoch {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(self.epoch_number.to_string().bytes());
        bytes.extend(self.total_fullnodes.to_string().bytes());
        bytes.extend(self.total_coins_movement.to_string().bytes());
        bytes.extend(self.new_coins.to_string().bytes());
        bytes.extend(self.burnt_coins.to_string().bytes());
        bytes.extend(self.locked_coins.to_string().bytes());
        bytes.extend(self.blocks.to_string().bytes());
        bytes.extend(self.salt.to_string().bytes());
        for committee in &self.committees {
            bytes.extend(committee.hash.bytes());
        }
        bytes.extend(self.shuffle_bits.to_string().bytes());
        bytes
    }
}
impl Epoch {
    pub fn hash(&mut self) {
        self.hash = self.hash_item();
    }
    pub fn hash_return(&self) -> String {
        self.hash_item()
    }
    pub fn new() -> Epoch {
        Epoch {
            hash: "".to_owned(),
            epoch_number: get_top_epoch().unwrap_or_default().epoch_number + 1,
            total_fullnodes: 0,
            new_candidates: 0,
            total_coins_movement: 0,
            new_coins: 0,
            burnt_coins: 0,
            locked_coins: 0,
            blocks: 0,
            salt: 0,
            committees: vec![],
            shuffle_bits: 0,
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = serde_json::to_string(self)?;
        if save_data(
            &serialized,
            &(config().db_path + "/epochdata"),
            self.epoch_number.to_string(),
        ) == 1
        {
            return Ok(());
        } else {
            return Err("Failed to save data".into());
        }
    }
    pub fn set_top_epoch(&self) -> Result<(), Box<dyn std::error::Error>> {
        if save_data(
            &self.epoch_number.to_string(),
            &(config().db_path + "/epochdata"),
            "topepoch".to_string(),
        ) == 1
        {
            return Ok(());
        } else {
            return Err("Failed to save data".into());
        }
    }
    pub fn get(epoch_number: u64) -> Result<Epoch, Box<dyn std::error::Error>> {
        let got_data = get_data(config().db_path + "/epochdata", &epoch_number.to_string());
        if got_data != "-1" {
            return Ok(serde_json::from_str(&got_data)?);
        } else {
            return Err("could not find epoch data on disk".into());
        }
    }
}
pub fn get_top_epoch() -> Result<Epoch, Box<dyn std::error::Error>> {
    let got_data = get_data(config().db_path + "/epochdata", "topepoch");
    if got_data != "-1" {
        return Epoch::get(got_data.parse()?);
    } else {
        return Err("could not find top epoch height on disk".into());
    }
}
