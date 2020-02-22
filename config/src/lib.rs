use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::io::prelude::*;
extern crate log;
use log::{error, info};
/* use std::net::{IpAddr, Ipv4Addr, Ipv6Addr}; */

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub version_major: u8,
    pub version_breaking: u8,
    pub version_minor: u8,
    pub coin_name: String,
    pub db_path: String,
    pub node_drop_off_threshold: u8,
    pub decimal_places: u8,
    pub max_connections: u16,
    pub max_threads: u8,
    pub chain_key: String,
    pub state: u8,
    pub ip_host: Vec<u16>,
    pub seednodes: Vec<Vec<u16>>,
    pub ignore_minor_updates: bool,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub allow_cors: char,
    pub buffer_bytes: u16,
    pub network_id: Vec<u8>,
    pub node_type: char,
    pub identitiy: String,
    pub key_file_path: String,
    pub log_level: u8, 
    pub min_intrest: f32,
    pub max_intrest: f32,
    pub max_reward: u32,
    pub min_vote: u8,
    pub probatory_epoch_count: u8,
    certificateDifficulty: u64,
}


pub fn config() -> Config {
    let mut file = File::open("node.conf").unwrap_or_else(|e| {
        error!("Failed to Open Config file: {}", e);
        panic!();
    });
    let mut data: String = String::from("");
    file.read_to_string(&mut data).unwrap();
    let conf: Config = serde_json::from_str(&data).unwrap_or_else(|e| {
        error!("Failed To Deserilise Config: {}", e);
        panic!();
    });
    return conf;
}

impl Default for Config {
    fn default () -> Config {
        Config
        {
             version_major: 0,
             version_breaking: 0,
             version_minor: 1,
             coin_name: String::from("Avrio"),
             db_path: String::from("./database"),
             node_drop_off_threshold: 30,
             decimal_places: 4,
             max_connections: 50,
             max_threads: 4,
             chain_key: "".to_string(),
             state: 0,
             ip_host: vec![127,0,0,1,12345],
             seednodes: vec![
                 vec![127,0,0,1],
                 vec![127,0,0,1],
             ],
             ignore_minor_updates: false,
             p2p_port: 12345,
             rpc_port: 54321,
             allow_cors: 'n',
             buffer_bytes: 128,
             network_id: vec![
                 0x61, 0x76, 0x72, 0x69, 0x6f, 0x20, 0x6e, 0x6f, 0x6f, 0x64, 0x6c, 0x65,
             ],
             node_type: 'n',
             identitiy: String::from(""),
             key_file_path: "wallet.keys".to_string(),
             log_level: 2, // 0,1,2,3,4,5 trace, debug, info, warn, error, fatal respectivly
             min_intrest: 0.5,
             max_intrest: 3.0,
             max_reward: 25000,
             min_vote: 65, // min vote to not be banned
             probatory_epoch_count: 10,
             certificateDifficulty: 1000, // TODO find this value
        }
    }
}



impl Config {
    pub fn create(&self) -> io::Result<()> { // create file
        let mut file = File::create("node.conf")?;
        file.write_all(serde_json::to_string(self).unwrap().as_bytes())?;
        Ok(())
    }
    pub fn save(&self) -> io::Result<()> { // save to exisiting/ update
        let mut file = File::open("node.conf")?;
        file.write_all(serde_json::to_string(self).unwrap().as_bytes())?;
        Ok(())
    }
}
