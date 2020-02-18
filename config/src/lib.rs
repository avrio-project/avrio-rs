use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::io::prelude::*;
/* use std::net::{IpAddr, Ipv4Addr, Ipv6Addr}; */

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub version_major: u32,
    pub version_minor: u32,
    pub coin_name: String,
    pub node_drop_off_threshold: u64,
    pub decimal_places: u8,
    pub max_connections: u16,
    pub max_threads: u8,
    pub chain_key: String,
    pub state: u8,
    pub ip_host: Vec<u8>,
    pub seednodes: Vec<Vec<u8>>,
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
}

pub fn config() -> Config {
    let mut file = File::open("node.conf").unwrap_or_else(|e| {
        errror!("Failed to Open Config file: {}", e);
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
impl Config {
    pub fn new_default() -> Config { // creates a config struct with default value (using Config::new_default()) // TODO
        return Config {
            //
        };
    }
    pub fn create(&self) -> io::Result<()> { // create file
        let mut file = File::create("node.conf")?;
        file.write_all(serde_json::to_string(&conf).unwrap().as_bytes())?;
        Ok(())
    }
    pub fn save(&self) -> io::Result<()> { // save to exisiting/ update
        let mut file = File::open("node.conf")?;
        file.write_all(serde_json::to_string(&conf).unwrap().as_bytes())?;
        Ok(())
    }
}
