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
    pub node_drop_off_threshold: u64, // percent of online nodes that can go offline before a rearrange
    pub decimal_places: u8,
    pub max_connections: u16,
    pub max_threads: u8,
    pub chain_key: String,
    pub state: u8,
    pub host: u64,
    pub seednodes: Vec<Vec<u8>>,
    pub ignore_minor_updates: bool,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub allow_cors: String,
    pub buffer_bytes: u16,
    pub network_id: String,
    pub node_type: char,
    pub identitiy: String,
}

pub fn config() -> Config {
    let mut file = File::open("node.conf").unwrap();
    let mut data: String = String::from("");
    file.read_to_string(&mut data).unwrap();
    let conf: Config = serde_json::from_str(&data).unwrap();
    return conf;
}

pub fn create_config(conf: Config) -> io::Result<()> {
    let mut file = File::create("node.conf")?;
    file.write_all(serde_json::to_string(&conf).unwrap().as_bytes())?;
    Ok(())
}
