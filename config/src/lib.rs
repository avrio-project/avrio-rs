use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::io::prelude::*;
/* use std::net::{IpAddr, Ipv4Addr, Ipv6Addr}; */

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    version_major: u32,
    version_minor: u32,
    coin_name: String,
    node_drop_off_threshold: u64, // percent of online nodes that can go offline before a rearrange
    decimal_places: u8,
    max_connections: u16,
    max_threads: u8,
    chain_key: String,
    state: u8,
    host: u64,
    seednodes: Vec<Vec<u8>>,
    ignore_minor_updates: bool,
    p2p_port: u16,
    rpc_port: u16,
    allow_cors: String,
    buffer_bytes: u16,
    network_id: String,
    node_type: char,
    identitiy: String,
}

/* impl Serialize for Config {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Config", 19)?;
        state.serialize_field("version_major", &self.version_major)?;
        state.serialize_field("version_minor", &self.version_minor)?;
        state.serialize_field("coin_name", &self.coin_name)?;
        state.serialize_field("node_drop_off_threshold", &self.node_drop_off_threshold)?;
        state.serialize_field("decimal_places", &self.decimal_places)?;
        state.serialize_field("max_connections", &self.max_connections)?;
        state.serialize_field("max_threads", &self.max_threads)?;
        state.serialize_field("chain_key", &self.chain_key)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("host", &self.host)?;
        state.serialize_field("seednodes", &self.seednodes)?;
        state.serialize_field("ignore_minor_updates", &self.ignore_minor_updates)?;
        state.serialize_field("p2p_port", &self.p2p_port)?;
        state.serialize_field("rpc_port", &self.rpc_port)?;
        state.serialize_field("allow_cors", &self.allow_cors)?;
        state.serialize_field("buffer_bytes", &self.buffer_bytes)?;
        state.serialize_field("network_id", &self.network_id)?;
        state.serialize_field("node_type", &self.node_type)?;
        state.serialize_field("identitiy", &self.identitiy)?;
        state.end()
    }
} */

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
