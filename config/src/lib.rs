extern crate serde_json;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::io::prelude::*;
extern crate log;
use dirs::*;

/* use std::net::{IpAddr, Ipv4Addr, Ipv6Addr}; */
/// This is the struct that holds the built in , network params that are set by the core devs and the same for everyone
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    pub version_major: u8,
    pub version_breaking: u8,
    pub version_minor: u8,
    pub coin_name: String,
    pub node_drop_off_threshold: u8,
    pub decimal_places: u8,
    pub buffer_bytes: u16,
    pub network_id: Vec<u8>,
    pub min_intrest: f32,
    pub max_intrest: f32,
    pub max_reward: u32,
    pub min_vote: u8,
    pub probatory_epoch_count: u8,
    pub certificateDifficulty: u128,
    pub fullnode_lock_amount: u64,
    pub transactionTimestampMaxOffset: u32,
    pub max_time_to_live: u64,
    pub target_epoch_length: u64,
    pub fullnode_lock_time: u64,
    pub username_burn_amount: u64,
    pub first_block_hash: String,
    pub commitee_size: u8,
    pub assessor_node_count: u8,
    pub consensus_commitee_size: u8,
    pub min_suported_version: Vec<u8>,
    pub max_supported_version: Vec<u8>,
}
/// This is what is saved in a file, the stuff the user can change and edit to fit their needs
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigSave {
    pub db_path: String,
    pub max_connections: u16,
    pub max_threads: u8,
    pub chain_key: String,
    pub state: u8,
    pub ip_host: String,
    pub seednodes: Vec<String>,
    pub ignore_minor_updates: bool,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub allow_cors: char,
    pub node_type: char,
    pub identitiy: String,
    pub key_file_path: String,
    pub log_level: u8,
    pub wallet_password: String,
    pub time_beetween_sync: u64,
}
/// This is the entire config - this is what is passed arround in software and what you should use in anything your build
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
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
    pub ip_host: String,
    pub seednodes: Vec<String>,
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
    pub certificateDifficulty: u128,
    pub fullnode_lock_amount: u64,
    pub transactionTimestampMaxOffset: u32,
    pub max_time_to_live: u64,
    pub target_epoch_length: u64,
    pub username_burn_amount: u64,
    pub fullnode_lock_time: u64,
    pub first_block_hash: String,
    pub wallet_password: String,
    pub commitee_size: u8,
    pub assessor_node_count: u8,
    pub consensus_commitee_size: u8,
    pub time_beetween_sync: u64,
    pub min_suported_version: Vec<u8>,
    pub max_supported_version: Vec<u8>,
}

pub fn config() -> Config {
    if let Ok(mut file) = File::open("node.conf") {
        let mut data: String = String::from("");
        if let Err(_) = file.read_to_string(&mut data) {
            return Config::default();
        } else {
            let conf: ConfigSave = serde_json::from_str(&data).unwrap_or_default();
            return conf.toConfig();
        }
    } else {
        return Config::default();
    }
}

impl Default for ConfigSave {
    fn default() -> ConfigSave {
        if let Some(dir) = home_dir() {
            if let Some(dir_str) = dir.to_str() {
                return ConfigSave {
                    db_path: dir_str.to_string() + &"/.avrio-datadir".to_string(),
                    max_connections: 50,
                    max_threads: 4,
                    chain_key: "".to_string(),
                    state: 0,
                    ip_host: "127.0.0.1".to_string(),
                    seednodes: vec![
                        "127.0.0.1:12345".to_string(),
                        "127.0.0.1:123456".to_string(),
                    ],
                    ignore_minor_updates: false,
                    p2p_port: 12345,
                    rpc_port: 54321,
                    allow_cors: 'n',
                    node_type: 'n',
                    identitiy: String::from(""),
                    key_file_path: "wallet.keys".to_string(),
                    log_level: 2, // 0,1,2,3,4,5 trace, debug, info, warn, error, fatal respectivly
                    wallet_password: "wallet_password_123".to_string(),
                    time_beetween_sync: 5 * 60000,
                };
            } else {
                return ConfigSave {
                    db_path: ".avrio-datadir".to_string(),
                    max_connections: 50,
                    max_threads: 4,
                    chain_key: "".to_string(),
                    state: 0,
                    ip_host: "127.0.0.1".to_string(),
                    seednodes: vec![
                        "127.0.0.1:12345".to_string(),
                        "127.0.0.1:123456".to_string(),
                    ],
                    ignore_minor_updates: false,
                    p2p_port: 12345,
                    rpc_port: 54321,
                    allow_cors: 'n',
                    node_type: 'n',
                    identitiy: String::from(""),
                    key_file_path: "wallet.keys".to_string(),
                    log_level: 2, // 0,1,2,3,4,5 trace, debug, info, warn, error, fatal respectivly
                    wallet_password: "wallet_password_123".to_string(),
                    time_beetween_sync: 5 * 60000,
                };
            }
        } else {
            return ConfigSave {
                db_path: ".avrio-datadir".to_string(),
                max_connections: 50,
                max_threads: 4,
                chain_key: "".to_string(),
                state: 0,
                ip_host: "127.0.0.1".to_string(),
                seednodes: vec![
                    "127.0.0.1:12345".to_string(),
                    "127.0.0.1:123456".to_string(),
                ],
                ignore_minor_updates: false,
                p2p_port: 12345,
                rpc_port: 54321,
                allow_cors: 'n',
                node_type: 'n',
                identitiy: String::from(""),
                key_file_path: "wallet.keys".to_string(),
                log_level: 2, // 0,1,2,3,4,5 trace, debug, info, warn, error, fatal respectivly
                wallet_password: "wallet_password_123".to_string(),
                time_beetween_sync: 5 * 60000,
            };
        }
    }
}

impl ConfigSave {
    pub fn toConfig(&self) -> Config {
        let nconf = NetworkConfig::default();
        return Config {
            db_path: self.db_path.to_owned(),
            max_connections: self.max_connections,
            max_threads: self.max_threads,
            chain_key: self.chain_key.to_owned(),
            state: self.state,
            ip_host: self.ip_host.to_owned(),
            seednodes: self.seednodes.to_owned(),
            ignore_minor_updates: self.ignore_minor_updates,
            p2p_port: self.p2p_port,
            rpc_port: self.rpc_port,
            allow_cors: self.allow_cors,
            node_type: self.node_type,
            identitiy: self.identitiy.to_owned(),
            key_file_path: self.key_file_path.to_owned(),
            log_level: self.log_level, // 0,1,2,3,4,5 trace, debug, info, warn, error, fatal respectivly
            version_breaking: nconf.version_breaking,
            version_major: nconf.version_major,
            version_minor: nconf.version_minor,
            coin_name: nconf.coin_name,
            node_drop_off_threshold: nconf.node_drop_off_threshold,
            certificateDifficulty: nconf.certificateDifficulty,
            decimal_places: nconf.decimal_places,
            min_intrest: nconf.min_intrest,
            min_vote: nconf.min_vote,
            max_intrest: nconf.max_intrest,
            buffer_bytes: nconf.buffer_bytes,
            network_id: nconf.network_id,
            max_reward: nconf.max_reward,
            probatory_epoch_count: nconf.probatory_epoch_count,
            fullnode_lock_amount: nconf.fullnode_lock_amount,
            transactionTimestampMaxOffset: nconf.transactionTimestampMaxOffset,
            max_time_to_live: nconf.max_time_to_live,
            target_epoch_length: nconf.target_epoch_length,
            username_burn_amount: nconf.username_burn_amount,
            fullnode_lock_time: nconf.fullnode_lock_time,
            first_block_hash: nconf.first_block_hash,
            wallet_password: self.wallet_password.to_owned(),
            time_beetween_sync: self.time_beetween_sync,
            commitee_size: nconf.commitee_size,
            consensus_commitee_size: nconf.consensus_commitee_size,
            assessor_node_count: nconf.assessor_node_count,
            min_suported_version: nconf.min_suported_version,
            max_supported_version: nconf.max_supported_version,
        };
    }
}
impl Default for Config {
    fn default() -> Config {
        return ConfigSave::default().toConfig();
    }
}

impl Default for NetworkConfig {
    fn default() -> NetworkConfig {
        // This is where you change the network parameters
        NetworkConfig {
            version_major: 0,
            version_breaking: 1,
            version_minor: 0,
            coin_name: "avrio".to_string(),
            node_drop_off_threshold: 30,
            decimal_places: 4,
            buffer_bytes: 128,
            network_id: vec![
                0x61, 0x76, 0x72, 0x69, 0x6f, 0x20, 0x6e, 0x6f, 0x6f, 0x64, 0x6c, 0x65,
            ],
            min_intrest: 0.5,
            max_intrest: 2.5,
            max_reward: 25000, // 2.5000 AIO
            min_vote: 65,
            probatory_epoch_count: 10,
            certificateDifficulty: 1000, // TODO find this value
            fullnode_lock_amount: 50000,
            transactionTimestampMaxOffset: 600,
            max_time_to_live: 600000,      // millisecconds
            target_epoch_length: 18000000, // 5 Hours
            fullnode_lock_time: 30 * 5,    // epoches (30 days)
            username_burn_amount: 5000,    // 0.5000 AIO
            first_block_hash: "0x...".to_string(),
            commitee_size: 15,
            consensus_commitee_size: 21,
            assessor_node_count: 6,
            min_suported_version: vec![0, 1, 0],
            max_supported_version: vec![0, 1, 0],
        }
    }
}

impl Config {
    pub fn toSave(self) -> ConfigSave {
        ConfigSave {
            db_path: self.db_path,
            max_connections: self.max_connections,
            max_threads: self.max_threads,
            chain_key: self.chain_key,
            state: self.state,
            ip_host: self.ip_host,
            seednodes: self.seednodes,
            ignore_minor_updates: self.ignore_minor_updates,
            p2p_port: self.p2p_port,
            rpc_port: self.rpc_port,
            allow_cors: self.allow_cors,
            node_type: self.node_type,
            identitiy: self.identitiy,
            key_file_path: self.key_file_path,
            log_level: self.log_level,
            wallet_password: self.wallet_password,
            time_beetween_sync: self.time_beetween_sync,
        }
    }
    /// This creates a config file from the provided struct, if the file exists it does the same thing as save()
    pub fn create(self) -> io::Result<()> {
        // create file
        let mut file = File::create("node.conf")?;
        file.write_all(serde_json::to_string(&self.toSave()).unwrap().as_bytes())?;
        Ok(())
    }
    /// This is how you save the config, it is a expensive function on devices with slow storage as it opens and writes to the file
    pub fn save(self) -> io::Result<()> {
        // save to exisiting/ update
        let mut file = File::open("node.conf")?;
        file.write_all(serde_json::to_string(&self.toSave()).unwrap().as_bytes())?;
        Ok(())
    }
}
