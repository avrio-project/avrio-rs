extern crate serde_json;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::io::prelude::*;
extern crate log;
use dirs::*;

use sha2::{Digest, Sha256};
#[macro_use]
extern crate lazy_static;
extern crate hex;
use std::sync::RwLock;
lazy_static! {
    static ref CONFIG_STACK: RwLock<Config> = RwLock::new(config_read("node.conf"));
}

/* use std::net::{IpAddr, Ipv4Addr, Ipv6Addr}; */
/// This is the struct that holds the built in network params that are set by the core devs and the same for everyone
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
    pub certificate_difficulty: u128,
    pub fullnode_lock_amount: u64,
    pub transaction_timestamp_max_offset: u32,
    pub max_time_to_live: u64,
    pub target_epoch_length: u64,
    pub fullnode_lock_time: u64,
    pub username_burn_amount: u64,
    pub first_block_hash: String,
    pub min_suported_version: Vec<u8>,
    pub max_supported_version: Vec<u8>,
    pub target_committee_count: u64, // the ideal number of committes to have,if there is not enough fullnodes this will not be reached
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
    pub api_port: u16,
    pub allow_cors: char,
    pub node_type: char,
    pub identitiy: String,
    pub key_file_path: String,
    pub log_level: u8,
    pub wallet_password: String,
    pub max_syncing_peers: u64,
    pub first_epoch_time: u64,
    pub god_account: String, // publickey of the 'god account', the first fullnode who starts the first epoch
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
    pub api_port: u16,
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
    pub certificate_difficulty: u128,
    pub fullnode_lock_amount: u64,
    pub transaction_timestamp_max_offset: u32,
    pub target_epoch_length: u64,
    pub username_burn_amount: u64,
    pub fullnode_lock_time: u64,
    pub first_block_hash: String,
    pub wallet_password: String,
    pub min_suported_version: Vec<u8>,
    pub max_supported_version: Vec<u8>,
    pub max_syncing_peers: u64,
    first_epoch_time: u64,
    god_account: String,
}

pub fn config_read(path: &str) -> Config {
    log::trace!("Reading config from disk");

    if let Ok(mut file) = File::open(path) {
        let mut data: String = String::from("");

        if file.read_to_string(&mut data).is_err() {
            Config::default()
        } else {
            let conf: ConfigSave = serde_json::from_str(&data).unwrap_or_default();

            conf.to_config()
        }
    } else {
        log::trace!("Failed to read from disk");

        Config::default()
    }
}

pub fn config() -> Config {
    CONFIG_STACK.read().unwrap().clone()
}

fn hash_id(id: u64) -> String {
    let mut hasher = Sha256::new();

    hasher.input(format!("{}", id).as_bytes());

    hex::encode(hasher.result())
}

impl Default for ConfigSave {
    fn default() -> ConfigSave {
        let dir = home_dir().unwrap();
        let dir_str = dir.to_str().unwrap();
        ConfigSave {
            db_path: dir_str.to_string() + &"/.avrio-datadir".to_string(),
            max_connections: 50,
            max_threads: 4,
            chain_key: "".to_string(),
            state: 0,
            ip_host: "0.0.0.0".to_string(),
            seednodes: vec![
                "72.137.255.181:56789".to_string(),
                "72.137.255.178:56789".to_string(),
            ],
            ignore_minor_updates: false,
            p2p_port: 56789,
            api_port: 54321,
            allow_cors: 'n',
            node_type: 'n',
            identitiy: hash_id(rand::random::<u64>()),
            key_file_path: "wallet.keys".to_string(),
            log_level: 2, // 0,1,2,3,4 trace, debug, info, warn, error respectivly
            wallet_password: "wallet_password_123".to_string(),
            max_syncing_peers: 8,
            first_epoch_time: 0,
            god_account: String::from(""),
        }
    }
}

impl ConfigSave {
    pub fn to_config(&self) -> Config {
        let nconf = NetworkConfig::default();

        Config {
            db_path: self.db_path.to_owned(),
            max_connections: self.max_connections,
            max_threads: self.max_threads,
            chain_key: self.chain_key.to_owned(),
            state: self.state,
            ip_host: self.ip_host.to_owned(),
            seednodes: self.seednodes.to_owned(),
            ignore_minor_updates: self.ignore_minor_updates,
            p2p_port: self.p2p_port,
            api_port: self.api_port,
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
            certificate_difficulty: nconf.certificate_difficulty,
            decimal_places: nconf.decimal_places,
            min_intrest: nconf.min_intrest,
            min_vote: nconf.min_vote,
            max_intrest: nconf.max_intrest,
            buffer_bytes: nconf.buffer_bytes,
            network_id: nconf.network_id,
            max_reward: nconf.max_reward,
            probatory_epoch_count: nconf.probatory_epoch_count,
            fullnode_lock_amount: nconf.fullnode_lock_amount,
            transaction_timestamp_max_offset: nconf.transaction_timestamp_max_offset,
            target_epoch_length: nconf.target_epoch_length,
            username_burn_amount: nconf.username_burn_amount,
            fullnode_lock_time: nconf.fullnode_lock_time,
            first_block_hash: nconf.first_block_hash,
            wallet_password: self.wallet_password.to_owned(),
            min_suported_version: nconf.min_suported_version,
            max_supported_version: nconf.max_supported_version,
            max_syncing_peers: self.max_syncing_peers,
            first_epoch_time: self.first_epoch_time,
            god_account: self.god_account.to_owned(),
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        ConfigSave::default().to_config()
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
            network_id: vec![0],
            min_intrest: 0.5,
            max_intrest: 2.5,
            max_reward: 25000, // 2.5000 AIO
            min_vote: 65,
            probatory_epoch_count: 10,
            certificate_difficulty: 1000, // TODO find this value
            fullnode_lock_amount: 50000,
            transaction_timestamp_max_offset: 600000, // 10 mins
            max_time_to_live: 600000,                 // millisecconds
            target_epoch_length: 1800000, // 30 mins (technically not target epoch length, but main stage length)
            fullnode_lock_time: 30 * 5,   // epoches (30 days)
            username_burn_amount: 5000,   // 0.5000 AIO
            first_block_hash: "0x...".to_string(),
            min_suported_version: vec![0, 1, 0],
            max_supported_version: vec![0, 1, 0],
            target_committee_count: 2, // consensus & normal
        }
    }
}

impl Config {
    pub fn prep_save(self) -> ConfigSave {
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
            api_port: self.api_port,
            allow_cors: self.allow_cors,
            node_type: self.node_type,
            identitiy: self.identitiy,
            key_file_path: self.key_file_path,
            log_level: self.log_level,
            wallet_password: self.wallet_password,
            max_syncing_peers: self.max_syncing_peers,
            first_epoch_time: self.first_epoch_time,
            god_account: self.god_account,
        }
    }

    /// This creates a config file from the provided struct, if the file exists it does the same thing as save()
    pub fn create(self) -> io::Result<()> {
        // create file
        let mut file = File::create("node.conf")?;
        let mut write_lock = CONFIG_STACK.write().unwrap();
        *write_lock = self.clone();
        file.write_all(serde_json::to_string(&self.prep_save()).unwrap().as_bytes())?;

        Ok(())
    }

    /// This is how you save the config, it is a expensive function on devices with slow storage as it opens and writes to the file
    pub fn save(self) -> io::Result<()> {
        // save to exisiting/ update
        let mut file = File::open("node.conf")?;
        let mut write_lock = CONFIG_STACK.write().unwrap();
        *write_lock = self.clone();
        file.write_all(serde_json::to_string(&self.prep_save()).unwrap().as_bytes())?;

        Ok(())
    }
}
