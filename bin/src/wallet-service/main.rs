#![feature(proc_macro_hygiene, decl_macro)]

extern crate lazy_static;
extern crate log;
use aead::NewAead;
use aead::{generic_array::GenericArray, Aead};
use aes_gcm::Aes256Gcm;
use avrio_config::config;
use avrio_core::account::to_dec;
use avrio_core::block::genesis::{generate_genesis_block, get_genesis_block, GenesisBlockErrors};
use avrio_core::block::{Block, BlockType, Header};
use avrio_core::transaction::Transaction;
use avrio_crypto::{raw_hash, Wallet};

use clap::{App, Arg, ArgMatches};
use common::*;
use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{Read, Write},
    sync::Mutex,
};

use rocket::config::{Environment, LoggingLevel};

#[macro_use]
extern crate rocket;
mod methods_v1;

lazy_static! {
    static ref USERS: Mutex<HashMap<String, Vec<String>>> = Mutex::new(HashMap::new());
    static ref OPEN_WALLETS: Mutex<HashMap<String, OpenedWallet>> = Mutex::new(HashMap::new());
    static ref CONFIG: Mutex<Option<ApiConfig>> = Mutex::new(None);
}

pub fn user_auth_level(key: String) -> Result<Vec<String>, ()> {
    let lock = USERS.lock().unwrap();
    let hashmap = &*lock;
    if hashmap.contains_key(&key) {
        return Ok(hashmap[&key].clone());
    }
    Err(())
}

#[derive(Clone, Debug)]
pub struct OpenedWallet {
    path: String,
    password: String,
    wallet: Wallet,
    meta: WalletMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletMetadata {
    pub balance: u64,
    pub locked: u64,
    pub last_update: u64, // the last "sync" time
    pub account_nonce: u64,
}
/// # WalletSave
/// This pub struct will be serilized into a string, and then encryped using the provided salt + password

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletSave {
    pub publickey: String,
    pub privatekey: String,
    pub metadata: WalletMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApiConfig {
    pub bind_address: String,
    pub bind_port: u64,
    pub api_password: Option<String>,
    pub node_address: String,
    pub refresh_interval: u64,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_address: String::from("127.0.0.1"),
            bind_port: 8040,
            api_password: Some(String::from("admin")),
            node_address: String::from("http://127.0.0.1:8000"),
            refresh_interval: 60,
        }
    }
}

impl ApiConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_str(&mut self, as_str: &str) -> Result<(), Box<dyn std::error::Error>> {
        let decoded: Self = serde_json::from_str(as_str)?;
        *self = decoded;
        Ok(())
    }

    pub fn to_string(&self) -> Result<String, Box<dyn std::error::Error>> {
        return Ok(serde_json::to_string(self)?);
    }
}

pub fn save_to_disk(path: String, data: String) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().write(true).create(true).open(path)?;
    file.write(data.as_bytes())?;
    Ok(())
}
pub fn load_from_disk(
    path: String,
    create_if_missing: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(create_if_missing)
        .create(create_if_missing)
        .open(path)?;
    let mut content = String::new();
    let _ = file.read_to_string(&mut content)?;
    Ok(content)
}

impl WalletSave {
    pub fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_string(str: &str) -> Result<WalletSave, Box<dyn std::error::Error>> {
        let decoded: Self = serde_json::from_str(str)?;
        Ok(decoded)
    }
}

impl OpenedWallet {
    /// Open
    /// Opens a wallet and returns the OpenedWallet pub struct
    /// It is up to you to add it to relivent handler streams, locks etc
    pub fn open(name: String, password: String) -> Result<Self, Box<dyn std::error::Error>> {
        let conf = avrio_config::config();
        let path = conf.db_path.clone() + &"/wallets/".to_owned() + &name;
        let mut padded = password.as_bytes().to_vec();
        while padded.len() != 32 && padded.len() < 33 {
            padded.push(b"n"[0]);
        }
        let padded_string = String::from_utf8(padded).unwrap();
        trace!("key: {}", padded_string);
        let key = GenericArray::clone_from_slice(padded_string.as_bytes());
        let aead = Aes256Gcm::new(&key);
        let mut padded = b"nonce".to_vec();
        while padded.len() != 12 {
            padded.push(b"n"[0]);
        }
        let padded_string = String::from_utf8(padded).unwrap();
        let nonce = GenericArray::from_slice(padded_string.as_bytes()); // 96-bits; unique per message
        trace!("nonce: {}", padded_string);
        let ciphertext = hex::decode(load_from_disk(path.clone(), false)?)?;
        let cleartest = String::from_utf8(
            aead.decrypt(nonce, ciphertext.as_ref())
                .expect("decryption failure!"),
        )
        .expect("failed to parse utf8 (i1)");
        let wallet_save: WalletSave = serde_json::from_str(&cleartest).unwrap();

        Ok(Self {
            path,
            password,
            wallet: Wallet::from_private_key(wallet_save.privatekey),
            meta: wallet_save.metadata,
        })
    }

    pub fn create_wallet(
        path: String,
        password: String,
        private_key: String,
        user: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let wallet = Wallet::from_private_key(private_key);
        let meta = WalletMetadata {
            balance: 0,
            locked: 0,
            last_update: 0,
            account_nonce: 0,
        };
        let mut wall = OpenedWallet {
            path,
            password,
            wallet,
            meta,
        };

        match USERS.lock() {
            Ok(mut users_lock) => {
                trace!("Got lock on USERS mutex");
                let users_hashmap = &mut *users_lock;
                if users_hashmap.contains_key(&user) {
                    let mut wallets_vec = users_hashmap[&user].clone();
                    wallets_vec.push(wall.path.clone());
                    users_hashmap.insert(user, wallets_vec);
                    *users_lock = users_hashmap.to_owned();
                } else {
                    error!("Tried to create a wallet under user with access code: {}, but access code does not exist. TIP: have you created the user profile yet?", user);
                    return Err("User does not exist".into());
                }
            }
            Err(e) => {
                error!("Failed to lock users mutex, error={}", e);
                return Err("Failed to lock users mutex".into());
            }
        }
        wall.init_wallet()?;
        wall.disk_flush(true)?;
        wall.refresh()?;
        wall.disk_flush(false)?;
        return Ok(wall);
    }

    pub fn add_to_locks(&self, user: &String) -> Result<(), Box<dyn std::error::Error>> {
        match OPEN_WALLETS.lock() {
            Ok(mut mutex_lock) => {
                mutex_lock.insert(raw_hash(&self.path), self.clone());
                trace!(
                    "Added wallet to locks, path={}, {:#?}",
                    self.path,
                    mutex_lock
                );
            }
            Err(e) => {
                error!("PoisionError: Cannot lock mutex (error={})", e);
                return Err(format!("Cannot lock open_wallet details mutex, error={}", e).into());
            }
        }
        match USERS.lock() {
            Ok(mut mutex_lock) => {
                if !mutex_lock.contains_key(user) {
                    error!("Cannot add wallet for unknown user {}", user);
                    return Err("User not found in user details mutex".into());
                }
                let mut curr = mutex_lock[user].clone();
                curr.push(self.path.clone());
                mutex_lock.insert(user.clone(), curr);
                trace!("Added wallet to user, {:#?}", mutex_lock);
            }
            Err(e) => {
                error!("PoisionError: Cannot lock mutex (error={})", e);
                return Err(format!("Cannot lock user details mutex, error={}", e).into());
            }
        }
        Ok(())
    }

    /// Close
    /// Takes in an OpenedWallet and closes it
    /// This refreshes the wallet and then flushes the meta data to disk (simmilar to a disk_flush)
    pub fn close(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.refresh();
        self.disk_flush(false)?;
        // TODO: close the wallet
        todo!()
    }

    pub fn get_balance(&self) -> u64 {
        self.meta.balance
    }

    pub fn get_locked(&self) -> u64 {
        self.meta.locked
    }

    /// # Refresh
    /// Polls the connected rpc server to refresh this wallets details
    /// If this chain does not exist, this will also create the chain (via sending the genesis blocks)
    pub fn refresh(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let request_url = format!(
            "{}/api/v1/balances/{}",
            CONFIG.lock().unwrap().as_ref().unwrap().node_address,
            self.wallet.public_key
        );
        if let Ok(response_undec) = reqwest::blocking::get(&request_url) {
            if let Ok(response) = response_undec.json::<Balances>() {
                info!(
                    "Balance: {}, Locked: {}",
                    to_dec(response.balance),
                    to_dec(response.locked)
                );
                if let Ok(mut locked_ls) = OPEN_WALLETS.lock() {
                    self.meta.balance = response.balance;
                    self.meta.locked = response.locked;
                    (*locked_ls).insert(self.path.clone(), self.to_owned());
                    drop(locked_ls);
                } else {
                    error!("Failed to lock OPENED_WALLETS mutex");
                }
            } else {
                error!("Failed to decode recieved 'balances' json");
            }
        } else {
            error!("Failed to request {}", request_url);
        }
        let request_url = format!(
            "{}/api/v1/transactioncount/{}",
            CONFIG.lock().unwrap().as_ref().unwrap().node_address,
            self.wallet.public_key
        );
        if let Ok(response) = reqwest::blocking::get(&request_url) {
            if let Ok(transactioncount) = response.json::<Transactioncount>() {
                if let Ok(mut locked_ls) = OPEN_WALLETS.lock() {
                    let mut wallet_details = (*locked_ls)
                        .get(&raw_hash(&self.path))
                        .unwrap_or(&self)
                        .clone();
                    wallet_details.meta.account_nonce = transactioncount.transaction_count;

                    (*locked_ls).insert(self.path.clone(), wallet_details);
                    return Ok(());
                } else {
                    error!("Failed to lock OPENED_WALLETS mutex");
                    return Err("Failed to lock OPENED_WALLETS mutex".into());
                }
            } else {
                error!("Failed to decode recieved 'transactioncount' json");
                return Err("Failed to decode recieved 'transactioncount' json".into());
            }
        } else {
            error!("Failed to request {}", request_url);
            return Err("Failed to request transactioncount".into());
        }
    }

    /// # Init wallet
    /// Sets up the OpenedWallet struct by polling the node
    /// You should have already created the OpenedWallet struct using open or create_wallet first
    pub fn init_wallet(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let wallet: OpenedWallet;
        if let Ok(locked_ls) = OPEN_WALLETS.lock() {
            trace!("got lock on OPEN_WALLETS mutex");
            wallet = locked_ls
                .get(&raw_hash(&self.path))
                .unwrap_or(&self)
                .clone();
        } else {
            error!("Failed to get lock on OPEN_WALLETS mutex");
            return Err("Failed to get lock on open_wallets mutex".into());
        }
        let request_url = format!(
            "{}/api/v1/blockcount/{}",
            CONFIG.lock().unwrap().as_ref().unwrap().node_address,
            wallet.wallet.public_key
        );
        let try_get_response = reqwest::blocking::get(&request_url);
        if let Ok(response) = try_get_response {
            let try_decode_json = response.json::<Blockcount>();
            if let Ok(response) = try_decode_json {
                let blockcount = response.blockcount;
                if blockcount == 0 {
                    info!("No existing blocks for chain, creating genesis blocks");
                    // Create genesis blocks, send to node
                    let mut genesis_block = get_genesis_block(&wallet.wallet.public_key);
                    if let Err(e) = genesis_block {
                        if e == GenesisBlockErrors::BlockNotFound {
                            info!(
                                "No genesis block found for chain: {}, generating",
                                wallet.wallet.address()
                            );
                            genesis_block = generate_genesis_block(
                                wallet.wallet.clone().public_key,
                                wallet.wallet.private_key.clone(),
                            );
                        } else {
                            error!(
                                "Database error occoured when trying to get genesisblock for chain: {}. (Fatal)",
                                wallet.wallet.address()
                            );
                            std::process::exit(1);
                        }
                    }
                    let genesis_block = genesis_block.unwrap();
                    let genesis_block_clone = genesis_block.clone();
                    // Now encode block as json and send to daemon
                    if let Ok(block_json) = serde_json::to_string(&genesis_block_clone) {
                        // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that

                        let mut rec_blk = genesis_block_clone
                            .form_receive_block(Some(
                                genesis_block_clone.header.chain_key.to_owned(),
                            ))
                            .unwrap();
                        rec_blk.header.height = 1;
                        rec_blk.header.prev_hash = genesis_block_clone.hash.clone();
                        rec_blk.signature = "".to_string();
                        rec_blk.hash();
                        if let Ok(rec_block_json) = serde_json::to_string(&rec_blk) {
                            info!(
                                "Sending genesis blocks to node, hashes=({}, {})",
                                genesis_block_clone.hash, rec_blk.hash
                            );
                            debug!("Genesis blocks encoded: {}, {}", block_json, rec_block_json);
                            let request_url = CONFIG
                                .lock()
                                .unwrap()
                                .as_ref()
                                .unwrap()
                                .node_address
                                .clone()
                                + "/api/v1/submit_block";
                            if let Ok(response) =
                                Client::new().post(request_url).json(&block_json).send()
                            {
                                if let Ok(response_string) = response.text() {
                                    if response_string.contains("error") {
                                        error!(
                                            "Failed to submit genesis send block, response={}",
                                            response_string
                                        );
                                        process::exit(1);
                                    } else {
                                        info!("Submitted genesis send block to node");
                                        debug!("Genesis send block response={}", response_string);
                                        let request_url = CONFIG
                                            .lock()
                                            .unwrap()
                                            .as_ref()
                                            .unwrap()
                                            .node_address
                                            .to_owned()
                                            + "/api/v1/submit_block";
                                        if let Ok(response) = Client::new()
                                            .post(request_url)
                                            .json(&rec_block_json)
                                            .send()
                                        {
                                            if let Ok(response_string) = response.text() {
                                                if response_string.contains("error") {
                                                    error!(
                                                            "Failed to submit genesis rec block, response={}",
                                                            response_string
                                                        );
                                                    process::exit(1);
                                                } else {
                                                    info!("Submitted genesis rec block to node");
                                                    debug!(
                                                        "Genesis rec block response={}",
                                                        response_string
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    info!("Found existing blocks for chain, skipping genesis block creation");
                }
                let request_url = format!(
                    "{}/api/v1/balances/{}",
                    CONFIG.lock().unwrap().as_ref().unwrap().node_address,
                    wallet.wallet.public_key
                );
                if let Ok(response_undec) = reqwest::blocking::get(&request_url) {
                    if let Ok(response) = response_undec.json::<Balances>() {
                        info!(
                            "Balance: {}, Locked: {}",
                            to_dec(response.balance),
                            to_dec(response.locked)
                        );
                        if let Ok(mut locked_ls) = OPEN_WALLETS.lock() {
                            let mut wallet_details = (*locked_ls)
                                .get(&raw_hash(&self.path))
                                .unwrap_or(&self)
                                .clone();
                            wallet_details.meta.balance = response.balance;
                            wallet_details.meta.locked = response.locked;
                            (*locked_ls).insert(self.path.clone(), wallet_details);
                            drop(locked_ls);
                        } else {
                            error!("Failed to lock OPENED_WALLETS mutex");
                            return Err("Failed to lock OPENED_WALLETS mutex".into());
                        }
                    } else {
                        error!("Failed to decode recieved 'balances' json");
                        return Err("Failed to decode recieved 'balances' json".into());
                    }
                } else {
                    error!("Failed to request {}", request_url);
                    return Err("Failed to request".into());
                }
                let request_url = format!(
                    "{}/api/v1/transactioncount/{}",
                    CONFIG.lock().unwrap().as_ref().unwrap().node_address,
                    wallet.wallet.public_key
                );
                if let Ok(response) = reqwest::blocking::get(&request_url) {
                    let json_res = response.json::<Transactioncount>();
                    if let Ok(transactioncount) = json_res {
                        if let Ok(mut locked_ls) = OPEN_WALLETS.lock() {
                            trace!("Got lock on OPEN_WALLETS");
                            let mut wallet_details = (*locked_ls)
                                .get(&raw_hash(&self.path))
                                .unwrap_or(&self)
                                .clone();
                            wallet_details.meta.account_nonce = transactioncount.transaction_count;

                            (*locked_ls).insert(self.path.clone(), wallet_details);
                            drop(locked_ls);
                        } else {
                            error!("Failed to lock OPENED_WALLETS mutex");
                            return Err("Failed to lock OPENED_WALLETS mutex".into());
                        }
                    } else {
                        error!(
                            "Failed to decode recieved 'transactioncount' json, error={}",
                            json_res.unwrap_err()
                        );
                        return Err("Failed to decode recieved 'transactioncount' json".into());
                    }
                }
            }
        }
        Ok(())
    }
    /// # Disk Flush
    /// Flush the wallet & metadata to disk
    pub fn disk_flush(&self, _create_if_missing: bool) -> Result<(), Box<dyn std::error::Error>> {
        let conf = avrio_config::config();
        let path = conf.db_path.clone() + &"/wallets/".to_owned() + &self.path;
        let mut padded = self.password.as_bytes().to_vec();
        while padded.len() != 32 && padded.len() < 33 {
            padded.push(b"n"[0]);
        }
        let padded_string = String::from_utf8(padded).unwrap();
        trace!("key: {}", padded_string);
        let key = GenericArray::clone_from_slice(padded_string.as_bytes());
        let aead = Aes256Gcm::new(&key);
        let mut padded = b"nonce".to_vec();
        while padded.len() != 12 {
            padded.push(b"n"[0]);
        }
        let padded_string = String::from_utf8(padded).unwrap();
        let nonce = GenericArray::from_slice(padded_string.as_bytes()); // 96-bits; unique per message
        trace!("nonce: {}", padded_string);
        let wallet_save = WalletSave {
            publickey: self.wallet.public_key.clone(),
            privatekey: self.wallet.private_key.clone(),
            metadata: self.meta.clone(),
        };

        let wallet_str = wallet_save.to_string();
        let ciphertext = hex::encode(
            aead.encrypt(nonce, wallet_str.as_bytes().as_ref())
                .expect("wallet private key encryption failure!"),
        );
        let _ = save_to_disk(path, ciphertext);
        Ok(())
    }
}

fn send_transaction(txn: Transaction, wall: Wallet) -> Result<String, Box<dyn std::error::Error>> {
    let request_url = format!(
        "{}/api/v1/blockcount/{}",
        CONFIG.lock().unwrap().as_ref().unwrap().node_address,
        wall.public_key.clone()
    );
    let response = reqwest::blocking::get(&request_url)?;

    let response_decoded = response.json::<Blockcount>()?;
    let height = response_decoded.blockcount;
    let request_url = format!(
        "{}/api/v1/hash_at_height/{}/{}",
        CONFIG.lock().unwrap().as_ref().unwrap().node_address,
        wall.public_key.clone(),
        height - 1
    );
    let response = reqwest::blocking::get(&request_url)?;
    let response_decoded = response.json::<HashAtHeight>()?;
    let prev_block_hash = response_decoded.hash;
    let mut blk = Block {
        header: Header {
            version_major: 0,
            version_breaking: 0,
            version_minor: 0,
            chain_key: wall.public_key.clone(),
            prev_hash: prev_block_hash,
            height,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64,
            network: config().network_id,
        },
        block_type: BlockType::Send,
        send_block: None,
        txns: vec![txn],
        hash: "".to_owned(),
        signature: "".to_owned(),
    };
    blk.hash();
    let _ = blk.sign(&wall.private_key);
    let block_json = serde_json::to_string(&blk)?;

    let request_url = CONFIG
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .node_address
        .to_owned()
        + "/api/v1/submit_block";
    if let Ok(response) = Client::new().post(request_url).json(&block_json).send() {
        if let Ok(response_string) = response.text() {
            if response_string.contains("error") {
                error!("Failed to submit block, response={}", response_string);
            } else {
                debug!("Submit response={}", response_string);
            }
        }
    }

    info!("Sent block to node");

    Ok(blk.hash)
}

fn launch_api(api_config: ApiConfig) {
    if api_config.api_password.is_none() || api_config.api_password == Some(String::from("admin")) {
        warn!("You have not set a password for the api (or the password is set to default), this means anyone who had access to the port can controll your wallet-service");
        warn!("If the wallet-service is exposed to the internet (eg port {} is port forwareded) exit immidiatley and set this value in wa.conf", api_config.bind_port);
    }
    info!(
        "Launching api on {}:{}",
        api_config.bind_address, api_config.bind_port
    );
    {
        *CONFIG.lock().unwrap() = Some(api_config.clone());
    }
    let config = rocket::Config::build(Environment::Staging)
        .log_level(LoggingLevel::Off) // disables logging
        .address(api_config.bind_address)
        .port(api_config.bind_port as u16)
        .finalize()
        .unwrap();

    rocket::custom(config)
        .mount("/json_rpc/", methods_v1::get_middleware())
        .launch();
}

fn get_args() -> ArgMatches<'static> {
    App::new("Avrio Wallet")
        .version("Testnet alpha v0.1.0")
        .about("This is the offical CLI wallet for the avrio network.")
        .author("Leo Cornelius")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config-file")
                .value_name("FILE")
                .help(
                    "(DOESNT WORK YET!!) Sets a custom config file, if not set will use node.conf",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("loglev")
                .long("log-level")
                .short("v")
                .takes_value(true)
                .help("Sets the level of verbosity: 0: Error, 1: Warn, 2: Info, 3: debug"),
        )
        .arg(
            Arg::with_name("apiaddr")
                .long("api-addr")
                .short("a")
                .takes_value(true)
                .help("Sets the api server addr (INCLUDES PORT)"),
        )
        .arg(
            Arg::with_name("rpcaddr")
                .long("rpc-addr")
                .short("r")
                .takes_value(true)
                .help("Sets the rpc server addr (INCLUDES PORT)"),
        )
        .get_matches()
}

fn main() {
    let args = get_args();
    setup_logging(args.value_of("loglev").unwrap_or("2").parse().unwrap_or(2))
        .expect("FATAL: Failed to setup logging");
    // Load the global config from disk
    info!("Avrio wallet service version 1.0.0");
    avrio_database::init_db(config().db_path + "/wallet").unwrap();


    let api_config_string = load_from_disk(String::from("wa.conf"), true).unwrap();
    let mut api_config = ApiConfig::new();
    let api_config_res = api_config.from_str(&api_config_string);
    if let Err(e) = api_config_res {
        error!(
            "Api config corruted or missing (decoding error={}), recreating",
            e
        );
        api_config = ApiConfig::new();
        save_to_disk(String::from("wa.conf"), api_config.to_string().unwrap()).unwrap();
    } else {
        info!("Loaded config");
    }
    let api_conf_clone = api_config.clone();
    let api_thread = std::thread::spawn(move || {
        launch_api(api_conf_clone);
    });
    // Launch the wallet update service
    let refresher_thread = std::thread::spawn(move || {
        info!("Starting wallet update service");
        loop {
            let mut wallets_clone: HashMap<String, OpenedWallet> = HashMap::new();
            match OPEN_WALLETS.lock() {
                Ok(mut wallets) => {
                    trace!("Got lock on OPEN_WALLETS mutex");
                    for wallet in wallets.values_mut() {
                        wallets_clone.insert(wallet.path.clone(), wallet.clone());
                    }
                }
                Err(e) => {
                    error!("Failed to lock wallet list: {}", e);
                }
            }
            for wallet in wallets_clone.values_mut() {
                debug!("Refreshing {}", wallet.wallet.address());
                let _ = wallet.refresh();
                let _ = wallet.disk_flush(true);
            }
            std::thread::sleep(Duration::from_secs(api_config.refresh_interval));
        }
    });
    refresher_thread.join().unwrap();
    api_thread.join().unwrap();
}
