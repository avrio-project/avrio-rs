/*
    Copyright The Avrio Core Developers 2020

    api/src/v1.rs

    This file handles the JSON API of the headless wallet.
*/
use aead::{NewAead};
 // Or `Aes128Gcm`

use avrio_core::block::{Block, BlockType, Header};
use avrio_core::{
    transaction::Transaction,
};

use log::*;

use rocket::{routes, Route};
use std::io::prelude::*;
extern crate avrio_p2p;
use crate::{user_auth_level, OpenedWallet, CONFIG, OPEN_WALLETS, USERS};
use avrio_crypto::Wallet;
use lazy_static::*;
use rand::Rng;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::error::Error;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
lazy_static! {
    static ref WALLET_DETAILS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static ref AUTH_TOKENS: Mutex<Vec<String>> = Mutex::new(Vec::new());
}
#[derive(Default, Clone, Deserialize, Debug)]
struct TxnDetails {
    pub amount: u64,
    pub reciever: String,
    pub sender: String,
    pub txn_type: String,
    pub extra: String,
}

#[derive(Clone, Deserialize, Debug)]
struct Blockcount {
    success: bool,
    blockcount: u64,
}

#[derive(Clone, Deserialize, Debug)]
struct HashAtHeight {
    success: bool,
    hash: String,
}

#[derive(Clone, Deserialize, Debug)]
struct Transactioncount {
    success: bool,
    transaction_count: u64,
}

fn generate_token() -> String {
    let rng = rand::thread_rng();
    let token: String = rng
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .collect();
    token
}

fn form_receive_block(blk: &Block, for_chain: &String) -> Result<Block, Box<dyn Error>> {
    if blk.block_type == BlockType::Recieve {
        return Err("Block is recive block already".into());
    }
    // else we can get on with forming the rec block for this block
    let mut blk_clone = blk.clone();
    blk_clone.block_type = BlockType::Recieve;
    blk_clone.header.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;
    let chain_key_value: String = for_chain.to_owned();
    let mut txn_iter = 0;
    for txn in blk_clone.clone().txns {
        txn_iter += 1;
        if txn.receive_key != chain_key_value {
            blk_clone.txns.remove(txn_iter);
        }
    }
    if chain_key_value == blk.header.chain_key {
        blk_clone.header.height += 1;
        blk_clone.send_block = Some(blk.hash.to_owned());
        blk_clone.header.prev_hash = blk.hash.clone();
        blk_clone.hash();
        blk_clone.signature = "".to_string();
        return Ok(blk_clone);
    } else {
        let request_url = format!(
            "http://127.0.0.1:8000/api/v1/blockcount/{}",
            for_chain.clone()
        );
        let response = reqwest::blocking::get(&request_url)?;

        let response_decoded = response.json::<Blockcount>()?;
        let height = response_decoded.blockcount;
        let request_url = format!(
            "http://127.0.0.1:8000/api/v1/hash_at_height/{}/{}",
            for_chain.clone(),
            height - 1
        );
        let response = reqwest::blocking::get(&request_url)?;
        let response_decoded = response.json::<HashAtHeight>()?;
        blk_clone.header.chain_key = chain_key_value;
        blk_clone.header.height = height; // we DONT need to add 1 to the blockcount as it is the COUNT of blocks on a chain which starts on 1, and block height starts from 0, this means there is already a +1 delta between the two
        blk_clone.send_block = Some(blk.hash.to_owned());
        blk_clone.header.prev_hash = response_decoded.hash;
        blk_clone.hash();
        blk_clone.signature = "".to_string();
        return Ok(blk_clone);
    }
}

fn send_transaction(txn: Transaction, wall: Wallet) -> Result<(), Box<dyn Error>> {
    let request_url = format!(
        "http://127.0.0.1:8000/api/v1/blockcount/{}",
        wall.public_key.clone()
    );
    let response = reqwest::blocking::get(&request_url)?;

    let response_decoded = response.json::<Blockcount>()?;
    let height = response_decoded.blockcount;
    let request_url = format!(
        "http://127.0.0.1:8000/api/v1/hash_at_height/{}/{}",
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
            network: vec![97, 118, 114, 105, 111, 32, 110, 111, 111, 100, 108, 101],
        },
        block_type: BlockType::Send,
        send_block: None,
        txns: vec![txn],
        hash: "".to_owned(),
        signature: "".to_owned(),
    };
    blk.hash();
    let _ = blk.sign(&wall.private_key);
    let mut blocks: Vec<String> = vec![];
    let block_json = serde_json::to_string(&blk)?;
    blocks.push(block_json);
    // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that
    let mut proccessed_accs: Vec<String> = vec![];

    let mut failed = false;
    for txn in &blk.txns {
        if !proccessed_accs.contains(&txn.receive_key) {
            let try_rec_block = form_receive_block(&blk, &txn.receive_key.to_owned());
            if let Ok(rec_blk) = try_rec_block {
                trace!("Created rec block={:#?}", rec_blk);

                proccessed_accs.push(txn.receive_key.clone());
                if let Ok(rec_blk_json) = serde_json::to_string(&rec_blk) {
                    blocks.push(rec_blk_json);
                } else {
                    error!("Failed to encode rec block as json");
                    failed = true;
                    break;
                }
            } else {
                failed = true;
                error!(
                    "Failed to form rec block, gave error={}",
                    try_rec_block.unwrap_err()
                );
                break;
            }
        }
    }
    if !failed {
        // now transmit all blocks to node
        for block_json in blocks {
            let request_url = "http://127.0.0.1:8000/api/v1/submit_block";
            if let Ok(response) = Client::new().post(request_url).json(&block_json).send() {
                if let Ok(response_string) = response.text() {
                    if response_string.contains("error") {
                        error!("Failed to submit block, response={}", response_string);
                    } else {
                        debug!("Submit response={}", response_string);
                    }
                }
            }
        }
        info!("Sent all blocks to node");
    }

    Ok(())
}

fn not_supported() -> String {
    "{ \"error\": \"NOT_SUPPORTED\"}".to_owned()
}

#[get("/")]
fn must_provide_method() -> &'static str {
    "{ \"success\": false, \"error\": \"METHOD_MISSING\" }"
}
#[get("/auth/<key>")]
pub fn auth(key: String) -> String {
    let mut valid = false;
    match CONFIG.lock().unwrap().clone().unwrap().api_password {
        Some(api_pass) => {
            valid = api_pass == key;
        }
        None => valid = true,
    }
    if valid {
        // generate a token and add to list of valid tokens
        match USERS.lock() {
            Ok(mut users) => {
                let token = generate_token();
                users.insert(token.clone(), vec![]);
                log::info!("New user authenticated, provided key: {}", token);
                return ("{ \"success\": true, \"token\": \"".to_owned() + &token + "\"}")
                    .to_string();
            }
            Err(e) => {
                error!("Failed to lock user hashmap, error={}", e);
                return not_supported();
            }
        }
    } else {
        return ("{ \"success\": false, ".to_owned() + "\"error\": \"Invalid key\"}").to_string();
    }
}

#[get("/openwallet/<walletname>/<password>/<auth>")]
pub fn open_wallet(walletname: String, password: String, auth: String) -> String {
    // check if a wallet is open

    if let Ok(_) = user_auth_level(auth.clone()) {
        if let Ok(wall) = OpenedWallet::open(walletname.clone(), password) {
            debug!("Opened wallet {}", walletname);
            // add to the users auth lust + global wallet details
            if let Err(_e) = wall.add_to_locks(&auth) {
                return ("{ \"success\": false, \"error\": \"internal error: failed to add wallet to mutexes\" }").to_string();
            } else {
                return ("{ \"success\": true, \"wallet\": ".to_owned() + &walletname + &"}")
                    .to_string();
            }
        } else {
            return ("{ \"success\": false, \"error\": \"internal error: failed to open wallet\" }").to_string();
        }
    } else {
        return ("{ \"success\": false, \"error\": \"not authenticated\" }").to_string();
    }
}

#[get("/createwallet/<walletname>/<password>/<authkey>")]
pub fn create_wallet(walletname: String, password: String, authkey: String) -> String {
    // check if this user is authenticated
    if let Err(_e) = user_auth_level(authkey.clone()) {
        return ("{ \"success\": false, \"error\": \"not authenticated\" }").to_string();
    }
    // create a new wallet
    let keys = Wallet::gen();
    let wall = OpenedWallet::create_wallet(
        walletname.clone(),
        password.clone(),
        keys.private_key,
        authkey.clone(),
    );
    if let Err(_e) = wall {
        return ("{ \"success\": false, \"error\": \"internal error: failed to create wallet\" }")
            .to_string();
    } else {
        let wallet = wall.unwrap();
        return ("{ \"success\": true, \"public_key\": ".to_owned()
            + &wallet.wallet.public_key
            + &"}")
            .to_string();
    }
}

pub fn get_wallet_with_publickey(
    public_key: String,
) -> std::result::Result<OpenedWallet, Box<dyn std::error::Error>> {
    let mut wallets = OPEN_WALLETS.lock()?;
    for (_key, wallet) in wallets.iter_mut() {
        if wallet.wallet.public_key == public_key {
            return Ok(wallet.clone());
        }
    }
    Err("not found".into())
}

#[get("/wallet_details/<publickey>/<auth>")]
pub fn wallet_details(publickey: String, auth: String) -> String {
    // check if this user is authenticated
    match user_auth_level(auth.clone()) {
        Ok(wallets) => {
            // get the wallet details
            if let Ok(wallet) = get_wallet_with_publickey(publickey.clone()) {
                // check the user is allowed to access this wallet
                if !wallets.contains(&wallet.path) {
                    return ("{ \"success\": false, \"error\": \"not authenticated for this wallet\" }").to_string();
                }
                return ("{ \"success\": true, \"wallet\": ".to_owned()
                    + &wallet.wallet.public_key
                    + ", \"balance\": "
                    + &wallet.meta.balance.to_string()
                    + ", \"locked\": "
                    + &wallet.meta.locked.to_string()
                    + &"}")
                    .to_string();
            } else {
                return ("{ \"success\": false, \"error\": \"internal error: failed to get wallet\" }")
                    .to_string();
            }
        }
        Err(_) => return ("{ \"success\": false, \"error\": \"not authenticated\" }").to_string(),
    };
}

//#[get("/send/<publickey>/<recipitent>/<amount>/<auth>")]
pub fn send(publickey: String, recipitent: String, amount: u64, auth: String) -> String {
    // check if this user is authenticated
    if let Ok(wallets) = user_auth_level(auth.clone()) {
        // get the wallet details
        if let Ok(wallet) = get_wallet_with_publickey(publickey.clone()) {
            // check the user is allowed to access this wallet
            if !wallets.contains(&wallet.path) {
                return ("{ \"success\": false, \"error\": \"not authenticated for this wallet\" }").to_string();
            }
            if (wallet.meta.balance - amount) < 0 {
                return ("{ \"success\": false, \"error\": \"insufficient funds\" }").to_string();
            }
            // form a transaction
            let mut transaction = Transaction {
                hash: String::default(),
                amount,
                extra: String::default(),
                flag: 'n',
                sender_key: publickey.clone(),
                receive_key: recipitent.clone(),
                access_key: String::default(),
                unlock_time: 0,
                gas_price: 100,
                max_gas: u64::max_value(),
                nonce: wallet.meta.account_nonce,
                timestamp: chrono::Utc::now().timestamp() as u64,
            };
            transaction.hash();
            trace!(
                "Created transaction: {:?} for wallet: {} (requested by user: {})",
                transaction,
                publickey,
                auth
            );
            let txn_res = crate::send_transaction(transaction.clone(), wallet.wallet.clone());
            if let Err(e) = txn_res {
                error!("Failed to send transaction, error: {}", e);
                return format!("{{ \"success\": false, \"error\": \"internal error: failed to send transaction, error={}\" }}", e);
            } else {
                return ("{ \"success\": true, \"transaction_hash\": ".to_owned()
                    + &transaction.hash
                    + "\"block_hash\": "
                    + &txn_res.unwrap()
                    + "\"\" }")
                    .to_string();
            }
        } else {
            return ("{ \"success\": false, \"error\": \"internal error: failed to get wallet\" }")
                .to_string();
        }
    } else {
        return ("{ \"success\": false, \"error\": \"not authenticated\" }").to_string();
    };
}

pub fn get_middleware() -> Vec<Route> {
    routes![
        must_provide_method,
        wallet_details,
        open_wallet,
        auth,
        create_wallet
    ]
}
