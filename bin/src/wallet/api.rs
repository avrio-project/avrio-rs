/*
    Copyright The Avrio Core Developers 2020

    api/src/v1.rs

    This file handles the JSON API of the headless wallet.
*/
use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use avrio_config::config;
use avrio_core::block::{get_block, get_block_from_raw, save_block, Block, BlockType, Header};
use avrio_core::{
    account::{get_account, to_atomic},
    transaction::Transaction,
};
use avrio_database::{get_data, save_data};
use log::*;
use rocket::config::{Config, Environment, LoggingLevel};
use rocket::{routes, Route};
use std::io::prelude::*;
extern crate avrio_p2p;
use avrio_crypto::Wallet;
use lazy_static::*;
use rand::Rng;
use reqwest::Client;
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
    let mut rng = rand::thread_rng();
    let token: String = rng
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .collect();
    token
}

async fn form_receive_block(blk: &Block, for_chain: &String) -> Result<Block, Box<dyn Error>> {
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
        let response = reqwest::get(&request_url).await?;

        let response_decoded = response.json::<Blockcount>().await?;
        let height = response_decoded.blockcount;
        let request_url = format!(
            "http://127.0.0.1:8000/api/v1/hash_at_height/{}/{}",
            for_chain.clone(),
            height - 1
        );
        let response = reqwest::get(&request_url).await?;
        let response_decoded = response.json::<HashAtHeight>().await?;
        blk_clone.header.chain_key = chain_key_value;
        blk_clone.header.height = height; // we DONT need to add 1 to the blockcount as it is the COUNT of blocks on a chain which starts on 1, and block height starts from 0, this means there is already a +1 delta between the two
        blk_clone.send_block = Some(blk.hash.to_owned());
        blk_clone.header.prev_hash = response_decoded.hash;
        blk_clone.hash();
        blk_clone.signature = "".to_string();
        return Ok(blk_clone);
    }
}

async fn send_transaction(txn: Transaction, wall: Wallet) -> Result<(), Box<dyn Error>> {
    let request_url = format!(
        "http://127.0.0.1:8000/api/v1/blockcount/{}",
        wall.public_key.clone()
    );
    let response = reqwest::get(&request_url).await?;

    let response_decoded = response.json::<Blockcount>().await?;
    let height = response_decoded.blockcount;
    let request_url = format!(
        "http://127.0.0.1:8000/api/v1/hash_at_height/{}/{}",
        wall.public_key.clone(),
        height - 1
    );
    let response = reqwest::get(&request_url).await?;
    let response_decoded = response.json::<HashAtHeight>().await?;
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
            let try_rec_block = form_receive_block(&blk, &txn.receive_key.to_owned()).await;
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
            if let Ok(response) = Client::new()
                .post(request_url)
                .json(&block_json)
                .send()
                .await
            {
                if let Ok(response_string) = response.text().await {
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
    if key == "1234567890" {
        // TODO: use value passed as cmd line option
        // generate a token and add to list of valid tokens
        match AUTH_TOKENS.lock() {
            Ok(mut auth_tokens) => {
                let token = generate_token();
                auth_tokens.push(token.clone());
                return ("{ \"success\": true, \"token\": ".to_owned() + &token + "}").to_string();
            }
            Err(e) => {
                error!("Failed to lock auth tokens, error={}", e);
                return not_supported();
            }
        }
    } else {
        return ("{ \"success\": false, ".to_owned() + "\"error\": \"Invalid key\"}").to_string();
    }
}

#[get("/openwallet/<walletname>/<password>")]
pub fn open_wallet(walletname: String, password: String) -> String {
    // check if a wallet is open
    match WALLET_DETAILS.lock() {
        Ok(mut wallet_details) => {
            if wallet_details.len() == 0 {
                // wallet is not open, open one
                // TODO: use unique nonce
                // can we just hash the public key with some local data on the computer (maybe mac address)? Or is that insufficent (TODO: find out)
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
                let ciphertext = hex::decode(get_data(
                    "wallets/".to_owned() + &walletname,
                    &"privkey".to_owned(),
                ))
                .expect("failed to parse hex");
                let privkey = String::from_utf8(
                    aead.decrypt(nonce, ciphertext.as_ref())
                        .expect("decryption failure!"),
                )
                .expect("failed to parse utf8 (i1)");
                let wall = Wallet::from_private_key(privkey);
                *wallet_details = vec![wall.public_key, privkey.clone()];
                return ("{ \"success\": true, \"wallet\": ".to_owned() + &walletname + "}")
                    .to_string();
            } else {
                return ("{ \"success\": false, \"error\": \"Wallet already open\"}").to_string();
            }
        }
        Err(e) => {
            error!("Failed to lock wallet details, error={}", e);
            return not_supported();
        }
    }
}

fn save_wallet(
    keypair: &[String],
    password: String,
    name: String,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut conf = config();
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
    let publickey_en = hex::encode(
        aead.encrypt(nonce, keypair[0].as_bytes().as_ref())
            .expect("wallet public key encryption failure!"),
    );
    let privatekey_en = hex::encode(
        aead.encrypt(nonce, keypair[1].as_bytes().as_ref())
            .expect("wallet private key encryption failure!"),
    );
    let _ = save_data(&publickey_en, &path, "pubkey".to_owned());
    let _ = save_data(&privatekey_en, &path, "privkey".to_owned());
    info!("Saved wallet to {}", path);
    conf.chain_key = keypair[0].clone();
    conf.create()?;
    Ok(())
}

#[get("/createwallet/<walletname>/<password>/<privatekey>/<authkey>")]
pub fn create_wallet(
    walletname: String,
    password: String,
    privatekey: String,
    authkey: String,
) -> String {
    if avrio_database::get_data(
        "wallets/".to_owned() + &walletname,
        "pubkey",
    ) != "-1"
    {
        error!("Wallet with name={} already exists", walletname);
        return "{\"success\": false, \"error\": \"wallet with name already exists\" }".into();
    } else {
        info!("Creating wallet with name: {}", walletname);
        let wallet = avrio_crypto::Wallet::from_private_key(privatekey);
        match save_wallet(
            &[wallet.private_key.clone(), wallet.private_key.clone()],
            password,
            walletname,
        ) {
            Err(e) => {
                error!("Failed to save imported wallet: gave error={}", e);
                return "{\"success\": false, \"error\": \"Failed to save wallet\" }".into();
            }
            Ok(_) => match WALLET_DETAILS.lock() {
                Ok(mut lock) => {
                    *lock = vec![wallet.public_key.clone(), wallet.private_key.clone()];
                    return "{\"success\": true, \"publickey\": \"".to_owned()
                        + &wallet.public_key
                        + "\" }";
                }
                Err(e) => {
                    error!("Failed to gain lock on WALLET_DETAILS mutex, error={}", e);
                    return "{\"success\": false, \"error\": \"Failed to gain lock on WALLET_DETAILS mutex\" }".into();
                }
            },
        }
    }
}

#[get("/balance/<chain>")]
pub fn get_balance_v1(chain: String) -> String {
    if let Ok(acc) = get_account(&chain) {
        let balance: u64 = acc.balance;
        let locked: u64 = acc.locked;

        "{ \"success\": true, ".to_owned()
            + "\"chainkey\": \""
            + &chain
            + "\", "
            + "\"balance\": "
            + &balance.to_string()
            + ", "
            + "\"locked\": "
            + &locked.to_string()
            + " }"
    } else {
        "{ \"success\": false, ".to_owned()
            + "\"chainkey\": "
            + &chain
            + ", "
            + "\"balance\": "
            + &0.to_string()
            + ", "
            + "\"locked\": "
            + &0.to_string()
            + " }"
    }
}

#[post(
    "/submit_transaction",
    format = "application/json",
    data = "<transaction_data>"
)]
pub async fn submit_block_v1(transaction_data: rocket::Data) -> String {
    let mut bytes_stream = transaction_data.open();
    let mut holder_vec: Vec<u8> = vec![];
    loop {
        let mut buffer = [0u8; 512];
        let try_read_from_stream = bytes_stream.read(&mut buffer);
        if let Ok(size) = try_read_from_stream {
            trace!("Read {} bytes into buffer", size);
            if size == 0 {
                break;
            } else {
                holder_vec.append(&mut buffer.to_vec());
            }
        } else {
            debug!(
                "Failed to read into buf, error={}",
                try_read_from_stream.unwrap_err()
            );
            return format!(" {{ \"error\" : \" failed to read from datastream \" }}");
        }
    }
    let try_utf8_to_json = String::from_utf8(holder_vec);
    if let Ok(txn_pretrim) = try_utf8_to_json {
        if txn_pretrim != "" {
            let mut txn = txn_pretrim[1..].replace("\\", "").to_string(); // this very verbose bit of code removes everything outside the { } and removes the \
            loop {
                if &txn[txn.len() - 1..] != "}" {
                    txn = txn[0..txn.len() - 1].to_string();
                } else {
                    break;
                }
            }
            trace!("txn submited by API json={}", txn);
            let try_string_to_txn = serde_json::from_str::<TxnDetails>(&txn);
            if let Ok(txn_details) = try_string_to_txn {
                // TODO check we have loaded wallet with public key/sender key sender, create txn, block etc, submit to node

                match WALLET_DETAILS.lock() {
                    Ok(lock) => {
                        if lock[0] == txn_details.sender {
                            let mut txn = Transaction {
                                hash: String::from(""),
                                amount: txn_details.amount,
                                extra: String::from(""),
                                flag: 'c',
                                sender_key: lock[0].clone(),
                                receive_key: txn_details.reciever.clone(),
                                access_key: String::from(""),
                                unlock_time: 0,
                                gas_price: 10, // 0.001 AIO
                                max_gas: u64::max_value(),
                                nonce: 0,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .expect("Time went backwards")
                                    .as_millis() as u64,
                            };
                            let request_url = format!(
                                "http://127.0.0.1:8000/api/v1/transactioncount/{}",
                                lock[0]
                            );
                            if let Ok(response) = reqwest::get(&request_url).await {
                                if let Ok(transactioncount) =
                                    response.json::<Transactioncount>().await
                                {
                                    txn.nonce = transactioncount.transaction_count;
                                    txn.hash();
                                    let wall: Wallet = Wallet::from_private_key(lock[1].clone());
                                    if let Err(e) = send_transaction(txn, wall.clone()).await {
                                        error!("Failed to send txn, got error={}", e);
                                    }
                                } else {
                                    error!("Failed to decode recieved response into transactioncount struct");
                                }
                            } else {
                                error!("Failed to send request={}", request_url);
                            }
                            return "{\"success\": true, \"hash\": \"".to_owned()
                                + &lock[0]
                                + "\" }";
                        } else {
                            return "{\"success\": false, \"error\": \"Wallet not loaded\" }"
                                .into();
                        }
                    }
                    Err(e) => {
                        error!("Failed to gain lock on WALLET_DETAILS mutex, error={}", e);
                        return "{\"success\": false, \"error\": \"Failed to gain lock on WALLET_DETAILS mutex\" }".into();
                    }
                }
                //return format!(" {{ \"error\" : \" unimplemented \" }}");
            } else {
                debug!(
                    "Failed to decode json into TxnDetails struct, gave error: {}",
                    try_string_to_txn.unwrap_err()
                );
                return format!(" {{ \"error\" : \" json to struct failed \" }}");
            }
        } else {
            debug!("JSON string blank",);
            return format!(" {{ \"error\" : \" JSON string blank \" }}",);
        }
    } else {
        debug!(
            "Failed to turn utf8 bytes to txn_detail (submit txn_detail api, error={})",
            try_utf8_to_json.unwrap_err(),
        );
        return format!(" {{ \"error\" : \" utf8 to json failed \" }}");
    }
}

pub fn get_middleware() -> Vec<Route> {
    routes![
        must_provide_method,
        submit_block_v1,
        get_balance_v1,
        open_wallet,
        auth,
        create_wallet
    ]
}

pub fn start_server() {
    let config = rocket::Config::build(Environment::Staging)
        .log_level(LoggingLevel::Off) // disables logging
        .finalize()
        .unwrap();

    rocket::custom(config)
        .mount("/json_rpc/", get_middleware())
        .launch();
}
