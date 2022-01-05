#![feature(proc_macro_hygiene, decl_macro)]
/*
    Copyright 2020 the avrio core devs

    bin/test/one/src/wallet/main.rs

    This is the first attempt at a Avrio CLI wallet.
    It uses the JSON API v1 provided by the Avrio Daemon.
*/
extern crate rocket;

use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use avrio_config::config;
use avrio_core::block::{
    genesis::{generate_genesis_block, get_genesis_block, GenesisBlockErrors},
    Block, BlockType, Header,
};
use avrio_core::{account::*, transaction::Transaction};
use avrio_crypto::Wallet;
use avrio_database::*;
use avrio_rpc::{launch_client, Announcement, Caller};
use clap::{App, Arg};
use common::*;
use lazy_static::*;
use log::{debug, error, info, trace, warn};
use reqwest::Client;
use serde::Deserialize;
use serde_json;
use std::{default::Default, sync::Mutex};
use std::{
    error::Error,
    io,
    io::prelude::*,
    process,
    time::{SystemTime, UNIX_EPOCH},
};
use text_io::read;

#[derive(Default, Clone)]
struct WalletDetails {
    wallet: Option<Wallet>,
    balance: u64,
    locked: u64,
    top_block_hash: String,
    username: String,
    proccessed_anns: Vec<String>,
}

lazy_static! {
    static ref WALLET_DETAILS: Mutex<WalletDetails> = Mutex::new(WalletDetails::default());
    static ref SERVER_ADDR: Mutex<String> = Mutex::new(String::from("http://127.0.0.1:8000"));
}
fn trim_newline(s: &mut String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s.clone()
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
            "{}/api/v1/blockcount/{}",
            SERVER_ADDR.lock().unwrap().to_owned(),
            for_chain.clone()
        );
        let response = reqwest::get(&request_url).await?;

        let response_decoded = response.json::<Blockcount>().await?;
        let height = response_decoded.blockcount;
        let request_url = format!(
            "{}/api/v1/hash_at_height/{}/{}",
            SERVER_ADDR.lock().unwrap().to_owned(),
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

fn get_choice() -> u8 {
    info!("[1] Open an existing wallet");
    info!("[2] Create a wallet");
    info!("[3] Import private keys");
    let ans: u8 = trim_newline(&mut read!()).parse::<u8>().unwrap();
    return ans;
}
pub fn new_ann(ann: Announcement) {
    if let Ok(mut locked) = WALLET_DETAILS.lock() {
        debug!("Gained lock on WALLET_DETAILS");
        if ann.m_type == "block".to_string() {
            // ann.msg contains a block in json format
            if let Ok(blk) = serde_json::from_str::<Block>(&ann.content) {
                if locked.proccessed_anns.contains(&blk.hash) {
                    return;
                }
                locked.proccessed_anns.push(blk.hash.clone());
                if blk.block_type == BlockType::Recieve {
                    let balance_before = locked.balance;
                    let locked_balance_before = locked.locked;
                    for txn in blk.txns {
                        trace!("Txn: {:#?}", txn);
                        if txn.sender_key == locked.wallet.as_ref().unwrap().public_key {
                            match txn.flag {
                                'n' => {
                                    locked.balance -= txn.amount;
                                    locked.balance -= txn.gas() * txn.gas_price;
                                }
                                'c' => {
                                    locked.balance += txn.amount;
                                }
                                'u' => {
                                    locked.username = txn.extra.clone();
                                    locked.balance -= txn.amount;
                                    locked.balance -= txn.gas() * txn.gas_price;
                                    info!("Registered new username: {}", locked.username);
                                }
                                'l' => {
                                    locked.balance -= txn.amount;
                                    locked.locked += txn.amount;
                                    locked.balance -= txn.gas() * txn.gas_price;
                                    info!("Locked funds, commitment: {}", txn.hash);
                                }
                                'b' => {
                                    locked.balance -= txn.amount;
                                    locked.balance -= txn.gas() * txn.gas_price;
                                }
                                _ => {
                                    error!(
                                        "Involved in unsupported transaction type, flag={}",
                                        txn.flag
                                    );
                                    debug!("Txn dump: {:#?}", txn);
                                }
                            }
                        }
                    }
                    if balance_before != locked.balance {
                        locked.top_block_hash = blk.hash.clone();
                        info!(
                            "New block {}, old balance: {}, new balance: {}",
                            blk.hash,
                            to_dec(balance_before),
                            to_dec(locked.balance)
                        );
                        if locked_balance_before != locked.locked {
                            info!(
                                "Locked funds changed: old={} AIO, new={} AIO",
                                locked_balance_before, locked.locked
                            );
                        }
                    } else {
                        debug!("Block contained no transactions affecting us");
                    }
                } else {
                    debug!("Block was a send block");
                }
            }
        }
    }
}

async fn send_transaction(txn: Transaction, wall: Wallet) -> Result<(), Box<dyn Error>> {
    let request_url = format!(
        "{}/api/v1/blockcount/{}",
        SERVER_ADDR.lock().unwrap().to_owned(),
        wall.public_key.clone()
    );
    let response = reqwest::get(&request_url).await?;

    let response_decoded = response.json::<Blockcount>().await?;
    let height = response_decoded.blockcount;
    let request_url = format!(
        "{}/api/v1/hash_at_height/{}/{}",
        SERVER_ADDR.lock().unwrap().to_owned(),
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
    let mut blocks: Vec<String> = vec![];
    let block_json = serde_json::to_string(&blk)?;
    blocks.push(block_json);
    // now for each txn to a unique reciver form the rec block of the block we just formed and prop + enact that
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
            let request_url = SERVER_ADDR.lock().unwrap().to_owned() + "/api/v1/submit_block";
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
#[tokio::main]
async fn main() {
    let matches = App::new("Avrio Wallet")
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
        .get_matches();
    //println!("{}", matches.occurrences_of("loglev"));
    let art = "
   #    #     # ######  ### #######
  # #   #     # #     #  #  #     #
 #   #  #     # #     #  #  #     #
#     # #     # ######   #  #     #
#######  #   #  #   #    #  #     #
#     #   # #   #    #   #  #     #
#     #    #    #     # ### ####### ";
    println!("{}", art);
    setup_logging(
        matches
            .value_of("loglev")
            .unwrap_or("2")
            .parse::<u64>()
            .unwrap_or(2),
    )
    .expect("Failed to setup logging");
    info!("Avrio Wallet Testnet v0.1.0 (alpha)");
    let config_ = config();
    let _ = config_.save();
    if let Some(addr) = matches.value_of("apiaddr") {
        *(SERVER_ADDR.lock().unwrap()) = format!("http://{}", addr);
    }

    info!("Welcome to the avrio wallet, please choose an option");
    let wallet = match get_choice() {
        1 => open_wallet_gather(),
        2 => create_wallet(),
        3 => import_wallet(),
        _ => {
            error!("Please choose a number beetween 1 and 3!");
            Err("invalid number".into())
        }
    };
    if let Ok(wall) = wallet {
        info!("Using wallet with publickey={}", wall.public_key);
        debug!("Creating caller struct");
        let caller = Caller {
            callback: Box::new(new_ann),
        };
        if let Ok(mut locked_ls) = WALLET_DETAILS.lock() {
            *locked_ls = WalletDetails {
                wallet: Some(wall.clone()),
                balance: 0,
                locked: 0,
                top_block_hash: "".to_string(),
                username: "".to_string(),
                proccessed_anns: vec![],
            };
            drop(locked_ls);
            let request_url = format!(
                "{}/api/v1/blockcount/{}",
                SERVER_ADDR.lock().unwrap().to_string(),
                wall.public_key
            );
            let try_get_response = reqwest::get(&request_url).await;
            if let Ok(response) = try_get_response {
                let try_decode_json = response.json::<Blockcount>().await;
                if let Ok(response) = try_decode_json {
                    let blockcount = response.blockcount;
                    if blockcount == 0 {
                        info!("No existing blocks for chain, creating genesis blocks");
                        // Create genesis blocks, send to node
                        let mut genesis_block = get_genesis_block(&wall.public_key);
                        if let Err(e) = genesis_block {
                            if e == GenesisBlockErrors::BlockNotFound {
                                info!(
                                    "No genesis block found for chain: {}, generating",
                                    wall.address()
                                );
                                genesis_block = generate_genesis_block(
                                    wall.clone().public_key,
                                    wall.private_key.clone(),
                                );
                            } else {
                                error!(
                                "Database error occoured when trying to get genesisblock for chain: {}. (Fatal)",
                                wall.address()
                            );
                                process::exit(1);
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
                                debug!(
                                    "Genesis blocks encoded: {}, {}",
                                    block_json, rec_block_json
                                );
                                let request_url =
                                    SERVER_ADDR.lock().unwrap().to_owned() + "/api/v1/submit_block";
                                if let Ok(response) = Client::new()
                                    .post(request_url)
                                    .json(&block_json)
                                    .send()
                                    .await
                                {
                                    if let Ok(response_string) = response.text().await {
                                        if response_string.contains("error") {
                                            error!(
                                                "Failed to submit genesis send block, response={}",
                                                response_string
                                            );
                                            process::exit(1);
                                        } else {
                                            info!("Submitted genesis send block to node");
                                            debug!(
                                                "Genesis send block response={}",
                                                response_string
                                            );
                                            let request_url =
                                                SERVER_ADDR.lock().unwrap().to_string()
                                                    + "/api/v1/submit_block";
                                            if let Ok(response) = Client::new()
                                                .post(request_url)
                                                .json(&rec_block_json)
                                                .send()
                                                .await
                                            {
                                                if let Ok(response_string) = response.text().await {
                                                    if response_string.contains("error") {
                                                        error!(
                                                            "Failed to submit genesis rec block, response={}",
                                                            response_string
                                                        );
                                                        process::exit(1);
                                                    } else {
                                                        info!(
                                                            "Submitted genesis rec block to node"
                                                        );
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
                        info!(
                            "Node has {} blocks for our chain, getting details",
                            blockcount
                        );
                    }
                    let request_url = format!(
                        "{}/api/v1/balances/{}",
                        SERVER_ADDR.lock().unwrap().to_string(),
                        wall.public_key
                    );
                    if let Ok(response_undec) = reqwest::get(&request_url).await {
                        if let Ok(response) = response_undec.json::<Balances>().await {
                            info!(
                                "Balance: {}, Locked: {}",
                                to_dec(response.balance),
                                to_dec(response.locked)
                            );
                            if let Ok(mut locked_ls) = WALLET_DETAILS.lock() {
                                let mut wallet_details = (*locked_ls).clone();
                                wallet_details.balance = response.balance;
                                wallet_details.locked = response.locked;
                                *locked_ls = wallet_details;
                                drop(locked_ls);
                            } else {
                                error!("Failed to lock WALLET_DETAILS mutex");
                            }
                        } else {
                            error!("Failed to decode recieved 'balances' json");
                        }
                    } else {
                        error!("Failed to request {}", request_url);
                    }
                    let request_url = format!(
                        "{}/api/v1/transactioncount/{}",
                        SERVER_ADDR.lock().unwrap().to_string(),
                        wall.public_key
                    );
                    if let Ok(response) = reqwest::get(&request_url).await {
                        if let Ok(transactioncount) = response.json::<Transactioncount>().await {
                            info!(
                                "Transaction count for our chain: {}",
                                transactioncount.transaction_count,
                            );
                        }
                    }

                    if let Ok(walletdetails) = WALLET_DETAILS.lock() {
                        info!("Our balance: {}", to_dec(walletdetails.balance));
                    }
                    let mut rpcaddr = "127.0.0.1:17785";
                    if let Some(addr) = matches.value_of("rpcaddr") {
                        rpcaddr = addr;
                    }
                    let rpcaddr_split: Vec<&str> = rpcaddr.split(':').collect();
                    if let Ok(_) = launch_client(
                        rpcaddr_split[0].to_string(),
                        rpcaddr_split[1].parse().unwrap_or(17785),
                        vec![],
                        caller,
                    ) {
                        debug!("Launched RPC listener");
                    } else {
                        error!("Failed to connect to RPC server, please check it is running on the specified (or default) port");
                        error!("Note: when using --rpcaddr make sure to use both the ip and port (eg --rpcaddr 127.0.0.1:1231) ");
                        process::exit(1);
                    }
                    loop {
                        // Now we loop until shutdown
                        let _ = io::stdout().flush();
                        let read: String = trim_newline(&mut read!("{}\n"));
                        trace!("{:?}", read);
                        let read_split: Vec<&str> = read.split(' ').collect();
                        if read_split[0] == "send" {
                            let mut amount: f64 = 0.0;
                            let mut extra_data: String = String::from("");
                            let mut addr: String = String::from("");
                            match read_split.len() {
                                3 => {
                                    if let Ok(amount_parsed) = read_split[1].parse::<f64>() {
                                        if let Ok(receiver_parsed) = read_split[2].parse::<String>()
                                        {
                                            amount = amount_parsed;
                                            addr = receiver_parsed;
                                        }
                                    }
                                }
                                4 => {
                                    if let Ok(amount_parsed) = read_split[2].parse::<f64>() {
                                        if let Ok(receiver_parsed) = read_split[1].parse::<String>()
                                        {
                                            if let Ok(extra_parsed) =
                                                read_split[3].parse::<String>()
                                            {
                                                amount = amount_parsed;
                                                addr = receiver_parsed;
                                                extra_data = extra_parsed;
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    info!("Please enter the amount");
                                    amount =
                                        trim_newline(&mut read!("{}\n")).parse::<f64>().unwrap();
                                    info!("Please enter the reciever address or username:");
                                    addr = trim_newline(&mut read!());
                                    info!("Enter extra data (must be at most 100 chars long");
                                    extra_data = trim_newline(&mut read!("{}\n"));
                                    if extra_data.len() > 100 {
                                        error!("Extra data must be under or equal to 100 bytes");
                                    }
                                }
                            }
                            if amount == 0.0 {
                            } else {
                                let mut txn = Transaction {
                                    hash: String::from(""),
                                    amount: to_atomic(amount),
                                    extra: extra_data.clone(),
                                    flag: 'n',
                                    sender_key: wall.public_key.clone(),
                                    receive_key: String::from(""),
                                    access_key: String::from(""),
                                    unlock_time: 0,
                                    gas_price: 10, // 0.001 AIO

                                    max_gas: u64::max_value(),
                                    nonce: 0,
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .expect("Time went backwards")
                                        .as_millis()
                                        as u64,
                                };
                                let request_url = format!(
                                    "{}/api/v1/balances/{}",
                                    SERVER_ADDR.lock().unwrap().to_string(),
                                    wall.public_key
                                );
                                if let Ok(response_undec) = reqwest::get(&request_url).await {
                                    if let Ok(response) = response_undec.json::<Balances>().await {
                                        if txn.amount + txn.fee() > response.balance {
                                            error!("Insufficent balance");
                                        } else {
                                            if avrio_crypto::valid_address(&addr) {
                                                let rec_wall = Wallet::from_address(addr);
                                                txn.receive_key = rec_wall.public_key;
                                            } else {
                                                debug!(
                                        "Could not find acc with addr={}, trying as username",
                                        addr
                                    );
                                                let request_url = format!(
                                                    "{}/api/v1/publickey_for_username/{}",
                                                    SERVER_ADDR.lock().unwrap().to_string(),
                                                    addr
                                                );
                                                if let Ok(response) =
                                                    reqwest::get(&request_url).await
                                                {
                                                    if let Ok(publickey_for_username) = response
                                                        .json::<PublickeyForUsername>()
                                                        .await
                                                    {
                                                        txn.receive_key =
                                                            publickey_for_username.publickey;
                                                    }
                                                }
                                            }
                                            let request_url = format!(
                                                "{}/api/v1/transactioncount/{}",
                                                SERVER_ADDR.lock().unwrap().to_string(),
                                                wall.public_key
                                            );
                                            if let Ok(response) = reqwest::get(&request_url).await {
                                                if let Ok(transactioncount) =
                                                    response.json::<Transactioncount>().await
                                                {
                                                    txn.nonce = transactioncount.transaction_count;
                                                    txn.hash();
                                                    if let Err(e) =
                                                        send_transaction(txn, wall.clone()).await
                                                    {
                                                        error!(
                                                            "Failed to send txn, got error={}",
                                                            e
                                                        );
                                                    }
                                                } else {
                                                    error!("Failed to decode recieved response into transactioncount struct");
                                                }
                                            } else {
                                                error!("Failed to send request={}", request_url);
                                            }
                                        }
                                    }
                                }
                            }
                        } else if read == *"address" {
                            info!("Our address: {}", wall.address());
                        } else if read_split[0] == "claim" {
                            let mut amount: f64 = 0.0;
                            match read_split.len() {
                                2 => {
                                    if let Ok(amount_parsed) = read_split[1].parse::<f64>() {
                                        amount = amount_parsed;
                                    } else {
                                        info!("Please enter the amount");
                                        amount = trim_newline(&mut read!("{}\n"))
                                            .parse::<f64>()
                                            .unwrap();
                                    }
                                }
                                _ => {
                                    info!("Please enter the amount");
                                    amount =
                                        trim_newline(&mut read!("{}\n")).parse::<f64>().unwrap();
                                }
                            }
                            let mut txn = Transaction {
                                hash: String::from(""),
                                amount: to_atomic(amount),
                                extra: String::from(""),
                                flag: 'c',
                                sender_key: wall.public_key.clone(),
                                receive_key: wall.public_key.clone(),
                                access_key: String::from(""),
                                unlock_time: 0,
                                gas_price: 10, // 0.001 AIO
                                max_gas: u64::max_value(),
                                nonce: 0,
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Time went backwards")
                                    .as_millis() as u64,
                            };
                            let request_url = format!(
                                "{}/api/v1/transactioncount/{}",
                                SERVER_ADDR.lock().unwrap().to_string(),
                                wall.public_key
                            );
                            if let Ok(response) = reqwest::get(&request_url).await {
                                if let Ok(transactioncount) =
                                    response.json::<Transactioncount>().await
                                {
                                    txn.nonce = transactioncount.transaction_count;
                                    txn.hash();
                                    if let Err(e) = send_transaction(txn, wall.clone()).await {
                                        error!("Failed to send txn, got error={}", e);
                                    }
                                } else {
                                    error!("Failed to decode recieved response into transactioncount struct");
                                }
                            } else {
                                error!("Failed to send request={}", request_url);
                            }
                        } else if read == *"address"
                            || read == *"get_address"
                            || read == *"get_addr"
                        {
                            info!("Our address: {}", wall.address());
                        } else if read == *"balance" || read == *"get_balance" || read == *"bal" {
                            if let Ok(lock) = WALLET_DETAILS.lock() {
                                info!("Our balance: {}", to_dec(lock.balance));
                            } else {
                                error!("Failed to get lock on WALLET_DETAILS muxtex (try again)");
                            }
                        } else if read == *"register_username" {
                            if let Ok(lock) = WALLET_DETAILS.lock() {
                                if lock.username == "" {
                                    info!("Enter desired_username:");
                                    let desired_username: String = trim_newline(&mut read!());
                                    if !desired_username.chars().all(char::is_alphanumeric) {
                                        error!("Username may only contain alphanumeric charactors");
                                    } else {
                                        let request_url = format!(
                                            "{}/api/v1/publickey_for_username/{}",
                                            SERVER_ADDR.lock().unwrap().to_string(),
                                            desired_username
                                        );
                                        if let Ok(response) = reqwest::get(&request_url).await {
                                            if let Ok(publickey_for_username) =
                                                response.json::<PublickeyForUsername>().await
                                            {
                                                if publickey_for_username.publickey != "" {
                                                    error!("Username {} is taken, try another (rerun register_username)", desired_username);
                                                } else {
                                                    let mut txn = Transaction {
                                                        hash: String::from(""),
                                                        amount: to_atomic(0.50),
                                                        extra: desired_username.clone(),
                                                        flag: 'u',
                                                        sender_key: wall.public_key.clone(),
                                                        receive_key: wall.public_key.clone(),
                                                        access_key: String::from(""),
                                                        unlock_time: 0,
                                                        gas_price: 10, // 0.001 AIO
                                                        max_gas: u64::max_value(),
                                                        nonce: 0,
                                                        timestamp: SystemTime::now()
                                                            .duration_since(UNIX_EPOCH)
                                                            .expect("Time went backwards")
                                                            .as_millis()
                                                            as u64,
                                                    };
                                                    let request_url = format!(
                                                        "{}/api/v1/balances/{}",
                                                        SERVER_ADDR.lock().unwrap().to_string(),
                                                        wall.public_key
                                                    );
                                                    if let Ok(response_undec) =
                                                        reqwest::get(&request_url).await
                                                    {
                                                        if let Ok(response) =
                                                            response_undec.json::<Balances>().await
                                                        {
                                                            if txn.amount + txn.fee()
                                                                > response.balance
                                                            {
                                                                error!("Insufficent balance");
                                                            } else {
                                                                let request_url = format!(
                                                                    "{}/api/v1/transactioncount/{}",
                                                                    SERVER_ADDR
                                                                        .lock()
                                                                        .unwrap()
                                                                        .to_string(),
                                                                    wall.public_key
                                                                );
                                                                if let Ok(response) =
                                                                    reqwest::get(&request_url).await
                                                                {
                                                                    if let Ok(transactioncount) =
                                                                    response
                                                                        .json::<Transactioncount>()
                                                                        .await
                                                                {
                                                                    txn.nonce = transactioncount
                                                                        .transaction_count;
                                                                    txn.hash();
                                                                    if let Err(e) =
                                                                        send_transaction(
                                                                            txn,
                                                                            wall.clone(),
                                                                        )
                                                                        .await
                                                                    {
                                                                        error!(
                                                                "Failed to send txn, got error={}",
                                                                e
                                                            );
                                                                    }
                                                                } else {
                                                                    error!("Failed to decode recieved response into transactioncount struct");
                                                                }
                                                                } else {
                                                                    error!(
                                                                        "Failed to send request={}",
                                                                        request_url
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
                                    error!(
                                        "You already have a username, username={}",
                                        lock.username
                                    );
                                    error!("Username deregistering is currently disabled, please create a new wallet to register this username");
                                }
                            } else {
                                error!("Failed to get lock on WALLET_DETAILS muxtex (try again)");
                            }
                        } else if read == *"get_keypair" {
                            warn!("WARNING: You are about to be given the private key to your account. This string allows ANYONE (with the key) to send a transaction from your account");
                            warn!("If someone is telling you to give them this key, you are probably being scammed. The avrio team will never ask your for your private key. ");
                            warn!("The only time you should enter your private key, is into a wallet to use your funds. HOWEVER, we do not reccomened doing this. Instead create a new wallet, and send the funds to it from here");
                            warn!("Please remeber the avrio team is not liable for any funds lost");
                            error!("You can safley ignore this message as testnet coins have no value, but dont go loosing your coins :D");
                            info!("If you understand these risks please enter: confirm");
                            let confirm: String = trim_newline(&mut read!());
                            if confirm.to_uppercase() != "CONFIRM" {
                                error!("Did not enter confirm, aborting (got {})", confirm);
                            } else {
                                println!("Your publickey is: {}", wall.public_key); // println! to prevent it being saved in the logs
                                println!("Your private key is: {}", wall.private_key);
                            }
                        } else if read == *"burn" {
                            info!("Please enter the amount");
                            let amount: f64 =
                                trim_newline(&mut read!("{}\n")).parse::<f64>().unwrap();
                            let mut txn = Transaction {
                                hash: String::from(""),
                                amount: to_atomic(amount),
                                extra: String::from(""),
                                flag: 'b',
                                sender_key: wall.public_key.clone(),
                                receive_key: wall.public_key.clone(),
                                access_key: String::from(""),
                                unlock_time: 0,
                                gas_price: 10, // 0.001 AIO
                                max_gas: u64::max_value(),
                                nonce: 0,
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Time went backwards")
                                    .as_millis() as u64,
                            };
                            let request_url = format!(
                                "{}/api/v1/balances/{}",
                                SERVER_ADDR.lock().unwrap().to_string(),
                                wall.public_key
                            );
                            if let Ok(response_undec) = reqwest::get(&request_url).await {
                                if let Ok(response) = response_undec.json::<Balances>().await {
                                    if txn.amount + txn.fee() > response.balance {
                                        error!("Insufficent balance");
                                    } else {
                                        let request_url = format!(
                                            "{}/api/v1/transactioncount/{}",
                                            SERVER_ADDR.lock().unwrap().to_string(),
                                            wall.public_key
                                        );
                                        if let Ok(response) = reqwest::get(&request_url).await {
                                            if let Ok(transactioncount) =
                                                response.json::<Transactioncount>().await
                                            {
                                                txn.nonce = transactioncount.transaction_count;
                                                txn.hash();
                                                if let Err(e) =
                                                    send_transaction(txn, wall.clone()).await
                                                {
                                                    error!("Failed to send txn, got error={}", e);
                                                }
                                            } else {
                                                error!("Failed to decode recieved response into transactioncount struct");
                                            }
                                        } else {
                                            error!("Failed to send request={}", request_url);
                                        }
                                    }
                                }
                            }
                        } else if read == "help" {
                            info!("Commands:");
                            info!("balance : Gets the balance of the currently loaded wallet");
                            info!("get_address : Gets the address assosciated with this wallet");
                            info!("send : Sends a transaction");
                            info!("generate : Allows you to generate lots of blocks with lots of transactions in for stress testing. Please dont abuse");
                            info!("send_txn_advanced : allows you to send a transaction with advanced options");
                            info!("burn : allows you to burn funds");
                            info!("exit : Safely shutsdown thr program. PLEASE use instead of ctrl + c");
                            info!("help : shows this help");
                        } else if read_split[0] == "generate" {
                            if read_split.len() == 3 {
                                let amount: u64 = read_split[1].parse().unwrap_or(1);
                                let txn_per_block: u64 = read_split[2].parse().unwrap_or(1);
                                let mut blocks: Vec<Block> = vec![];
                                if txn_per_block <= 10 && amount < 200 {
                                    let mut failed = false;
                                    let request_url = format!(
                                        "{}/api/v1/balances/{}",
                                        SERVER_ADDR.lock().unwrap().to_string(),
                                        wall.public_key
                                    );
                                    if let Ok(response_undec) = reqwest::get(&request_url).await {
                                        if let Ok(response) =
                                            response_undec.json::<Balances>().await
                                        {
                                            if amount * (txn_per_block * 200) + amount
                                                > response.balance
                                            {
                                                error!("Insufficent balance");
                                            } else {
                                                info!("Beginning generation");
                                                if let Ok(blocks) = generate_blocks(
                                                    amount,
                                                    txn_per_block,
                                                    wall.clone(),
                                                )
                                                .await
                                                {
                                                    info!("Generation complete");
                                                    for block in blocks {
                                                        /*if let Err(e) =
                                                            send_block(block, wall.clone())
                                                                .await
                                                        {
                                                            error!(
                                                                "Failed to send block, got error={}",
                                                                e
                                                            );
                                                            failed = true;
                                                        }*/
                                                    }
                                                    if failed {
                                                        error!("Failed to send all blocks");
                                                    }
                                                } else {
                                                    error!("Failed to generate blocks");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else if read_split[0] == "lock" {
                            info!("Enter amount:");
                            let amount: String = trim_newline(&mut read!());
                            if let Ok(amount_int) = amount.parse::<f64>() {
                                let mut txn = Transaction {
                                    hash: String::from(""),
                                    amount: to_atomic(amount_int),
                                    extra: String::from(""),
                                    flag: 'l',
                                    sender_key: wall.public_key.clone(),
                                    receive_key: wall.public_key.clone(),
                                    access_key: String::from(""),
                                    unlock_time: 0,
                                    gas_price: 20,
                                    max_gas: u64::MAX,
                                    nonce: 0,
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .expect("time went backwards ono")
                                        .as_millis()
                                        as u64,
                                };
                                let request_url = format!(
                                    "{}/api/v1/transactioncount/{}",
                                    SERVER_ADDR.lock().unwrap().to_string(),
                                    wall.public_key
                                );
                                if let Ok(response) = reqwest::get(&request_url).await {
                                    if let Ok(transactioncount) =
                                        response.json::<Transactioncount>().await
                                    {
                                        txn.nonce = transactioncount.transaction_count;

                                        let request_url = format!(
                                            "{}/api/v1/balances/{}",
                                            SERVER_ADDR.lock().unwrap().to_string(),
                                            wall.public_key
                                        );
                                        if let Ok(response_undec) = reqwest::get(&request_url).await
                                        {
                                            if let Ok(response) =
                                                response_undec.json::<Balances>().await
                                            {
                                                if txn.amount + txn.fee() < response.balance {
                                                    txn.hash();

                                                    match send_transaction(txn, wall.clone()).await
                                                    {
                                                        Ok(_) => {
                                                            info!("Locked {} AIO", amount_int);
                                                        }
                                                        Err(e) => {
                                                            error!("Failed to send txn: {}", e);
                                                        }
                                                    }
                                                } else {
                                                    error!(
                                                        "Insufficent balance, have={}, need={}",
                                                        response.balance,
                                                        txn.amount + txn.fee()
                                                    )
                                                }
                                            } else {
                                                error!("Failed to parse balance")
                                            }
                                        } else {
                                            error!("Failed to get balance")
                                        }
                                    } else {
                                        error!("Failed to parse txn count");
                                    }
                                } else {
                                    error!("Failed tog et txn count for chain");
                                }
                            } else {
                                error!("{} is not a valid number", amount);
                            }
                        } else {
                            error!("Unknown command: {}", read);
                        }
                    }
                } else {
                    error!("Failed to decode json, gave error={:?}", try_decode_json);
                }
            } else {
                error!(
                    "Failed to get blockcount for our chain, error={}",
                    try_get_response.unwrap_err()
                );
            }
        } else {
            error!("Failed to gain lock on wallet details LS");
        }
    } else {
        error!("Failed to get wallet");
        std::process::exit(0);
    }
}

pub async fn generate_blocks(
    amount: u64,
    txn_per_block: u64,
    wallet: Wallet,
) -> Result<Vec<Block>, Box<dyn std::error::Error>> {
    let mut blocks = vec![];
    let mut last_hash = String::from("");
    // get top block hash from the api
    let mut height = 0;
    let mut account_nonce: u64 = 0;
    let request_url = format!(
        "{}/api/v1/transactioncount/{}",
        SERVER_ADDR.lock().unwrap().to_string(),
        wallet.public_key
    );
    if let Ok(response) = reqwest::get(&request_url).await {
        if let Ok(transactioncount) = response.json::<Transactioncount>().await {
            account_nonce = transactioncount.transaction_count;
        } else {
            error!("Failed to decode recieved response into transactioncount struct");
            return Err("Failed to decode recieved response into transactioncount struct".into());
        }
    } else {
        error!("Failed to send request={}", request_url);
        return Err("Failed to send request".into());
    }
    let request_url = format!(
        "{}/api/v1/blockcount/{}",
        SERVER_ADDR.lock().unwrap().to_owned(),
        wallet.public_key.clone()
    );
    if let Ok(response) = reqwest::get(&request_url).await {
        if let Ok(response_decoded) = response.json::<Blockcount>().await {
            height = response_decoded.blockcount;
            let request_url = format!(
                "{}/api/v1/hash_at_height/{}/{}",
                SERVER_ADDR.lock().unwrap().to_owned(),
                wallet.public_key.clone(),
                height - 1
            );
            if let Ok(response) = reqwest::get(&request_url).await {
                if let Ok(response_decoded) = response.json::<HashAtHeight>().await {
                    last_hash = response_decoded.hash;
                }
            }
        }
    }
    if last_hash == "" {
        error!("Failed to get last hash");
        return Err("Failed to get last hash".into());
    }
    for block_height in height..(height + amount) {
        // generate txns
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_millis() as u64;
        let mut txns: Vec<Transaction> = vec![];
        for _ in 0..=txn_per_block {
            let mut txn = Transaction {
                hash: String::default(),
                amount: 0,
                extra: String::default(),
                flag: 'n',
                sender_key: wallet.public_key.clone(),
                receive_key: wallet.public_key.clone(),
                access_key: String::default(),
                unlock_time: 0,
                gas_price: 10,
                max_gas: u64::MAX,
                nonce: account_nonce + (txn_per_block * (block_height - height)),
                timestamp: time_now,
            };
            txn.hash();
            txns.push(txn);
        }
        // generate a block
        let mut block = Block {
            header: Header {
                version_major: config().version_major,
                version_breaking: config().version_breaking,
                version_minor: config().version_minor,
                chain_key: wallet.public_key.clone(),
                prev_hash: last_hash.clone(),
                height: block_height,
                timestamp: time_now,
                network: config().network_id,
            },
            block_type: BlockType::Send,
            send_block: None,
            txns,
            hash: String::default(),
            signature: String::default(),
        };
        block.hash();
        if let Err(sign_error) = block.sign(&wallet.private_key) {
            error!("Failed to sign block, error={}", sign_error);
            return Err(format!("Failed to sign block, error={}", sign_error).into());
        }
        last_hash = block.hash.clone();
        blocks.push(block);
    }
    Ok(blocks)
}

pub fn create_wallet() -> Result<Wallet, Box<dyn Error>> {
    info!("Enter new wallet name:");
    let name: String = trim_newline(&mut read!());
    info!("Enter password:");
    let password: String = rpassword::read_password()?;
    if get_data(config().db_path + &"/wallets/".to_owned() + &name, "pubkey") != "-1" {
        error!("Wallet already exists");
        return Err("Wallet path taken".into());
    } else {
        let mut keypair: Vec<String> = vec![];
        generate_keypair(&mut keypair);
        if let Err(e) = save_wallet(&keypair, password, name) {
            error!("Failed to save new wallet, gave error={}", e);
            return Err(e);
        } else {
            info!("Created and saved wallet with public key: {}", keypair[0]);
            return Ok(Wallet::from_private_key(keypair[1].clone()));
        }
    }
}

fn import_wallet() -> Result<Wallet, Box<dyn Error>> {
    info!("Please enter the wallet private key");
    let private_key: String = trim_newline(&mut read!());
    info!("Please enter name of new wallet");
    let name: String = trim_newline(&mut read!());
    if get_data(config().db_path + &"/wallets/".to_owned() + &name, "pubkey") != "-1" {
        error!("Wallet with name={} already exists", name);
        return Err("wallet with name already exists".into());
    }
    info!("Please enter wallet password");
    let password: String = rpassword::read_password()?;
    let wallet = Wallet::from_private_key(private_key);
    if let Err(e) = save_wallet(
        &[wallet.private_key.clone(), wallet.private_key.clone()],
        password,
        name,
    ) {
        error!("Failed to save imported wallet: gave error={}", e);
    }
    Ok(wallet)
}

fn open_wallet_gather() -> Result<Wallet, Box<dyn Error>> {
    info!("Enter your wallet name");
    let name: String = trim_newline(&mut read!());
    info!("Enter your wallet password");
    let pswd: String = rpassword::read_password()?;
    Ok(open_wallet(name, pswd))
}

pub fn save_wallet(
    keypair: &[String],
    password: String,
    name: String,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let conf = config();
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
    Ok(())
}

pub fn generate_keypair(out: &mut Vec<String>) {
    let wallet: Wallet = Wallet::gen();
    out.push(wallet.public_key.clone());
    out.push(wallet.private_key);
    let _conf = config();
}

pub fn open_wallet(wallet_name: String, password: String) -> Wallet {
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
        config().db_path + &"/wallets/".to_owned() + &wallet_name,
        &"privkey".to_owned(),
    ))
    .expect("failed to parse hex");
    let privkey = String::from_utf8(
        aead.decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!"),
    )
    .expect("failed to parse utf8 (i1)");
    Wallet::from_private_key(privkey)
}
