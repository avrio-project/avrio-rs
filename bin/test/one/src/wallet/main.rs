/*
    Copyright 2020 the avrio core devs

    bin/test/one/src/wallet/main.rs

    This is the first attempt at a Avrio CLI wallet.
    It uses the JSON API v1 provided by the Avrio Daemon.
*/

use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use avrio_blockchain::{
    genesis::{generate_genesis_block, get_genesis_block, GenesisBlockErrors},
    Block, BlockType, Header,
};
use avrio_config::config;
use avrio_core::{account::*, transaction::Transaction};
use avrio_crypto::Wallet;
use avrio_database::*;
use avrio_rpc::{launch_client, Announcement, Caller};
use clap::{App, Arg};
use fern::colors::{Color, ColoredLevelConfig};
use lazy_static::*;
use log::*;
use reqwest::Client;
use serde::Deserialize;
use serde_json;
use std::sync::Mutex;
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
}
#[derive(Clone, Deserialize, Debug)]
struct Blockcount {
    success: bool,
    blockcount: u64,
}
#[derive(Clone, Deserialize, Debug)]
struct Transactioncount {
    success: bool,
    transaction_count: u64,
}

#[derive(Clone, Deserialize, Debug)]
struct HashAtHeight {
    success: bool,
    hash: String,
}

#[derive(Clone, Deserialize, Debug)]
struct PublickeyForUsername {
    success: bool,
    publickey: String,
}

#[derive(Clone, Deserialize)]
struct Balances {
    success: bool,
    chainkey: String,
    balance: u64,
    locked: u64,
}
lazy_static! {
    static ref WALLET_DETAILS: Mutex<WalletDetails> = Mutex::new(WalletDetails::default());
}

fn setup_logging(verbosity: u64) -> Result<(), fern::InitError> {
    let mut base_config = fern::Dispatch::new();
    base_config = match verbosity {
        0 => {
            // Let's say we depend on something which whose "info" level messages are too
            // verbose to include in end-user output. If we don't need them,
            // let's not include them.
            base_config
                .level(log::LevelFilter::Error)
                .level_for("avrio_database", log::LevelFilter::Error)
                .level_for("avrio_config", log::LevelFilter::Error)
                .level_for("avrio_wallet", log::LevelFilter::Error)
                .level_for("avrio_core", log::LevelFilter::Error)
                .level_for("avrio_crypto", log::LevelFilter::Error)
                .level_for("avrio_blockchain", log::LevelFilter::Error)
                .level_for("avrio_rpc", log::LevelFilter::Error)
                .level_for("avrio_p2p", log::LevelFilter::Error)
        }
        1 => base_config
            .level(log::LevelFilter::Warn)
            .level(log::LevelFilter::Error)
            .level_for("avrio_database", log::LevelFilter::Warn)
            .level_for("avrio_config", log::LevelFilter::Warn)
            .level_for("seednode", log::LevelFilter::Warn)
            .level_for("avrio_core", log::LevelFilter::Warn)
            .level_for("avrio_crypto", log::LevelFilter::Warn)
            .level_for("avrio_wallet", log::LevelFilter::Warn)
            .level_for("avrio_p2p", log::LevelFilter::Warn)
            .level_for("avrio_rpc", log::LevelFilter::Warn)
            .level_for("avrio_blockchain", log::LevelFilter::Warn),
        2 => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Info)
            .level_for("avrio_config", log::LevelFilter::Info)
            .level_for("seednode", log::LevelFilter::Info)
            .level_for("avrio_core", log::LevelFilter::Info)
            .level_for("avrio_crypto", log::LevelFilter::Info)
            .level_for("avrio_p2p", log::LevelFilter::Info)
            .level_for("avrio_wallet", log::LevelFilter::Info)
            .level_for("avrio_rpc", log::LevelFilter::Info)
            .level_for("avrio_blockchain", log::LevelFilter::Info),
        3 => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Debug)
            .level_for("avrio_config", log::LevelFilter::Debug)
            .level_for("seednode", log::LevelFilter::Debug)
            .level_for("avrio_core", log::LevelFilter::Debug)
            .level_for("avrio_crypto", log::LevelFilter::Debug)
            .level_for("avrio_p2p", log::LevelFilter::Debug)
            .level_for("avrio_wallet", log::LevelFilter::Debug)
            .level_for("avrio_rpc", log::LevelFilter::Debug)
            .level_for("avrio_blockchain", log::LevelFilter::Debug),
        _ => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Trace)
            .level_for("avrio_config", log::LevelFilter::Trace)
            .level_for("seednode", log::LevelFilter::Trace)
            .level_for("avrio_core", log::LevelFilter::Trace)
            .level_for("avrio_wallet", log::LevelFilter::Trace)
            .level_for("avrio_p2p", log::LevelFilter::Trace)
            .level_for("avrio_crypto", log::LevelFilter::Trace)
            .level_for("avrio_rpc", log::LevelFilter::Trace)
            .level_for("avrio_blockchain", log::LevelFilter::Trace),
    };

    // Separate file config so we can include year, month and day in file logs
    let file_config = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .chain(fern::log_file("avrio-wallet.log")?);

    let stdout_config = fern::Dispatch::new()
        .format(|out, message, record| {
            let colors = ColoredLevelConfig::default()
                .info(Color::Green)
                .debug(Color::Magenta);
            // special format for debug messages coming from our own crate.
            if record.level() > log::LevelFilter::Info && record.target() == "cmd_program" {
                out.finish(format_args!(
                    "---\nDEBUG: {}: {}\n---",
                    chrono::Local::now().format("%H:%M:%S"),
                    message
                ))
            } else {
                out.finish(format_args!(
                    "{}[{}][{}] {}",
                    chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                    record.target(),
                    colors.color(record.level()),
                    message
                ))
            }
        })
        .chain(io::stdout());

    base_config
        .chain(file_config)
        .chain(stdout_config)
        .apply()?;

    Ok(())
}

fn get_choice() -> u8 {
    info!("[1] Open an existing wallet");
    info!("[2] Create a wallet");
    info!("[3] Import private keys");
    let ans: u8 = read!();
    return ans;
}
pub fn new_ann(ann: Announcement) {
    if let Ok(mut locked) = WALLET_DETAILS.lock() {
        debug!("Gained lock on WALLET_DETAILS");
        if ann.m_type == "block".to_string() {
            // ann.msg contains a block in json format
            if let Ok(blk) = serde_json::from_str::<Block>(&ann.content) {
                if blk.block_type == BlockType::Recieve {
                    let balance_before = locked.balance;
                    for txn in blk.txns {
                        trace!("Txn: {:#?}", txn);
                        if txn.sender_key == locked.wallet.as_ref().unwrap().public_key
                            && txn.flag != 'c'
                        {
                            locked.balance -= txn.amount;
                            locked.balance -= txn.gas * txn.gas_price;
                        } else if txn.receive_key == locked.wallet.as_ref().unwrap().public_key {
                            locked.balance += txn.amount;
                        }
                    }
                    if balance_before != locked.balance {
                        info!(
                            "New block {}, old balance: {}, new balance: {}",
                            blk.hash,
                            to_dec(balance_before),
                            to_dec(locked.balance)
                        );
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
#[tokio::main]
async fn main() {
    let matches = App::new("Avrio Wallet")
        .version("Testnet Pre-alpha 0.0.1")
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
    info!("Avrio Wallet Testnet v1.0.0 (pre-alpha)");
    let config_ = config();
    let _ = config_.save();
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
            };
            drop(locked_ls);
            let request_url = format!(
                "http://127.0.0.1:8000/api/v1/blockcount/{}",
                wall.public_key
            );
            let try_get_response = reqwest::get(&request_url).await;
            if let Ok(response) = try_get_response {
                let try_decode_json = response.json::<Blockcount>().await;
                if let Ok(response) = try_decode_json {
                    let blockcount = response.blockcount;
                    if blockcount == 0 {
                        info!("No existing blocks for chain, creating genesis blocks");
                        // TODO: Create genesis blocks, send to node
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
                                let request_url = "http://127.0.0.1:8000/api/v1/submit_block";
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
                                                "http://127.0.0.1:8000/api/v1/submit_block";
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
                    let request_url =
                        format!("http://127.0.0.1:8000/api/v1/balances/{}", wall.public_key);
                    if let Ok(response) = reqwest::get(&request_url).await {
                        if let Ok(response) = response.json::<Balances>().await {
                            info!("Balance: {}, Locked: {}", response.balance, response.locked);
                            if let Ok(mut locked_ls) = WALLET_DETAILS.lock() {
                                let mut wallet_details = (*locked_ls).clone();
                                wallet_details.balance = response.balance;
                                wallet_details.locked = response.locked;
                                *locked_ls = wallet_details;
                                drop(locked_ls);
                            }
                        }
                    }
                    let request_url = format!(
                        "http://127.0.0.1:8000/api/v1/transactioncount/{}",
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
                    if let Ok(_) = launch_client(17785, vec![], caller) {
                        debug!("Launched RPC listener");
                    }
                    loop {
                        // Now we loop until shutdown
                        let _ = io::stdout().flush();
                        let read: String = read!("{}\n");
                        if read == *"send_txn" {
                            info!("Please enter the amount");
                            let amount: f64 = read!("{}\n");
                            let mut txn = Transaction {
                                hash: String::from(""),
                                amount: to_atomc(amount),
                                extra: String::from(""),
                                flag: 'n',
                                sender_key: wall.public_key.clone(),
                                receive_key: String::from(""),
                                access_key: String::from(""),
                                unlock_time: 0,
                                gas_price: 10, // 0.001 AIO
                                gas: 20,
                                max_gas: u64::max_value(),
                                nonce: 0,
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Time went backwards")
                                    .as_millis() as u64,
                                signature: String::from(""),
                            };
                            info!("Please enter the reciever address or username:");
                            let addr: String = read!();
                            if avrio_crypto::valid_address(&addr) {
                                let rec_wall = Wallet::from_address(addr);
                                txn.receive_key = rec_wall.public_key;
                            } else {
                                debug!("Could not find acc with addr={}, trying as username", addr);
                                let request_url = format!(
                                    "http://127.0.0.1:8000/api/v1/publickey_for_username/{}",
                                    addr
                                );
                                if let Ok(response) = reqwest::get(&request_url).await {
                                    if let Ok(publickey_for_username) =
                                        response.json::<PublickeyForUsername>().await
                                    {
                                        txn.receive_key = publickey_for_username.publickey;
                                    }
                                }
                            }
                            let request_url = format!(
                                "http://127.0.0.1:8000/api/v1/transactioncount/{}",
                                wall.public_key
                            );
                            if let Ok(response) = reqwest::get(&request_url).await {
                                if let Ok(transactioncount) =
                                    response.json::<Transactioncount>().await
                                {
                                    txn.nonce = transactioncount.transaction_count;
                                    txn.hash();
                                    let _ = txn.sign(&wall.private_key);
                                    let request_url = format!(
                                        "http://127.0.0.1:8000/api/v1/blockcount/{}",
                                        wall.public_key.clone()
                                    );
                                    let try_get_response = reqwest::get(&request_url).await;
                                    if let Ok(response) = try_get_response {
                                        let try_decode_json = response.json::<Blockcount>().await;
                                        if let Ok(response) = try_decode_json {
                                            let height = response.blockcount;
                                            let request_url = format!(
                                                "http://127.0.0.1:8000/api/v1/hash_at_height/{}/{}",
                                                wall.public_key.clone(),
                                                height - 1
                                            );
                                            let try_get_response = reqwest::get(&request_url).await;
                                            if let Ok(response) = try_get_response {
                                                let try_decode_json =
                                                    response.json::<HashAtHeight>().await;
                                                if let Ok(response) = try_decode_json {
                                                    let prev_block_hash = response.hash;
                                                    let mut blk = Block {
                                                        header: Header {
                                                            version_major: 0,
                                                            version_breaking: 0,
                                                            version_minor: 0,
                                                            chain_key: wall.public_key.clone(),
                                                            prev_hash: prev_block_hash,
                                                            height: height,
                                                            timestamp: SystemTime::now()
                                                                .duration_since(UNIX_EPOCH)
                                                                .expect("Time went backwards")
                                                                .as_millis()
                                                                as u64,
                                                            network: vec![
                                                                97, 118, 114, 105, 111, 32, 110,
                                                                111, 111, 100, 108, 101,
                                                            ],
                                                        },
                                                        block_type: BlockType::Send,
                                                        send_block: None,
                                                        txns: vec![txn],
                                                        hash: "".to_owned(),
                                                        signature: "".to_owned(),
                                                        confimed: false,
                                                        node_signatures: vec![],
                                                    };
                                                    blk.hash();
                                                    let _ = blk.sign(&wall.private_key);
                                                    let mut blocks: Vec<String> = vec![];
                                                    if let Ok(block_json) =
                                                        serde_json::to_string(&blk)
                                                    {
                                                        blocks.push(block_json);
                                                        // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that
                                                        let mut proccessed_accs: Vec<String> =
                                                            vec![];

                                                        let mut failed = false;
                                                        for txn in &blk.txns {
                                                            if !proccessed_accs
                                                                .contains(&txn.receive_key)
                                                            {
                                                                let rec_blk = blk
                                                                    .form_receive_block(Some(
                                                                        txn.receive_key.to_owned(),
                                                                    ))
                                                                    .unwrap();
                                                                trace!(
                                                                    "Created rec block={:#?}",
                                                                    rec_blk
                                                                );

                                                                proccessed_accs
                                                                    .push(txn.receive_key.clone());
                                                                if let Ok(rec_blk_json) =
                                                                    serde_json::to_string(&rec_blk)
                                                                {
                                                                    blocks.push(rec_blk_json);
                                                                } else {
                                                                    error!("Failed to encode rec block as json");
                                                                    failed = true;
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
                                                                    if let Ok(response_string) =
                                                                        response.text().await
                                                                    {
                                                                        if response_string
                                                                            .contains("error")
                                                                        {
                                                                            error!(
                                                                                "Failed to submit block, response={}",
                                                                                response_string
                                                                            );
                                                                        } else {
                                                                            debug!(
                                                                                "Submit response={}",
                                                                                response_string
                                                                            );
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            info!("Sent all blocks to node");
                                                        }
                                                    } else {
                                                        error!(
                                                            "Failed to encode source block as json"
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                error!("Failed to decode recieved response into transactioncount struct");
                            }
                        } else if read == *"address" {
                            info!("Our address: {}", wall.address());
                        } else if read == *"claim" {
                            info!("Please enter the amount");
                            let amount: f64 = read!("{}\n");
                            let mut txn = Transaction {
                                hash: String::from(""),
                                amount: to_atomc(amount),
                                extra: String::from(""),
                                flag: 'c',
                                sender_key: wall.public_key.clone(),
                                receive_key: wall.public_key.clone(),
                                access_key: String::from(""),
                                unlock_time: 0,
                                gas_price: 10, // 0.001 AIO
                                gas: 20,
                                max_gas: u64::max_value(),
                                nonce: 0,
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Time went backwards")
                                    .as_millis() as u64,
                                signature: String::from(""),
                            };
                            let request_url = format!(
                                "http://127.0.0.1:8000/api/v1/transactioncount/{}",
                                wall.public_key
                            );
                            if let Ok(response) = reqwest::get(&request_url).await {
                                if let Ok(transactioncount) =
                                    response.json::<Transactioncount>().await
                                {
                                    txn.nonce = transactioncount.transaction_count;
                                    txn.hash();
                                    let _ = txn.sign(&wall.private_key);
                                    let request_url = format!(
                                        "http://127.0.0.1:8000/api/v1/blockcount/{}",
                                        wall.public_key.clone()
                                    );
                                    let try_get_response = reqwest::get(&request_url).await;
                                    if let Ok(response) = try_get_response {
                                        let try_decode_json = response.json::<Blockcount>().await;
                                        if let Ok(response) = try_decode_json {
                                            let height = response.blockcount;
                                            let request_url = format!(
                                                "http://127.0.0.1:8000/api/v1/hash_at_height/{}/{}",
                                                wall.public_key.clone(),
                                                height - 1
                                            );
                                            let try_get_response = reqwest::get(&request_url).await;
                                            if let Ok(response) = try_get_response {
                                                let try_decode_json =
                                                    response.json::<HashAtHeight>().await;
                                                if let Ok(response) = try_decode_json {
                                                    let prev_block_hash = response.hash;
                                                    let mut blk = Block {
                                                        header: Header {
                                                            version_major: 0,
                                                            version_breaking: 0,
                                                            version_minor: 0,
                                                            chain_key: wall.public_key.clone(),
                                                            prev_hash: prev_block_hash,
                                                            height: height,
                                                            timestamp: SystemTime::now()
                                                                .duration_since(UNIX_EPOCH)
                                                                .expect("Time went backwards")
                                                                .as_millis()
                                                                as u64,
                                                            network: vec![
                                                                97, 118, 114, 105, 111, 32, 110,
                                                                111, 111, 100, 108, 101,
                                                            ],
                                                        },
                                                        block_type: BlockType::Send,
                                                        send_block: None,
                                                        txns: vec![txn],
                                                        hash: "".to_owned(),
                                                        signature: "".to_owned(),
                                                        confimed: false,
                                                        node_signatures: vec![],
                                                    };
                                                    blk.hash();
                                                    let _ = blk.sign(&wall.private_key);
                                                    let mut blocks: Vec<String> = vec![];
                                                    if let Ok(block_json) =
                                                        serde_json::to_string(&blk)
                                                    {
                                                        blocks.push(block_json);
                                                        // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that
                                                        let mut proccessed_accs: Vec<String> =
                                                            vec![];

                                                        let mut failed = false;
                                                        for txn in &blk.txns {
                                                            if !proccessed_accs
                                                                .contains(&txn.receive_key)
                                                            {
                                                                let rec_blk = blk
                                                                    .form_receive_block(Some(
                                                                        txn.receive_key.to_owned(),
                                                                    ))
                                                                    .unwrap();
                                                                trace!(
                                                                    "Created rec block={:#?}",
                                                                    rec_blk
                                                                );

                                                                proccessed_accs
                                                                    .push(txn.receive_key.clone());
                                                                if let Ok(rec_blk_json) =
                                                                    serde_json::to_string(&rec_blk)
                                                                {
                                                                    blocks.push(rec_blk_json);
                                                                } else {
                                                                    error!("Failed to encode rec block as json");
                                                                    failed = true;
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
                                                                    if let Ok(response_string) =
                                                                        response.text().await
                                                                    {
                                                                        if response_string
                                                                            .contains("error")
                                                                        {
                                                                            error!(
                                                                                "Failed to submit block, response={}",
                                                                                response_string
                                                                            );
                                                                        } else {
                                                                            debug!(
                                                                                "Submit response={}",
                                                                                response_string
                                                                            );
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            info!("Sent all blocks to node");
                                                        }
                                                    } else {
                                                        error!(
                                                            "Failed to encode source block as json"
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                error!("Failed to decode recieved response into transactioncount struct");
                            }
                        } else if read == *"address" {
                            info!("Our address: {}", wall.address());
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
fn create_wallet() -> Result<Wallet, Box<dyn Error>> {
    info!("Enter new wallet name:");
    let name: String = read!();
    info!("Enter password:");
    let password: String = read!();
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
    let private_key: String = read!();
    info!("Please enter name of new wallet");
    let name: String = read!();
    if get_data(config().db_path + &"/wallets/".to_owned() + &name, "pubkey") != "-1" {
        error!("Wallet with name={} already exists", name);
        return Err("wallet with name already exists".into());
    }
    info!("Please enter wallet password");
    let password: String = read!();
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
    let name: String = read!();
    info!("Enter your wallet password");
    let pswd: String = read!();
    Ok(open_wallet(name, pswd))
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
    let aead = Aes256Gcm::new(key);
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

fn generate_keypair(out: &mut Vec<String>) {
    let wallet: Wallet = Wallet::gen();
    out.push(wallet.public_key.clone());
    out.push(wallet.private_key);
    let mut conf = config();
    conf.chain_key = wallet.public_key;
    let _ = conf.save();
}

fn open_wallet(wallet_name: String, password: String) -> Wallet {
    // TODO: use unique nonce
    // can we just hash the public key with some local data on the computer (maybe mac address)? Or is that insufficent (TODO: find out)
    let mut padded = password.as_bytes().to_vec();
    while padded.len() != 32 && padded.len() < 33 {
        padded.push(b"n"[0]);
    }
    let padded_string = String::from_utf8(padded).unwrap();
    trace!("key: {}", padded_string);
    let key = GenericArray::clone_from_slice(padded_string.as_bytes());
    let aead = Aes256Gcm::new(key);
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
