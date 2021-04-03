/*
    Copyright 2020 the avrio core devs

    bin/test/one/src/wallet/main.rs

    This is the first attempt at a Avrio CLI wallet.
    It uses the JSON API v1 provided by the Avrio Daemon.
*/

use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use avrio_blockchain::{Block, BlockType};
use avrio_config::{config, Config};
use avrio_core::{account::*, transaction::Transaction};
use avrio_crypto::Wallet;
use avrio_database::*;
use avrio_rpc::{launch_client, Announcement, Caller};
use clap::{App, Arg};
use fern::colors::{Color, ColoredLevelConfig};
use lazy_static::*;
use log::*;
use serde_json;
use std::sync::Mutex;
use std::{error::Error, io};
use text_io::read;
#[derive(Default)]
struct WalletDetails {
    wallet: Option<Wallet>,
    balance: u64,
    top_block_hash: String,
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
        .chain(fern::log_file("program.log")?);

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
                        if txn.sender_key == locked.wallet.as_ref().unwrap().public_key {
                            locked.balance -= txn.amount;
                        } else if txn.receive_key == locked.wallet.as_ref().unwrap().public_key {
                            locked.balance += txn.amount;
                        }
                    }
                    if balance_before != locked.balance {
                        info!(
                            "New block {}, old balance: {}, new balance: {}",
                            blk.hash, balance_before, locked.balance
                        );
                    } else {
                        debug!("Block contained no transactions affecting us");
                    }
                }
            }
        }
    }
}
fn main() {
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
        if let Ok(_) = launch_client(12, vec![], caller) {
            debug!("Launched RPC listener");
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
