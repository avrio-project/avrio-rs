use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use serenity::{
    async_trait,
    model::{gateway::Ready, id::ChannelId},
    prelude::*,
};
use std::io::{self, Write};
use std::thread;
use tokio::runtime::Runtime;

extern crate clap;
use clap::{App, Arg};

use std::fs::create_dir_all;

use std::net::{SocketAddr, TcpStream};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

pub extern crate avrio_config;
use avrio_config::{config, Config};

extern crate avrio_core;
use avrio_core::{account::to_atomc, transaction::Transaction};

use avrio_p2p::{
    core::new_connection, core::rec_server, helper::prop_block, helper::sync, helper::sync_needed,
};

extern crate avrio_blockchain;
use avrio_blockchain::{
    genesis::{generateGenesisBlock, genesisBlockErrors, genesis_blocks, getGenesisBlock},
    *,
};

extern crate avrio_database;
use avrio_database::{get_data, get_peerlist, open_database, save_data};

#[macro_use]
extern crate log;
extern crate simple_logger;

extern crate hex;

use avrio_api::start_server;

extern crate avrio_crypto;
use avrio_crypto::Wallet;
use fern::colors::{Color, ColoredLevelConfig};

use text_io::read;
struct Handler;
static TXN_NOTIF_CHANNEL_ID: u64 = 823568815350480916;
static mut CTX_HOLDER: Option<Context> = None;

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        info!("{} is connected!", ready.user.name);
        unsafe { CTX_HOLDER = Some(ctx) }
    }
}

pub async fn recieved_block(block: avrio_blockchain::Block) {
    if config().discord_token == "DISCORD_TOKEN" {
        return;
    }
    debug!("Discord hook: {:?}", block);

    unsafe {
        if let Err(why) = ChannelId(TXN_NOTIF_CHANNEL_ID)
            .send_message(&CTX_HOLDER.clone().unwrap(), |m| {
                m.embed(|e| {
                    e.title("New Block recieved");
                    e.field("Hash", format!("{}", block.hash.to_owned()), false);
                    e.field("Transaction count", block.txns.len(), true);
                    let mut total_transfered = 0;
                    for txn in block.clone().txns {
                        total_transfered += txn.amount;
                    }
                    e.field(
                        "Total funds change",
                        avrio_core::account::to_dec(total_transfered),
                        true,
                    );
                    e.field("Timestamp", format!("{} ", block.header.timestamp), false);
                    if block.block_type == BlockType::Recieve {
                        e.field("Type", "Recieve", true);
                        e.field(
                            "Send block hash",
                            format!("{} ", block.send_block.clone().unwrap_or_default()),
                            true,
                        );
                    } else {
                        e.field("Type", "Send", false);
                    }
                    //e.field("Signature", format!("{} ", txn.signature), false);
                    //e.field("Gas, gas price, total fee", format!("{}, {}, {} ", txn.gas, txn.gas_price, txn.gas * txn.gas_price), false);
                    e.footer(|f| {
                        f.text("Avro Testnet Bot");

                        f
                    });
                    e
                });
                m
            })
            .await
        {
            error!("Error sending message: {:?}", why);
        };
    }
}

pub async fn username_registered(
    block: avrio_blockchain::Block,
    account: avrio_core::account::Account,
) {
    if config().discord_token == "DISCORD_TOKEN" {
        return;
    }
    debug!("Discord hook: {:?} {:?}", block, account);
    unsafe {
        if let Err(why) = ChannelId(TXN_NOTIF_CHANNEL_ID)
            .send_message(&CTX_HOLDER.clone().unwrap(), |m| {
                m.embed(|e| {
                    e.title("New Username registered");
                    e.field("Username", format!("{}", account.username), true);
                    e.field(
                        "Address",
                        format!(
                            "{}",
                            avrio_crypto::public_key_to_address(&account.public_key)
                        ),
                        true,
                    );
                    e.field("In block", format!("{}", block.hash.to_owned()), false);
                    e.field("Timestamp", format!("{} ", block.header.timestamp), false);
                    e.footer(|f| {
                        f.text("Avro Testnet Bot");

                        f
                    });
                    e
                });
                m
            })
            .await
        {
            error!("Error sending message: {:?}", why);
        };
    }
}

#[tokio::main]
async fn main_discord() {
    let token = avrio_config::config().discord_token;
    if token != "DISCORD_TOKEN" {
        info!("Creating discord client");
        let mut client = Client::builder(&token)
            .event_handler(Handler)
            .await
            .expect("Err creating client");

        if let Err(why) = client.start().await {
            error!("Client error: {:?}", why);
        }
    }
}

pub fn safe_exit() {
    // TODO: save mempool to disk + send kill to all threads.

    info!("Goodbye!");
    avrio_p2p::core::close_all();
    avrio_database::close_flush_stream();
    std::process::exit(0);
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
                .level_for("avrio_blockchain", log::LevelFilter::Error)
                .level_for("avrio_database", log::LevelFilter::Error)
                .level_for("avrio_config", log::LevelFilter::Error)
                .level_for("seednode", log::LevelFilter::Error)
                .level_for("avrio_core", log::LevelFilter::Error)
                .level_for("avrio_crypto", log::LevelFilter::Error)
                .level_for("avrio_blockchain", log::LevelFilter::Error)
        }
        1 => base_config
            .level(log::LevelFilter::Warn)
            .level(log::LevelFilter::Error)
            .level_for("avrio_blockchain", log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Warn)
            .level_for("avrio_config", log::LevelFilter::Warn)
            .level_for("seednode", log::LevelFilter::Warn)
            .level_for("avrio_core", log::LevelFilter::Warn)
            .level_for("avrio_crypto", log::LevelFilter::Warn)
            .level_for("avrio_blockchain", log::LevelFilter::Warn),
        2 => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_blockchain", log::LevelFilter::Info)
            .level_for("avrio_database", log::LevelFilter::Info)
            .level_for("avrio_config", log::LevelFilter::Info)
            .level_for("seednode", log::LevelFilter::Info)
            .level_for("avrio_core", log::LevelFilter::Info)
            .level_for("avrio_crypto", log::LevelFilter::Info)
            .level_for("avrio_blockchain", log::LevelFilter::Info),
        3 => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_blockchain", log::LevelFilter::Debug)
            .level_for("avrio_database", log::LevelFilter::Debug)
            .level_for("avrio_config", log::LevelFilter::Debug)
            .level_for("seednode", log::LevelFilter::Debug)
            .level_for("avrio_core", log::LevelFilter::Debug)
            .level_for("avrio_crypto", log::LevelFilter::Debug)
            .level_for("avrio_blockchain", log::LevelFilter::Debug),
        _ => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_blockchain", log::LevelFilter::Trace)
            .level_for("avrio_database", log::LevelFilter::Trace)
            .level_for("avrio_config", log::LevelFilter::Trace)
            .level_for("seednode", log::LevelFilter::Trace)
            .level_for("avrio_core", log::LevelFilter::Trace)
            .level_for("avrio_crypto", log::LevelFilter::Trace)
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
                    "[{}][{}][{}] {}",
                    chrono::Local::now().format("%H:%M"),
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
fn generate_chains() -> Result<(), Box<dyn std::error::Error>> {
    for block in genesis_blocks() {
        info!(
            "addr: {}",
            Wallet::new(block.header.chain_key.clone(), "".to_owned()).address()
        );
        if getBlockFromRaw(block.hash.clone()) != block {
            saveBlock(block.clone())?;
            enact_block(block)?;
        }
    }
    return Ok(());
}

fn database_present() -> bool {
    let get_res = get_data(
        config().db_path + &"/chains/masterchainindex".to_owned(),
        &"digest".to_owned(),
    );
    if get_res == "-1".to_owned() {
        return false;
    } else if get_res == "0".to_string() {
        return false;
    } else {
        return true;
    }
}

fn create_file_structure() -> std::result::Result<(), Box<dyn std::error::Error>> {
    info!("Creating datadir folder structure");
    create_dir_all(config().db_path + &"/blocks".to_string())?;
    create_dir_all(config().db_path + &"/chains".to_string())?;
    create_dir_all(config().db_path + &"/wallets".to_string())?;
    create_dir_all(config().db_path + &"/accounts".to_string())?;
    create_dir_all(config().db_path + &"/usernames".to_string())?;
    info!("Created datadir folder structure");
    return Ok(());
}

fn connect(seednodes: Vec<SocketAddr>, connected_peers: &mut Vec<TcpStream>) -> u8 {
    let mut conn_count: u8 = 0;
    for peer in seednodes {
        let error = new_connection(&peer.to_string());
        match error {
            Ok(_) => {
                info!("Connected to {:?}::{:?}", peer, 11523);
                conn_count += 1;
                connected_peers.push(error.unwrap());
            }
            _ => warn!(
                "Failed to connect to {:?}:: {:?}, returned error {:?}",
                peer, 11523, error
            ),
        };
    }
    return conn_count;
}

fn save_wallet(keypair: &Vec<String>) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut conf = config();
    let path = conf.db_path.clone() + &"/wallets/".to_owned() + &keypair[0];
    if conf.wallet_password == Config::default().wallet_password {
        warn!("Your wallet password is set to default, please change this password and run avrio daemon with --change-password-from-default <newpassword> (TODO LEO)");
    }
    let mut padded = conf.wallet_password.as_bytes().to_vec();
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
    return Ok(());
}

fn generate_keypair(out: &mut Vec<String>) {
    let wallet: Wallet = Wallet::gen();
    out.push(wallet.public_key.clone());
    out.push(wallet.private_key);
    let mut conf = config();
    conf.chain_key = wallet.public_key;
    let _ = conf.save();
}

fn open_wallet(key: String, address: bool) -> Wallet {
    let wall: Wallet;
    if address == true {
        wall = Wallet::from_address(key);
    } else {
        wall = Wallet::new(key, "".to_owned());
    }
    // TODO: use unique nonce
    // can we just hash the public key with some local data on the computer (maybe mac address)? Or is that insufficent (TODO: find out)
    let mut padded = config().wallet_password.as_bytes().to_vec();
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
        config().db_path + &"/wallets/".to_owned() + &wall.public_key,
        &"privkey".to_owned(),
    ))
    .expect("failed to parse hex");
    let privkey = String::from_utf8(
        aead.decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!"),
    )
    .expect("failed to parse utf8 (i1)");
    return Wallet::from_private_key(privkey);
}

fn main() {
    ctrlc::set_handler(move || {
        safe_exit();
    })
    .expect("Error setting Ctrl-C handler");
    let matches = App::new("Avrio Daemon")
        .version("Testnet Pre-alpha 0.0.1")
        .about("This is the offical daemon for the avrio network.")
        .author("Leo Cornelius")
        .arg(
            Arg::with_name("conf")
                .short("c")
                .long("conf-file")
                .value_name("FILE")
                .help("(DOESNT WORK YET!!) Sets a custom conf file, if not set will use node.conf")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("loglev")
                .long("log-level")
                .short("v")
                .value_name("loglev-val")
                .takes_value(true)
                .help(
                    "Sets the level of verbosity: 0: Error, 1: Warn, 2: Info, 3: Debug, 4: Trace",
                ),
        )
        .get_matches();
    match matches.value_of("loglev").unwrap_or(&"2") {
        "0" => setup_logging(0).unwrap(),
        "1" => setup_logging(1).unwrap(),
        "2" => setup_logging(2).unwrap(),
        "3" => setup_logging(3).unwrap(),
        "4" => setup_logging(4).unwrap(),
        _ => {
            println!("Unknown log-level: {} ", matches.occurrences_of("loglev"));
            println!("Supported levels: 0: Error, 1: Warn, 2: Info, 3: Debug, 4: Trace");
            std::process::exit(1);
        }
    }
    let art = " 
     ▄▄▄▄▄▄▄▄▄▄▄  ▄               ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
    ▐░░░░░░░░░░░▌▐░▌             ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
    ▐░█▀▀▀▀▀▀▀█░▌ ▐░▌           ▐░▌ ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌
    ▐░▌       ▐░▌  ▐░▌         ▐░▌  ▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌
    ▐░█▄▄▄▄▄▄▄█░▌   ▐░▌       ▐░▌   ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌       ▐░▌
    ▐░░░░░░░░░░░▌    ▐░▌     ▐░▌    ▐░░░░░░░░░░░▌     ▐░▌     ▐░▌       ▐░▌
    ▐░█▀▀▀▀▀▀▀█░▌     ▐░▌   ▐░▌     ▐░█▀▀▀▀█░█▀▀      ▐░▌     ▐░▌       ▐░▌
    ▐░▌       ▐░▌      ▐░▌ ▐░▌      ▐░▌     ▐░▌       ▐░▌     ▐░▌       ▐░▌
    ▐░▌       ▐░▌       ▐░▐░▌       ▐░▌      ▐░▌  ▄▄▄▄█░█▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌
    ▐░▌       ▐░▌        ▐░▌        ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
     ▀         ▀          ▀          ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 
                                                                           ";
    let mut chain_key: Vec<String> = vec![]; // 0 = pubkey, 1 = privkey
    println!("{}", art);
    info!("Avrio Seednode Daemon Testnet v1.0.0 (pre-alpha)");
    let conf = config();
    conf.create().unwrap();
    if !database_present() {
        create_file_structure().unwrap();
    }
    avrio_database::init_cache(1000000000).expect("Failed to init db cache");
    info!("Launching API server");
    let _api_server_handle = thread::spawn(|| {
        start_server();
    });
    let synced: bool;
    info!("Avrio Seednode Daemon successfully launched");
    if config().chain_key == "".to_owned() {
        generate_chains().unwrap();
        let chainsdigest: String =
            avrio_blockchain::form_state_digest(config().db_path + &"/chaindigest".to_owned())
                .unwrap_or_default();
        info!("Chain digest: {}", chainsdigest);
    }
    if config().discord_token != "DISCORD_TOKEN" {
        info!("Launching discord thread");
        let _discord_thread = thread::spawn(|| {
            main_discord();
        });
    }
    info!(
        "Launching P2p server on {}:{}",
        config().ip_host,
        config().p2p_port
    );
    let _p2p_handler = thread::spawn(|| {
        if let Err(_) = rec_server(&format!("{}:{}", config().ip_host, config().p2p_port)) {
            error!(
                "Error launching P2p server on {}:{} (Fatal)",
                config().ip_host,
                config().p2p_port
            );
            process::exit(1);
        }
    });
    let pl = get_peerlist();
    let mut connections: Vec<TcpStream> = vec![];
    connect(get_peerlist().unwrap_or_default(), &mut connections);
    let connections_mut: Vec<&mut TcpStream> = connections.iter_mut().collect();
    let mut new_peers: Vec<SocketAddr> = vec![];
    for connection in &connections_mut {
        for peer in avrio_p2p::helper::get_peerlist_from_peer(&mut connection.try_clone().unwrap())
            .unwrap_or_default()
        {
            new_peers.push(peer);
        }
    }
    let set: std::collections::HashSet<_> = new_peers.drain(..).collect(); // dedup
    new_peers.extend(set.into_iter());
    let mut pl_u = get_peerlist().unwrap_or_default();
    for peer in new_peers {
        pl_u.push(peer);
    }
    let set: std::collections::HashSet<_> = pl_u.drain(..).collect(); // dedup
    pl_u.extend(set.into_iter());
    for peer in pl_u {
        let _ = new_connection(&peer.to_string());
    }
    let syncneed = sync_needed();

    match pl {
        // do we need to sync
        Ok(_) => {
            match syncneed {
                // do we need to sync
                Ok(val) => match val {
                    true => {
                        info!("Starting sync (this will take some time)");
                        if let Ok(_) = sync() {
                            info!("Successfully synced with the network!");
                            synced = true;
                        } else {
                            error!("Syncing failed");
                            process::exit(1);
                        }
                    }
                    false => {
                        info!("No sync needed");
                        synced = true;
                    }
                },
                Err(e) => {
                    error!("Failed to ask peers if we need to sync, gave error: {}", e);
                    process::exit(1);
                }
            }
        }
        Err(_) => {
            info!("Failed to get peerlist. Presuming first start up based on this.");
            synced = true;
        }
    }
    if synced == true {
        info!("Your avrio daemon is now synced and up to date with the network!");
    } else {
        return ();
    }
    let wall: Wallet;
    if config().chain_key == "".to_owned() {
        info!("Generating a chain for self");
        generate_keypair(&mut chain_key);
        if chain_key[0] == "0".to_owned() {
            error!("failed to create keypair (Fatal)");
            process::exit(1);
        } else {
            info!(
                "Succsessfully created keypair with address: {}",
                Wallet::from_private_key(chain_key[1].clone()).address()
            );
            if let Err(e) = save_wallet(&chain_key) {
                error!(
                    "Failed to save wallet: {}, gave error: {}",
                    Wallet::from_private_key(chain_key[1].clone()).address(),
                    e
                );
                process::exit(1);
            }
        }
        // create the wallet sturct with our priv key
        wall = Wallet::from_private_key(chain_key[1].clone());

        let mut genesis_block = getGenesisBlock(&chain_key[0]);
        if let Err(e) = genesis_block {
            if e == genesisBlockErrors::BlockNotFound {
                info!(
                    "No genesis block found for chain: {}, generating",
                    Wallet::from_private_key(chain_key[1].clone()).address()
                );
                genesis_block = generateGenesisBlock(chain_key[0].clone(), chain_key[1].clone());
            } else {
                error!(
                "Database error occoured when trying to get genesisblock for chain: {}. (Fatal)",
                Wallet::from_private_key(chain_key[1].clone()).address()
            );
                process::exit(1);
            }
        }
        let genesis_block = genesis_block.unwrap();
        let genesis_block_clone = genesis_block.clone();
        match check_block(genesis_block) {
            Err(error) => {
                error!(
                "Failed to validate generated genesis block. Gave error: {:?}, block dump: {:?}. (Fatal)",
                error, genesis_block_clone
            );
                process::exit(1);
            }
            Ok(_) => info!(
                "Successfully generated genesis block with hash {}",
                genesis_block_clone.hash
            ),
        }
        let e_code = saveBlock(genesis_block_clone.clone());
        match e_code {
            Ok(_) => {
                info!("Sucessfully saved genesis block!");
                drop(e_code);
            }
            Err(e) => {
                error!(
                    "Failed to save genesis block gave error code: {:?} (fatal)!",
                    e
                );
                process::exit(1);
            }
        };
        info!(
            "Enacting genesis block (height={})",
            genesis_block_clone.header.height
        );
        let _ = enact_send(genesis_block_clone.clone()).unwrap();
        let _ = prop_block(&genesis_block_clone).unwrap();
        info!("Sent block to network; Generating rec blocks");
        let runtime = Runtime::new().unwrap();
        let _ = runtime.block_on(async {
            recieved_block(genesis_block_clone.clone()).await;
        });

        // recieved_block(genesis_block_clone.clone()).poll();

        // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that

        let rec_blk = genesis_block_clone
            .form_receive_block(Some(genesis_block_clone.header.chain_key.to_owned()))
            .unwrap();
        let _ = check_block(rec_blk.clone()).unwrap();
        let _ = saveBlock(rec_blk.clone()).unwrap();
        let _ = prop_block(&rec_blk).unwrap();
        let _ = enact_block(rec_blk.clone()).unwrap();
        let _ = runtime.block_on(async {
            recieved_block(rec_blk.clone()).await;
        });
        info!("Propagated recieve block hash={}", rec_blk.hash);
    } else {
        info!("Using chain: {}", config().chain_key);
        wall = open_wallet(config().chain_key, false);
    }
    info!(
        "Transaction count for our chain: {}",
        avrio_database::get_data(
            config().db_path
                + &"/chains/".to_owned()
                + &wall.public_key
                + &"-chainindex".to_owned(),
            &"txncount".to_owned(),
        )
    );
    let try_get_acc = avrio_core::account::getAccount(&wall.public_key);
    if let Ok(ouracc) = try_get_acc {
        info!("Our balance: {}", ouracc.balance_ui().unwrap());
    } else {
        error!(
            "Failed to get account, wallet_public_key={}, error={}",
            wall.public_key,
            try_get_acc.unwrap_err()
        );
    }
    loop {
        // Now we loop until shutdown
        let _ = io::stdout().flush();
        let read: String = read!("{}\n");
        if read == "send_txn".to_owned() {
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
            let rec_wall;
            if avrio_crypto::valid_address(&addr) {
                rec_wall = Wallet::from_address(addr);
            } else {
                rec_wall = Wallet::new(
                    avrio_core::account::getByUsername(&addr)
                        .unwrap()
                        .public_key,
                    "".to_owned(),
                );
            }
            txn.receive_key = rec_wall.public_key;
            txn.nonce = avrio_database::get_data(
                config().db_path
                    + &"/chains/".to_owned()
                    + &txn.sender_key
                    + &"-chainindex".to_owned(),
                &"txncount".to_owned(),
            )
            .parse()
            .unwrap_or(0);
            txn.hash();
            let _ = txn.sign(&wall.private_key);
            let inv_db = open_database(
                config().db_path
                    + &"/chains/".to_string()
                    + &wall.public_key
                    + &"-chainindex".to_string(),
            )
            .unwrap();
            let mut highest_so_far: u64 = 0;

            for (key, _) in inv_db.iter() {
                if let Ok(height) = key.parse::<u64>() {
                    if height > highest_so_far {
                        highest_so_far = height
                    }
                }
            }
            let height: u64 = highest_so_far;
            let mut blk = Block {
                header: Header {
                    version_major: 0,
                    version_breaking: 0,
                    version_minor: 0,
                    chain_key: wall.public_key.clone(),
                    prev_hash: getBlock(&wall.public_key, height).hash,
                    height: height + 1,
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
                confimed: false,
                node_signatures: vec![],
            };
            blk.hash();
            let _ = blk.sign(&wall.private_key);
            let _ = check_block(blk.clone()).unwrap();
            let _ = saveBlock(blk.clone()).unwrap();
            let _ = enact_send(blk.clone()).unwrap();
            let _ = prop_block(&blk).unwrap();
            let runtime = Runtime::new().unwrap();
            let _ = runtime.block_on(async {
                recieved_block(blk.clone()).await;
            });
            // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that
            let proccessed_accs: Vec<String> = vec![];
            for txn in &blk.txns {
                if !proccessed_accs.contains(&txn.receive_key) {
                    let rec_blk = blk
                        .form_receive_block(Some(txn.receive_key.to_owned()))
                        .unwrap();
                    let _ = check_block(rec_blk.clone()).unwrap();
                    let _ = saveBlock(rec_blk.clone()).unwrap();
                    let _ = prop_block(&rec_blk).unwrap();
                    let _ = enact_block(rec_blk.clone()).unwrap();
                    let _ = runtime.block_on(async {
                        recieved_block(blk.clone()).await;
                    });
                }
            }
            // all done
            // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that
            // all done
            let ouracc = avrio_core::account::getAccount(&wall.public_key).unwrap();
            info!(
                "Transaction sent! Txn hash: {}, Block hash: {}. Our new balance: {} AIO",
                blk.txns[0].hash,
                blk.hash,
                ouracc.balance_ui().unwrap()
            );
        } else if read == "get_balance" {
            info!(
                "Your balance: {} AIO",
                avrio_core::account::getAccount(&wall.public_key)
                    .unwrap()
                    .balance_ui()
                    .unwrap_or_default()
            );
        } else if read == "get_address" {
            info!("Your wallet's addres is: {}", wall.address());
        } else if read == "exit" {
            safe_exit();
            process::exit(0);
        } else if read == "address_details" {
            info!("Enter the address of the account.");
            let addr: String = read!("{}\n");
            let acc =
                avrio_core::account::getAccount(&Wallet::from_address(addr.clone()).public_key)
                    .unwrap_or_default();
            info!("Account details for {}", addr);
            info!("____________________________");
            info!(
                "Balance: {} AIO, Locked: {} AIO",
                acc.balance_ui().unwrap_or_default(),
                acc.locked
            );
            info!(
                "Account level: {}, access_keys: {:?}",
                acc.level, acc.access_keys
            );
            info!("Username: {}, Publickey: {}", acc.username, acc.public_key);
            info!("____________________________");
        } else if read == "help" {
            info!("Commands:");
            info!("get_balance : Gets the balance of the currently loaded wallet");
            info!("address_details: Gets details about the account assosiated with an address");
            info!("get_address : Gets the address assosciated with this wallet");
            info!("send_txn : Sends a transaction");
            info!("get_account : Gets an account via their publickey");
            info!("send_txn_advanced : allows you to send a transaction with advanced options");
            info!("get_block : Gets a block for given hash");
            info!("get_transaction : Gets a transaction for a given hash");
            info!("exit : Safely shutsdown thr program. PLEASE use instead of ctrl + c");
            info!("help : shows this help");
        } else if read == "send_txn_advanced" {
            error!("This doesnt work get, try again soon!");
        } else if read == "get_block" {
            info!("Enter block hash:");
            let hash: String = read!("{}\n");
            let blk: Block = getBlockFromRaw(hash);
            if blk == Block::default() {
                error!("Couldnt find a block with that hash");
            } else {
                info!("{:#?}", blk);
            }
        } else if read == "get_transaction" {
            info!("Enter the transaction hash:");
            let hash: String = read!("{}\n");
            let block_txn_is_in = get_data(config().db_path + &"/transactions".to_owned(), &hash);
            if block_txn_is_in == "-1".to_owned() {
                error!("Can not find that txn in db");
            } else {
                let blk: Block = getBlockFromRaw(block_txn_is_in);
                if blk == Block::default() {
                    error!("Couldnt find a block with that transaction in");
                } else {
                    for txn in blk.txns {
                        if txn.hash == hash {
                            info!("Transaction with hash: {}", txn.hash);
                            info!("____________________________");
                            info!(
                                "To: {}, From: {}",
                                Wallet::new(txn.receive_key.clone(), "".to_owned()).address(),
                                Wallet::new(txn.sender_key.clone(), "".to_owned()).address()
                            );
                            info!("Amount: {} AIO", avrio_core::account::to_dec(txn.amount));
                            info!("Timestamp: {}, Nonce: {}", txn.timestamp, txn.nonce);
                            info!(
                                "Block height: {}, Block Hash: {}",
                                blk.header.height, blk.hash
                            );
                            info!("From chain: {}", blk.header.chain_key);
                            info!("Txn type: {}", txn.typeTransaction());
                            info!(
                                "Used gas: {}, Gas price: {}, Fee: {}",
                                txn.gas,
                                txn.gas_price,
                                txn.gas * txn.gas_price
                            );
                            info!("Extra (appened data): {}", txn.extra);
                            info!("____________________________");
                        }
                    }
                }
            }
        } else if read == "get_account" {
            info!("Enter the public key of the account:");
            let addr: String = read!("{}\n");
            let wall = Wallet::new(addr.clone(), "".to_owned());
            let acc = avrio_core::account::getAccount(&wall.public_key).unwrap_or_default();
            info!("Account details for {}", wall.address());
            info!("____________________________");
            info!(
                "Balance: {} AIO, Locked: {} AIO",
                acc.balance_ui().unwrap_or_default(),
                acc.locked
            );
            info!(
                "Account level: {}, access_keys: {:?}",
                acc.level, acc.access_keys
            );
            info!("Username: {}, Publickey: {}", acc.username, acc.public_key);
            info!("____________________________");
        } else if read == "generate" {
            info!("Enter the number of blocks you would like to generate (max 15):");
            let amount: u64 = read!("{}\n");
            if amount == 0 {
                error!("amount must be greater than 0.");
            } else if amount > 15 {
                error!("You can't send more than 15 blocks per go.");
            } else if amount > 5 {
                warn!("this will be very slow, especialy on HDD. Continue? (Y/N)");
                let cont: String = read!();
                if cont.to_uppercase() != "Y".to_owned() {
                } else {
                    info!("Enter the number of transactions per block (max 100):");
                    let txnamount: u64 = read!("{}\n");
                    if txnamount > 100 || txnamount == 1 {
                        error!("Tx amount must be beetween (or equal to) 1 and 100");
                    } else {
                        info!(
                            "Generating {} blocks with {} txns in each",
                            amount, txnamount
                        );
                        let mut i_block: u64 = 0;
                        while i_block < amount {
                            let mut i: u64 = 0;
                            let mut txns: Vec<Transaction> = vec![];
                            let nonce_i = avrio_database::get_data(
                                config().db_path
                                    + &"/chains/".to_owned()
                                    + &wall.public_key.clone()
                                    + &"-chainindex".to_owned(),
                                &"txncount".to_owned(),
                            );
                            while i < txnamount {
                                let mut txn = Transaction {
                                    hash: String::from(""),
                                    amount: 100,
                                    extra: String::from(""),
                                    flag: 'n',
                                    sender_key: wall.public_key.clone(),
                                    receive_key: wall.public_key.clone(),
                                    access_key: String::from(""),
                                    gas_price: 100,
                                    max_gas: 100,
                                    gas: 20,
                                    nonce: nonce_i.parse().unwrap_or_default(),
                                    unlock_time: 0,
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .expect("Time went backwards")
                                        .as_millis()
                                        as u64,
                                    signature: String::from(""),
                                };
                                txn.hash();
                                txn.sign(&wall.private_key).unwrap();
                                txns.push(txn);
                                i += 1;
                                info!("txn {}/{}", i, txnamount);
                            }
                            let inv_db = open_database(
                                config().db_path
                                    + &"/chains/".to_string()
                                    + &wall.public_key
                                    + &"-chainindex".to_string(),
                            )
                            .unwrap();
                            let mut highest_so_far: u64 = 0;
                            for (key, _) in inv_db.iter() {
                                if let Ok(height) = key.parse::<u64>() {
                                    if height > highest_so_far {
                                        highest_so_far = height
                                    }
                                }
                            }
                            let height: u64 = highest_so_far;
                            let mut blk = Block {
                                header: Header {
                                    version_major: 0,
                                    version_breaking: 0,
                                    version_minor: 0,
                                    chain_key: wall.public_key.clone(),
                                    prev_hash: getBlock(&wall.public_key, height).hash,
                                    height: height + 1,
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .expect("Time went backwards")
                                        .as_millis()
                                        as u64,
                                    network: vec![
                                        97, 118, 114, 105, 111, 32, 110, 111, 111, 100, 108, 101,
                                    ],
                                },
                                block_type: BlockType::Send,
                                send_block: None,
                                txns,
                                hash: "".to_owned(),
                                signature: "".to_owned(),
                                confimed: false,
                                node_signatures: vec![],
                            };
                            blk.hash();
                            let _ = blk.sign(&wall.private_key);
                            let _ = check_block(blk.clone()).unwrap();
                            let _ = saveBlock(blk.clone()).unwrap();
                            let _ = enact_send(blk.clone()).unwrap();
                            let _ = prop_block(&blk).unwrap();
                            let runtime = Runtime::new().unwrap();
                            let _ = runtime.block_on(async {
                                recieved_block(blk.clone()).await;
                            });
                            // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that
                            let proccessed_accs: Vec<String> = vec![];
                            for txn in &blk.txns {
                                if !proccessed_accs.contains(&txn.receive_key) {
                                    let rec_blk = blk
                                        .form_receive_block(Some(txn.receive_key.to_owned()))
                                        .unwrap();
                                    let _ = check_block(rec_blk.clone()).unwrap();
                                    let _ = saveBlock(rec_blk.clone()).unwrap();
                                    let _ = prop_block(&rec_blk).unwrap();
                                    let _ = enact_block(rec_blk.clone()).unwrap();
                                    let runtime = Runtime::new().unwrap();
                                    let _ = runtime.block_on(async {
                                        recieved_block(rec_blk.clone()).await;
                                    });
                                }
                            }
                            // all done
                            i_block += 1;
                        }
                        let ouracc = avrio_core::account::getAccount(&wall.public_key).unwrap();
                        info!(
                            "Blocks sent! Our new balance: {} AIO",
                            ouracc.balance_ui().unwrap()
                        );
                    }
                }
            }
            continue;
        } else if read == "claim".to_owned() {
            info!("Please enter the amount");
            let amount: f64 = read!("{}\n");
            let mut txn = Transaction {
                hash: String::from(""),
                amount: to_atomc(amount),
                extra: String::from(""),
                flag: 'c',
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
            txn.receive_key = wall.public_key.clone();
            txn.nonce = avrio_database::get_data(
                config().db_path
                    + &"/chains/".to_owned()
                    + &txn.sender_key
                    + &"-chainindex".to_owned(),
                &"txncount".to_owned(),
            )
            .parse()
            .unwrap_or(0);
            txn.hash();
            let _ = txn.sign(&wall.private_key);
            let inv_db = open_database(
                config().db_path
                    + &"/chains/".to_string()
                    + &wall.public_key
                    + &"-chainindex".to_string(),
            )
            .unwrap();
            let mut highest_so_far: u64 = 0;

            for (key, _) in inv_db.iter() {
                if let Ok(height) = key.parse::<u64>() {
                    if height > highest_so_far {
                        highest_so_far = height
                    }
                }
            }
            let height: u64 = highest_so_far;
            let mut blk = Block {
                header: Header {
                    version_major: 0,
                    version_breaking: 0,
                    version_minor: 0,
                    chain_key: wall.public_key.clone(),
                    prev_hash: getBlock(&wall.public_key, height).hash,
                    height: height + 1,
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
                confimed: false,
                node_signatures: vec![],
            };
            blk.hash();
            let _ = blk.sign(&wall.private_key);
            let _ = check_block(blk.clone()).unwrap();
            let _ = saveBlock(blk.clone()).unwrap();
            let _ = enact_send(blk.clone()).unwrap();
            let _ = prop_block(&blk).unwrap();
            let runtime = Runtime::new().unwrap();
            let _ = runtime.block_on(async {
                recieved_block(blk.clone()).await;
            });
            // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that
            let proccessed_accs: Vec<String> = vec![];
            for txn in &blk.txns {
                if !proccessed_accs.contains(&txn.receive_key) {
                    let rec_blk = blk
                        .form_receive_block(Some(txn.receive_key.to_owned()))
                        .unwrap();
                    let _ = check_block(rec_blk.clone()).unwrap();
                    let _ = saveBlock(rec_blk.clone()).unwrap();
                    let _ = prop_block(&rec_blk).unwrap();
                    let _ = enact_block(rec_blk.clone()).unwrap();
                    let _ = runtime.block_on(async {
                        recieved_block(rec_blk.clone()).await;
                    });
                }
            }
            // all done
            let ouracc = avrio_core::account::getAccount(&wall.public_key).unwrap();
            info!(
                "Transaction sent! Txn hash: {}, Our new balance: {} AIO",
                blk.txns[0].hash,
                ouracc.balance_ui().unwrap()
            );
        } else if read == "register_username".to_owned() {
            info!("Please enter the username you would like to register:");
            let username: String = read!("{}\n");
            if let Ok(_) = avrio_core::account::getByUsername(&username) {
                error!("That username is already registered, please try another");
            } else {
                let acc = avrio_core::account::getAccount(&wall.public_key).unwrap_or_default();
                if acc == Default::default() {
                    error!("Failed to get your account");
                } else {
                    if acc.username != "".to_owned() {
                        error!("You already have a username");
                    } else if acc.balance_ui().unwrap_or_default() < 0.50 {
                        error!("You need at least 0.50 AIO to register a username (tip, use the claim command)");
                    } else {
                        let mut txn = Transaction {
                            hash: String::from(""),
                            amount: to_atomc(0.50),
                            extra: username,
                            flag: 'u',
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
                        txn.receive_key = wall.public_key.clone();
                        txn.nonce = avrio_database::get_data(
                            config().db_path
                                + &"/chains/".to_owned()
                                + &txn.sender_key
                                + &"-chainindex".to_owned(),
                            &"txncount".to_owned(),
                        )
                        .parse()
                        .unwrap_or(0);
                        txn.hash();
                        let _ = txn.sign(&wall.private_key);
                        let inv_db = open_database(
                            config().db_path
                                + &"/chains/".to_string()
                                + &wall.public_key
                                + &"-chainindex".to_string(),
                        )
                        .unwrap();
                        let mut highest_so_far: u64 = 0;
                        for (key, _) in inv_db.iter() {
                            if let Ok(height) = key.parse::<u64>() {
                                if height > highest_so_far {
                                    highest_so_far = height
                                }
                            }
                        }
                        let height: u64 = highest_so_far;
                        let mut blk = Block {
                            header: Header {
                                version_major: 0,
                                version_breaking: 0,
                                version_minor: 0,
                                chain_key: wall.public_key.clone(),
                                prev_hash: getBlock(&wall.public_key, height).hash,
                                height: height + 1,
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Time went backwards")
                                    .as_millis() as u64,
                                network: vec![
                                    97, 118, 114, 105, 111, 32, 110, 111, 111, 100, 108, 101,
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
                        let _ = check_block(blk.clone()).unwrap();
                        let _ = saveBlock(blk.clone()).unwrap();
                        let _ = enact_send(blk.clone()).unwrap();
                        let _ = prop_block(&blk).unwrap();
                        let runtime = Runtime::new().unwrap();
                        let _ = runtime.block_on(async {
                            recieved_block(blk.clone()).await;
                        });
                        // now for each txn to a unique reciver form the rec block of the block we just formed and prob + enact that
                        let proccessed_accs: Vec<String> = vec![];
                        for txn in &blk.txns {
                            if !proccessed_accs.contains(&txn.receive_key) {
                                let rec_blk = blk
                                    .form_receive_block(Some(txn.receive_key.to_owned()))
                                    .unwrap();
                                let _ = check_block(rec_blk.clone()).unwrap();
                                let _ = saveBlock(rec_blk.clone()).unwrap();
                                let _ = prop_block(&rec_blk).unwrap();
                                let _ = enact_block(rec_blk.clone()).unwrap();
                                let runtime = Runtime::new().unwrap();
                                let _ = runtime.block_on(async {
                                    recieved_block(rec_blk.clone()).await;
                                });
                                let _ = runtime.block_on(async {
                                    username_registered(
                                        rec_blk,
                                        avrio_core::account::getAccount(&wall.public_key)
                                            .unwrap_or_default(),
                                    )
                                    .await;
                                });
                            }
                        }
                        // all done;
                        let ouracc = avrio_core::account::getAccount(&wall.public_key).unwrap();
                        info!(
                            "Transaction sent! Txn hash: {}, Our new balance: {} AIO",
                            blk.txns[0].hash,
                            ouracc.balance_ui().unwrap()
                        );
                    }
                }
            }
        } else {
            info!("Unknown command: {}", read);
        }
    }
}
