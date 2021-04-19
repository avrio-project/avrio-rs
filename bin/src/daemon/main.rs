use std::thread;
use std::{
    io::{self, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use avrio_core::{
    account::to_dec,
    certificate::generate_certificate,
    invite::{generate_invite, new_invite},
    states::form_state_digest,
    transaction::Transaction,
    validate::Verifiable,
};
use avrio_rpc::*;
extern crate clap;
use clap::{App, Arg};

use std::fs::create_dir_all;
use std::process;

pub extern crate avrio_config;
use avrio_config::config;
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;
extern crate avrio_core;

use avrio_p2p::{
    core::new_connection,
    core::rec_server,
    helper::{prop_block, sync_in_order, sync_needed},
};

use avrio_core::{
    block::{genesis::genesis_blocks, *},
    mempool::Mempool,
};

extern crate avrio_database;
use avrio_database::{get_data, get_peerlist};
#[macro_use]
extern crate log;

extern crate hex;

use avrio_api::start_server;

extern crate avrio_crypto;
use avrio_crypto::Wallet;
use fern::colors::{Color, ColoredLevelConfig};

use lazy_static::lazy_static;
use text_io::read;

lazy_static! {
    static ref MEMPOOL: Mutex<Option<Mempool>> = Mutex::new(None);
}
pub fn safe_exit() {
    // TODO: save mempool to disk + send kill to all threads.

    info!("Goodbye!");
    let _ = avrio_p2p::core::close_all();
    avrio_database::close_flush_stream();
    (*(MEMPOOL.lock().unwrap()))
        .as_ref()
        .unwrap()
        .shutdown()
        .unwrap();
    *(MEMPOOL.lock().unwrap()) = None;
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
                .level_for("avrio_database", log::LevelFilter::Error)
                .level_for("avrio_config", log::LevelFilter::Error)
                .level_for("avrio_daemon", log::LevelFilter::Error)
                .level_for("avrio_core", log::LevelFilter::Error)
                .level_for("avrio_crypto", log::LevelFilter::Error)
                .level_for("avrio_rpc", log::LevelFilter::Error)
                .level_for("avrio_api", log::LevelFilter::Error)
                .level_for("avrio_p2p", log::LevelFilter::Error)
                .level_for("avrio_node", log::LevelFilter::Error)
        }
        1 => base_config
            .level(log::LevelFilter::Warn)
            .level(log::LevelFilter::Error)
            .level_for("avrio_database", log::LevelFilter::Warn)
            .level_for("avrio_config", log::LevelFilter::Warn)
            .level_for("seednode", log::LevelFilter::Warn)
            .level_for("avrio_core", log::LevelFilter::Warn)
            .level_for("avrio_crypto", log::LevelFilter::Warn)
            .level_for("avrio_daemon", log::LevelFilter::Warn)
            .level_for("avrio_p2p", log::LevelFilter::Warn)
            .level_for("avrio_rpc", log::LevelFilter::Warn)
            .level_for("avrio_api", log::LevelFilter::Warn)
            .level_for("avrio_node", log::LevelFilter::Warn),
        2 => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Info)
            .level_for("avrio_config", log::LevelFilter::Info)
            .level_for("seednode", log::LevelFilter::Info)
            .level_for("avrio_core", log::LevelFilter::Info)
            .level_for("avrio_crypto", log::LevelFilter::Info)
            .level_for("avrio_p2p", log::LevelFilter::Info)
            .level_for("avrio_daemon", log::LevelFilter::Info)
            .level_for("avrio_rpc", log::LevelFilter::Info)
            .level_for("avrio_api", log::LevelFilter::Info)
            .level_for("avrio_node", log::LevelFilter::Info),
        3 => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Debug)
            .level_for("avrio_config", log::LevelFilter::Debug)
            .level_for("seednode", log::LevelFilter::Debug)
            .level_for("avrio_core", log::LevelFilter::Debug)
            .level_for("avrio_crypto", log::LevelFilter::Debug)
            .level_for("avrio_p2p", log::LevelFilter::Debug)
            .level_for("avrio_daemon", log::LevelFilter::Debug)
            .level_for("avrio_api", log::LevelFilter::Debug)
            .level_for("avrio_node", log::LevelFilter::Debug),
        _ => base_config
            .level(log::LevelFilter::Warn)
            .level_for("avrio_database", log::LevelFilter::Trace)
            .level_for("avrio_config", log::LevelFilter::Trace)
            .level_for("seednode", log::LevelFilter::Trace)
            .level_for("avrio_core", log::LevelFilter::Trace)
            .level_for("avrio_daemon", log::LevelFilter::Trace)
            .level_for("avrio_p2p", log::LevelFilter::Trace)
            .level_for("avrio_crypto", log::LevelFilter::Trace)
            .level_for("avrio_rpc", log::LevelFilter::Trace)
            .level_for("avrio_api", log::LevelFilter::Trace)
            .level_for("avrio_node", log::LevelFilter::Trace),
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
        .chain(fern::log_file("avrio-daemon.log")?);

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
fn generate_chains() -> Result<(), Box<dyn std::error::Error>> {
    for block in genesis_blocks() {
        info!(
            "addr: {}",
            Wallet::new(block.header.chain_key.clone(), "".to_owned()).address()
        );
        if get_block_from_raw(block.hash.clone()) != block {
            save_block(block.clone())?;
            block.enact()?;
        }
    }
    // Create the seed invite
    // TODO: change this to a block on the 0 chain
    new_invite("FZ2YbpGw1ZjRW2dkwMRfy7N98iZCkcfezy5BxCGWRPgZ")?;
    // invite priv key:
    // GD8M1Qm17WXoukx8QqqfvYRJDoxmjf1jSXFXyVYHFeQtCX67cpw6otCpeporyLaNmLKrKAj8nFSNfszJYyuTL1UFt6SFeodz3QJ8iDkvwBPM4SMMGkV3
    Ok(())
}

fn database_present() -> bool {
    let get_res = get_data(
        config().db_path + &"/chains/masterchainindex".to_owned(),
        &"digest".to_owned(),
    );
    !(get_res == *"-1" || get_res == *"0")
}

fn create_file_structure() -> std::result::Result<(), Box<dyn std::error::Error>> {
    info!("Creating datadir folder structure");
    create_dir_all(config().db_path + &"/blocks".to_string())?;
    create_dir_all(config().db_path + &"/chains".to_string())?;
    create_dir_all(config().db_path + &"/wallets".to_string())?;
    create_dir_all(config().db_path + &"/accounts".to_string())?;
    create_dir_all(config().db_path + &"/usernames".to_string())?;
    info!("Created datadir folder structure");
    Ok(())
}

fn connect(seednodes: Vec<SocketAddr>, connected_peers: &mut Vec<TcpStream>) -> u8 {
    let mut conn_count: u8 = 0;
    for peer in seednodes {
        debug!("Connecting to: {}", peer);
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
    conn_count
}

fn main() {
    ctrlc::set_handler(move || {
        safe_exit();
    })
    .expect("Error setting Ctrl-C handler");
    let matches = App::new("Avrio Daemon")
        .version("Testnet alpha v0.1.0")
        .about("This is the offical daemon for the avrio network.")
        .author("Leo Cornelius")
        .subcommand(App::new("seednode").about("Runs the node as a seednode"))
        .arg(
            Arg::with_name("conf")
                .short("c")
                .long("conf-file")
                .value_name("FILE")
                .help("(DOESNT WORK YET!!) Sets a custom conf file, if not set will use node.conf")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("no-sync")
                .help("Don't try and sync the node")
                .long("--no-sync")
                .takes_value(false),
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
    let seednode: bool = matches.is_present("seednode");
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
    println!("{}", art);
    info!("Avrio Daemon Testnet v0.1.0 (alpha)");
    warn!("Warning, this software is not stable");
    if seednode {
        warn!("Running in seednode mode, if you don't know what you are doing this is a mistake");
    }
    let conf = config();
    conf.create().unwrap();
    if !database_present() {
        create_file_structure().unwrap();
    }
    avrio_database::init_cache(1000000000).expect("Failed to init db cache"); // 1 gb db cache // TODO: Move this number (cache size) to config
    info!("Launching API server");
    let _api_server_handle = thread::spawn(|| {
        start_server();
    });
    let synced: bool;
    info!("Starting mempool");
    let mut mempool = Mempool::new(vec![]);
    if let Err(e) = mempool.init() {
        error!("Failed to initalise mempool, gave error={}", e);
        std::process::exit(0);
    }
    let _ = mempool.load_from_disk(&(config().db_path + "/mempool")); // is allowed to fail
    let _ = mempool.save_to_disk(&(config().db_path + "/mempool")); // create files
    *(MEMPOOL.lock().unwrap()) = Some(mempool);
    info!("Avrio Daemon successfully launched");
    let mut statedigest = get_data(config().db_path + &"/chaindigest".to_owned(), "master");
    if statedigest == *"-1" {
        generate_chains().unwrap();
        statedigest =
            form_state_digest(config().db_path + &"/chaindigest".to_owned()).unwrap_or_default();
        info!("State digest: {}", statedigest);
    } else {
        info!("State digest: {}", statedigest);
    }
    info!(
        "Launching P2p server on {}:{}",
        config().ip_host,
        config().p2p_port
    );
    let _p2p_handler = thread::spawn(|| {
        if rec_server(&format!("{}:{}", config().ip_host, config().p2p_port)).is_err() {
            error!(
                "Error launching P2p server on {}:{} (Fatal)",
                config().ip_host,
                config().p2p_port
            );
            process::exit(1);
        }
    });
    let mut pl = get_peerlist().unwrap_or_default();
    let mut seednodes: Vec<SocketAddr> = vec![];
    for seednode_addr in config().seednodes {
        if let Ok(addr) = seednode_addr.parse::<SocketAddr>() {
            seednodes.push(addr);
        } else {
            warn!("Invalid seednode addr in config: {}", seednode_addr);
        }
    }
    info!("P2P identity={}", config().identitiy);

    for node in seednodes {
        trace!("Adding seednode with addr={} to peerlist", node);
        pl.push(node);
    }
    let mut connections: Vec<TcpStream> = vec![];
    connect(pl, &mut connections);
    let connections_mut: Vec<&mut TcpStream> = connections.iter_mut().collect();
    let mut new_peers: Vec<SocketAddr> = vec![];
    for connection in &connections_mut {
        for peer in avrio_p2p::helper::get_peerlist_from_peer(&connection.peer_addr().unwrap())
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
    if !matches.is_present("no-sync") {
        let syncneed = sync_needed();

        match syncneed {
            // do we need to sync
            Ok(val) => match val {
                true => {
                    info!("Starting sync (this will take some time)");
                    if sync_in_order().is_ok() {
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

        if synced {
            info!("Your avrio daemon is now synced and up to date with the network!");
        } else {
            safe_exit();
            return;
        }
    }
    info!("Launching RPC server");
    let _ = std::thread::spawn(move || {
        launch(17785);
    });
    info!("Launched RPC server on port=17785");
    loop {
        // Now we loop until shutdown
        let _ = io::stdout().flush();
        let read: String = read!("{}\n");
        if read == "exit" {
            safe_exit();
            process::exit(0);
        } else if read == "address_details" {
            info!("Enter the address of the account.");
            let addr: String = read!("{}\n");
            let acc =
                avrio_core::account::get_account(&Wallet::from_address(addr.clone()).public_key)
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

            info!("address_details: Gets details about the account assosiated with an address");

            info!("get_account : Gets an account via their publickey");

            info!("get_block : Gets a block for given hash");
            info!("get_transaction : Gets a transaction for a given hash");
            info!("exit : Safely shutsdown thr program. PLEASE use instead of ctrl + c");
            info!("help : shows this help");
        } else if read == "get_block" {
            info!("Enter block hash:");
            let hash: String = read!("{}\n");
            let blk: Block = get_block_from_raw(hash);
            if blk == Block::default() {
                error!("Couldnt find a block with that hash");
            } else {
                info!("{:#?}", blk);
            }
        } else if read == "get_transaction" {
            info!("Enter the transaction hash:");
            let hash: String = read!("{}\n");
            let block_txn_is_in = get_data(config().db_path + &"/transactions".to_owned(), &hash);
            if block_txn_is_in == *"-1" {
                error!("Can not find that txn in db");
            } else {
                let blk: Block = get_block_from_raw(block_txn_is_in);
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
                            info!("Txn type: {}", txn.type_transaction());
                            info!(
                                "Used gas: {}, Gas price: {}, Fee: {}",
                                txn.gas(),
                                txn.gas_price,
                                txn.gas() * txn.gas_price
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
            let acc = avrio_core::account::get_account(&wall.public_key).unwrap_or_default();
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
        } else if read == *"register_fullnode" {
            info!("Enter lock commitment: (tip you get this from locking funds in the wallet!)");
            let commitment: String = read!();
            // the commitment should be a valid txn hash, check it
            let block_txn_is_in =
                get_data(config().db_path + &"/transactions".to_owned(), &commitment);
            let mut commitment_txn: Transaction = Transaction::default();
            if block_txn_is_in == *"-1" {
                error!("Can not find comitment");
            } else {
                let blk: Block = get_block_from_raw(block_txn_is_in);
                if blk == Block::default() {
                    error!("Couldnt find a block with that commitment in");
                } else {
                    for txn in blk.txns {
                        if txn.hash == commitment {
                            commitment_txn = txn;
                        }
                    }
                }
            }
            if commitment_txn == Transaction::default() {
                error!("Block did not contain commitment as expected");
            } else {
                if commitment_txn.flag != 'l' {
                    error!(
                        "Comitment transaction type wrong, expected flag=l, got={}",
                        commitment_txn.flag
                    );
                } else if commitment_txn.amount != config().fullnode_lock_amount {
                    error!("Commitment transaction has insufficent amount, expected={} AIO, got={} AIO", to_dec(config().fullnode_lock_amount), to_dec(commitment_txn.amount));
                } else {
                    debug!("Found valid comitment, proceeding");
                    info!("Please enter the private key of the wallet you wish to register as a fullnode:");
                    let private_key_string: String = read!();
                    let wallet = Wallet::from_private_key(private_key_string);
                    info!("Please enter the invite:");
                    let invite: String = read!();
                    info!(
                        "Registering as fullnode with publickey={}? (y/n)",
                        wallet.public_key
                    );
                    let confirm: String = read!();
                    if confirm.to_ascii_uppercase() == "N" {
                        error!("Aboring...");
                    } else if confirm.to_ascii_uppercase() == "Y" {
                        info!("Forming fullnode certificate...");
                        if let Ok(cert) = generate_certificate(
                            &wallet.public_key,
                            &wallet.private_key,
                            &commitment,
                            invite,
                        ) {
                            // form a transaction using the private key given before, add it to a block and send
                            let mut txn: Transaction = Transaction {
                                hash: String::from(""),
                                amount: 1,
                                extra: serde_json::to_string(&cert).unwrap(),
                                flag: 'f',
                                sender_key: wallet.public_key.clone(),
                                receive_key: wallet.public_key.clone(),
                                access_key: String::from(""),
                                unlock_time: 0,
                                gas_price: 20,
                                max_gas: u64::MAX,
                                nonce: get_data(
                                    config().db_path
                                        + &"/chains/".to_owned()
                                        + &wallet.public_key
                                        + &"-chainindex".to_owned(),
                                    &"txncount".to_owned(),
                                )
                                .parse()
                                .unwrap_or(0),
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("time went backwards ONO")
                                    .as_millis() as u64,
                            };
                            txn.hash();
                            let prev_block = get_block_from_raw(get_data(
                                config().db_path
                                    + &"/chains/".to_owned()
                                    + &wallet.public_key
                                    + &"-chainindex".to_owned(),
                                "topblockhash",
                            ));
                            let mut send_block = Block {
                                header: Header {
                                    version_major: 0,
                                    version_breaking: 1,
                                    version_minor: 0,
                                    chain_key: wallet.public_key.clone(),
                                    prev_hash: prev_block.hash.clone(),
                                    height: prev_block.header.height + 1,
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .expect("time went backwards ONO")
                                        .as_millis()
                                        as u64,
                                    network: prev_block.header.network,
                                },
                                block_type: BlockType::Send,
                                send_block: None,
                                txns: vec![txn],
                                hash: String::from(""),
                                signature: String::from(""),
                            };
                            send_block.hash();
                            if let Err(e) = send_block.sign(&wallet.private_key) {
                                error!(
                                    "Failed to sign send block {}, gave error={}",
                                    send_block.hash, e
                                );
                            } else {
                                match send_block.form_receive_block(Some(wallet.public_key.clone()))
                                {
                                    Ok(rec_block) => {
                                        info!("Created blocks {} and {} containing fullnode registration; broadcasting", send_block.hash, rec_block.hash);
                                        if let Err(e) = send_block.valid() {
                                            error!(
                                                "Created send block {} invalid, reason={}",
                                                send_block.hash, e
                                            );
                                        } else {
                                            if let Err(e) = rec_block.valid() {
                                                error!(
                                                    "Created rec block {} invalid, reason={}",
                                                    rec_block.hash, e
                                                );
                                            } else {
                                                if let Err(e) = send_block.save() {
                                                    error!(
                                                        "Failed to save send block {}, error={}",
                                                        send_block.hash, e
                                                    );
                                                } else {
                                                    if let Err(e) = rec_block.save() {
                                                        error!(
                                                            "Failed to save rec block {}, error={}",
                                                            rec_block.hash, e
                                                        );
                                                    } else {
                                                        debug!("Saved blocks, enacting");
                                                        if let Err(e) = send_block.enact() {
                                                            error!(
                                                                "Failed to enact send block {}, error={}",
                                                                send_block.hash, e
                                                            );
                                                        } else {
                                                            if let Err(e) = rec_block.enact() {
                                                                error!(
                                                                    "Failed to enact rec block {}, error={}",
                                                                    rec_block.hash, e
                                                                );
                                                            } else {
                                                                debug!("Enacted blocks, sending to rpc and peers");
                                                                let _ = block_announce(
                                                                    send_block.clone(),
                                                                );
                                                                let _ = block_announce(
                                                                    rec_block.clone(),
                                                                );
                                                                if let Err(e) =
                                                                    prop_block(&send_block)
                                                                {
                                                                    error!(
                                                                        "Failed to enact send block {}, error={}",
                                                                        send_block.hash, e
                                                                    );
                                                                } else {
                                                                    if let Err(e) =
                                                                        prop_block(&rec_block)
                                                                    {
                                                                        error!(
                                                                            "Failed to enact rec block {}, error={}",
                                                                            rec_block.hash, e
                                                                        );
                                                                    } else {
                                                                        info!("Done! Registered as new fullnode candidate");
                                                                        let mut current_config =
                                                                            config();
                                                                        current_config.node_type =
                                                                            'c'; // set node type to candidate
                                                                        if let Err(e) =
                                                                            current_config.create()
                                                                        {
                                                                            error!("Failed to save new config to disk, gave error={}",e );
                                                                        }
                                                                        // TODO: Encrypt private key and save to disk
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to form rec block, aborting (error={})", e)
                                    }
                                };
                            }
                        }
                    } else {
                        error!("Unknown response: {}", confirm);
                    }
                }
            }
        } else if read == "generate_invite" {
            // TODO: Only let fullnodes generate invites, also broadcast new invite to other nodes so they can validate it
            let invite = generate_invite();
            match new_invite(&invite.0) {
                Ok(_) => info!("Invite: {}", invite.1),
                Err(e) => error!("Failed to create new invire, got error={}", e),
            }
        } else {
            info!("Unknown command: {}", read);
        }
    }
}
