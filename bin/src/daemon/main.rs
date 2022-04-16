pub(crate) mod fullnode;
use avrio_core::{
    account::to_dec,
    block::{genesis::genesis_blocks, *},
    certificate::{generate_certificate, get_fullnode_count},
    epoch::{get_top_epoch, Epoch},
    invite::{generate_invite, new_invite},
    mempool::Mempool,
    states::form_state_digest,
    timer::create_timer,
    transaction::{Transaction, EPOCH_STARTED_CALLBACKS, VRF_LOTTERY_CALLBACKS},
    validate::Verifiable,
};
use avrio_p2p::core::HANDLE_CHUNK_CALLBACK;
use avrio_rpc::*;
use bls_signatures::{PrivateKey, Serialize};
use fullnode::*;
use rand::thread_rng;
use std::panic;
use std::{fs::File, io::Read, thread, time::Duration};
use std::{
    io::{self, Write},
    time::{SystemTime, UNIX_EPOCH},
};
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

extern crate avrio_database;
use avrio_database::{get_data, get_peerlist};
#[macro_use]
extern crate log;

extern crate hex;

use avrio_api::start_server;

extern crate avrio_crypto;
use avrio_crypto::{
    generate_secp256k1_keypair, get_vrf, private_to_public_secp256k1, proof_to_hash, raw_hash,
    vrf_hash_to_integer, Wallet,
};
use bigdecimal::BigDecimal;

use common::setup_logging;
use lazy_static::lazy_static;
use text_io::read;

lazy_static! {
    static ref MEMPOOL: Mutex<Option<Mempool>> = Mutex::new(None);
    static ref FULLNODE_KEYS: Mutex<Vec<String>> = Mutex::new(vec![]);
}
pub fn safe_exit() {
    // TODO: save mempool to disk + send kill to all threads.

    info!("Goodbye!");
    let _ = avrio_p2p::core::close_all();
    (*(MEMPOOL.lock().unwrap()))
        .as_ref()
        .unwrap()
        .shutdown()
        .unwrap();
    *(MEMPOOL.lock().unwrap()) = None;
    avrio_database::close_db();
    std::process::exit(0);
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

fn generate_chains() -> Result<(), Box<dyn std::error::Error>> {
    let genesis_blocks = genesis_blocks();
    info!(
        "Generating chains (from {} genesis blocks)",
        genesis_blocks.len()
    );
    for block in genesis_blocks {
        info!(
            "Genesis block with hash {} from chain {}",
            block.hash,
            Wallet::new(block.header.chain_key.clone(), "".to_owned()).address()
        );
        if get_block_from_raw(block.hash.clone()) != block {
            save_block(block.clone())?;
            block.enact()?;
            debug!("Block {} was not saved, saved and enacted", block.hash);
        }
    }
    // Create the seed invites
    // TODO: change this to a block on the 0 chain
    new_invite("FZ2YbpGw1ZjRW2dkwMRfy7N98iZCkcfezy5BxCGWRPgZ")?;
    new_invite("HMkWDsDQ9JTF5xkqh5QjZMq56iapH4UVHL8BDod7dQnX")?;
    // invite priv key:
    // GD8M1Qm17WXoukx8QqqfvYRJDoxmjf1jSXFXyVYHFeQtCX67cpw6otCpeporyLaNmLKrKAj8nFSNfszJYyuTL1UFt6SFeodz3QJ8iDkvwBPM4SMMGkV3
    // and GD8M1Qm17WXoukx8QqqfvXP9c8xBx3egZAk4WEYux9GuTKMUjwTn8dxtAHL2Ffn3LGWz7pprKNAm7bNEuiKu7CDXfiDtM5zuug4p7UHfQoLKoYfiA5Vm
    // set up the top epoch
    let mut genesis_epoch = Epoch::new();
    genesis_epoch.epoch_number = 0;
    genesis_epoch.hash();
    genesis_epoch.save()?;
    genesis_epoch.set_top_epoch()?;
    Ok(())
}

fn database_present() -> bool {
    let get_res = get_data("chaindigest".to_owned(), &"master".to_owned());
    !(get_res == *"-1" || get_res == *"0")
}

fn create_file_structure() -> std::result::Result<(), Box<dyn std::error::Error>> {
    info!("Creating datadir folder structure");
    //TODO: evaluate which are no longer needed
    create_dir_all(config().db_path + &"/blocks".to_string())?;
    create_dir_all(config().db_path + &"/chains".to_string())?;
    create_dir_all(config().db_path + &"/wallets".to_string())?;
    create_dir_all(config().db_path + &"/keystore".to_string())?;
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
                info!("Connected to {:?}::{:?}", peer.ip(), peer.port());
                conn_count += 1;
                connected_peers.push(error.unwrap());
            }
            _ => warn!(
                "Failed to connect to {:?}::{:?}, returned error {:?}",
                peer.ip(),
                peer.port(),
                error
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
        .subcommand(App::new("generate_keypair").about("Generates a fullnode keypair and exits"))
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
    match matches.value_of("loglev").unwrap_or("2") {
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
    println!("{}", art);
    info!("Avrio Daemon Testnet v0.1.0 (alpha)");
    warn!("Warning, this software is not stable");
    if matches.is_present("generate_bls_keypair") {
        info!("Generating keypair...");
        let mut rng = thread_rng();
        let bls_private_key = PrivateKey::generate(&mut rng);
        let bls_public_key = bls_private_key.public_key();
        info!(
            "BLS publickey: {}",
            bs58::encode(bls_public_key.as_bytes()).into_string()
        );
        info!(
            "BLS privatekey: {}",
            bs58::encode(bls_public_key.as_bytes()).into_string()
        );
    }
    let conf = config();
    conf.create().unwrap();
    if config().node_type == 'c' || config().node_type == 'f' {
        info!("Running as candidate, loading keys");
        let keys = open_keypair();
        if keys.len() != 6 {
            error!("Bad fullnode keyfile, expected 6 keys, got {}", keys.len());
            safe_exit();
        }

        info!("Loaded keyfile: {}, {}", keys[0], keys[2]);
        match FULLNODE_KEYS.lock() {
            Ok(mut lock) => {
                *lock = keys;
                debug!("Set FULLNODE_KEYS");

                match VRF_LOTTERY_CALLBACKS.lock() {
                    Ok(mut lock) => {
                        debug!("Got mutex lock on VRF_LOTTERY_CALLBACKS lazy static ");
                        lock.push(Box::new(handle_vrf_lottery));
                        debug!("Registered in VRF_LOTTERY_CALLBACKS");
                    }
                    Err(lock_error) => {
                        error!(
                            "Failed to gain mutex lock on VRF_LOTTERY_CALLBACKS lazy static, got error={}",
                            lock_error
                        );
                        process::exit(0);
                    }
                }
                match HANDLE_CHUNK_CALLBACK.lock() {
                    Ok(mut lock) => {
                        *lock = Some(Box::new(fullnode::handle_proposed_chunk));
                        debug!("Registered in HANDLE_CHUNK_CALLBACK");
                    }
                    Err(lock_error) => {
                        error!(
                            "Failed to gain mutex lock on HANDLE_CHUNK_CALLBACK lazy static, got error={}",
                            lock_error
                        );
                        process::exit(0);
                    }
                }
                match EPOCH_STARTED_CALLBACKS.lock() {
                    Ok(mut lock) => {
                        debug!("Got mutex lock on EPOCH_STARTED_CALLBACKS lazy static ");
                        lock.push(Box::new(handle_new_epoch));
                        debug!("Registered in EPOCH_STARTED_CALLBACKS");
                    }
                    Err(lock_error) => {
                        error!(
                            "Failed to gain mutex lock on EPOCH_STARTED_CALLBACKS lazy static, got error={}",
                            lock_error
                        );
                        process::exit(0);
                    }
                }
                let epoch = get_top_epoch().unwrap();
                if get_fullnode_count() == 1 && epoch.epoch_number == 0 {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("time went backwards")
                        .as_millis();
                    let mut conf = config();
                    conf.node_type = 'f';
                    let _ = conf.create().unwrap();

                    if now > config().first_epoch_time as u128 {
                        warn!(
                            "Missed targeted genesis epoch time of {} by {} ms",
                            config().first_epoch_time,
                            now - config().first_epoch_time as u128
                        );
                        create_timer(
                            Duration::from_millis(5000),
                            Box::new(|()| {
                                let _ = start_genesis_epoch();
                            }),
                            (),
                        );
                    } else {
                        let time_till_genesis_epoch = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("time went backwards")
                            .as_millis()
                            as u64
                            - config().first_epoch_time;
                        info!(
                            "Running as god account, genesis epoch in {} ms",
                            time_till_genesis_epoch
                        );

                        create_timer(
                            Duration::from_millis(time_till_genesis_epoch),
                            Box::new(|()| {
                                let _ = start_genesis_epoch();
                            }),
                            (),
                        );
                    }
                }
            }
            Err(lock_error) => {
                error!(
                    "Failed to gain mutex lock on FULLNODE_KEYS lazy static, got error={}",
                    lock_error
                );
                process::exit(0);
            }
        }
    }
    if !database_present() {
        create_file_structure().unwrap();
    }
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
    let mut statedigest = get_data("chaindigest".to_owned(), "master");
    if statedigest == *"-1" {
        generate_chains().unwrap();
        statedigest =
            form_state_digest("chaindigest".to_owned()).unwrap_or_default();
        info!("State digest (regenerated): {}", statedigest);
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
    // figure out the current epoch stage
    let running = *(fullnode::RUNNING.lock().unwrap());
    if !running && config().node_type == 'f' {
        resume_operation().unwrap();
    }
    loop {
        // Now we loop until shutdown
        let _ = io::stdout().flush();
        let read: String = read!("{}\n");
        trace!("Read: {}", read);
        if read == "exit" {
            safe_exit();
            process::exit(0);
        } else if read.split(' ').collect::<Vec<&str>>()[0] == "get_data" {
            let mut params = read.split(' ').collect::<Vec<&str>>();
            if params.len() != 3 {
                error!("Needs 2 params (tip:  use 'none' if you want a value to be empty)")
            } else {
                for param in params.iter_mut() {
                    if *param == "none" {
                        *param = "";
                    }
                }
                info!("Got data: {}", get_data(params[1].to_owned(), params[2]));
            }
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
            info!("register_fullnode : Register as a fullnode");
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
            let block_txn_is_in = get_data("transactions".to_owned(), &hash);
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
            let block_txn_is_in = get_data("transactions".to_owned(), &commitment);
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
                    let private_key_string: String = trim_newline(&mut read!());
                    let wallet = Wallet::from_private_key(private_key_string);
                    info!("Please enter the invite:");
                    let invite: String = read!();
                    info!(
                        "Registering as fullnode with publickey={}? (y/n)",
                        wallet.public_key
                    );
                    let confirm: String = read!();
                    if confirm.to_ascii_uppercase() == "N" {
                        error!("Aborting...");
                    } else if confirm.to_ascii_uppercase() == "Y" {
                        if let Ok(_) = register_fullnode(wallet, invite, commitment) {
                            info!("Please restart your node for changes to take place");
                            safe_exit();
                        } else {
                            error!("Fullnode registration failed")
                        }
                    } else {
                        error!("Unknown response: {}", confirm);
                    }
                }
            }
        } else if read == "generate_invite" {
            // TODO: broadcast new invite to other nodes so they can validate it
            if config().node_type != 'f' {
                error!("Not a fullnode")
            }
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

pub fn register_fullnode(
    wallet: Wallet,
    invite: String,
    commitment: String,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Forming BLS keypair");
    let mut rng = thread_rng();
    let bls_private_key = PrivateKey::generate(&mut rng);
    let bls_public_key = bls_private_key.public_key();
    info!(
        "Formed BLS keypair: {}",
        bs58::encode(bls_public_key.as_bytes()).into_string()
    );
    info!("Forming secp256k1 keypair");
    let secp_keypair = generate_secp256k1_keypair();
    if secp_keypair.len() != 2 {
        error!("Failed to generate secp256k1 keypair");
        return Err("Failed to generate secp256k1 keypair".into());
    }
    info!("Formed secp256k1 keypair: {}", secp_keypair[1]);
    info!("Forming fullnode certificate...");
    if let Ok(cert) = generate_certificate(
        &wallet.public_key,
        &wallet.private_key,
        &commitment,
        invite,
        bs58::encode(bls_private_key.as_bytes()).into_string(),
        secp_keypair[0].clone(),
    ) {
        trace!("Formed certificate={:#?}", cert);
        // form a transaction using the private key given before, add it to a block and send
        let mut txn: Transaction = Transaction {
            hash: String::from(""),
            amount: 1,
            extra: bs58::encode(serde_json::to_string(&cert).unwrap().as_bytes()).into_string(),
            flag: 'f',
            sender_key: wallet.public_key.clone(),
            receive_key: wallet.public_key.clone(),
            access_key: String::from(""),
            unlock_time: 0,
            gas_price: 20,
            max_gas: u64::MAX,
            nonce: get_data(
                "chains/".to_owned() + &wallet.public_key + &"-chainindex".to_owned(),
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
            "chains/".to_owned() + &wallet.public_key + &"-chainindex".to_owned(),
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
                    .as_millis() as u64,
                network: config().network_id,
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
            match send_block.form_receive_block(Some(wallet.public_key.clone())) {
                Ok(rec_block) => {
                    info!(
                        "Created blocks {} and {} containing fullnode registration; broadcasting",
                        send_block.hash, rec_block.hash
                    );
                    if let Err(e) = send_block.valid() {
                        error!(
                            "Created send block {} invalid, reason={}",
                            send_block.hash, e
                        );
                    } else {
                        if let Err(e) = send_block.save() {
                            error!("Failed to save send block {}, error={}", send_block.hash, e);
                        } else {
                            debug!("Saved blocks, enacting");
                            if let Err(e) = send_block.enact() {
                                error!(
                                    "Failed to enact send block {}, error={}",
                                    send_block.hash, e
                                );
                            } else {
                                if let Err(e) = rec_block.valid() {
                                    error!(
                                        "Created rec block {} invalid, reason={}",
                                        rec_block.hash, e
                                    );
                                } else {
                                    if let Err(e) = rec_block.save() {
                                        error!(
                                            "Failed to save rec block {}, error={}",
                                            rec_block.hash, e
                                        );
                                    } else {
                                        if let Err(e) = rec_block.enact() {
                                            error!(
                                                "Failed to enact rec block {}, error={}",
                                                rec_block.hash, e
                                            );
                                        } else {
                                            debug!("Enacted blocks, sending to rpc and peers");
                                            let _ = block_announce(send_block.clone());
                                            let _ = block_announce(rec_block.clone());
                                            if let Err(e) = prop_block(&send_block) {
                                                error!(
                                                    "Failed to enact send block {}, error={}",
                                                    send_block.hash, e
                                                );
                                            } else {
                                                if let Err(e) = prop_block(&rec_block) {
                                                    error!(
                                                        "Failed to enact rec block {}, error={}",
                                                        rec_block.hash, e
                                                    );
                                                } else {
                                                    info!("Done! Registered as new fullnode candidate");
                                                    let mut current_config = config();
                                                    current_config.node_type = 'c'; // set node type to candidate
                                                    current_config.chain_key =
                                                        wallet.public_key.clone();
                                                    if let Err(e) = current_config.create() {
                                                        error!("Failed to save new config to disk, gave error={}",e );
                                                    }
                                                    // Save the keyfile to disk
                                                    if let Err(e) = save_keyfile(&[
                                                        wallet.private_key,
                                                        bs58::encode(bls_private_key.as_bytes())
                                                            .into_string(),
                                                        secp_keypair[0].clone(),
                                                    ]) {
                                                        error!("Failed to save keypair to disk; error={}", e);
                                                    } else {
                                                        return Ok(());
                                                    }
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
    Err("Failed".into())
}

pub fn save_keyfile(keypair: &[String]) -> io::Result<()> {
    let conf = config();
    let path = conf.db_path.clone() + &"/keystore/nodekey".to_owned();
    let mut file = File::create(path)?;
    file.write_all(serde_json::to_string(keypair).unwrap().as_bytes())?;
    Ok(())
}

pub fn open_keypair() -> Vec<String> {
    log::trace!("Reading keypair from disk");
    let conf = config();
    let path = conf.db_path.clone() + &"/keystore/nodekey".to_owned();
    if let Ok(mut file) = File::open(path) {
        let mut data: String = String::from("");

        if file.read_to_string(&mut data).is_err() {
            error!("Failed to read keypair from disk");
            return vec![];
        } else {
            let privkeys: Vec<String> = serde_json::from_str(&data).unwrap_or_default();
            if privkeys.len() != 3 {
                error!(
                    "Bad fullnode keyfile, expected 3 private keys, got {}",
                    privkeys.len()
                );
                safe_exit();
            }
            let wallet = Wallet::from_private_key(privkeys[0].clone());
            let bls_priv =
                PrivateKey::from_bytes(&bs58::decode(&privkeys[1]).into_vec().unwrap()).unwrap();
            let secp_pub = private_to_public_secp256k1(&privkeys[2]).unwrap_or_default();
            return vec![
                wallet.public_key,
                wallet.private_key,
                bs58::encode(bls_priv.public_key().as_bytes()).into_string(),
                privkeys[1].clone(),
                secp_pub,
                privkeys[2].clone(),
            ];
        }
    } else {
        error!("Failed to read keypair from disk");
        return vec![];
    }
}
