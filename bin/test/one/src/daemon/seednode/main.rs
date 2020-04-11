use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`

use std::time::Duration;

use std::thread;

extern crate clap;
use clap::{App, Arg};

use std::fs::create_dir_all;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

pub extern crate avrio_config;
use avrio_config::{config, Config};

extern crate avrio_core;
use avrio_core::transaction::Transaction;

extern crate avrio_p2p;
use avrio_p2p::{new_connection, prop_block, rec_server, sync, sync_needed};

extern crate avrio_blockchain;
use avrio_blockchain::{
    genesis::{generateGenesisBlock, genesisBlockErrors, genesis_blocks, getGenesisBlock},
    *,
};

extern crate avrio_database;
use avrio_database::{getData, getIter, get_peerlist, openDb, saveData};

#[macro_use]
extern crate log;
extern crate simple_logger;

extern crate hex;

use avrio_rpc::start_server;

extern crate avrio_crypto;
use avrio_crypto::Wallet;

fn generate_chains() -> Result<(), Box<dyn std::error::Error>> {
    for block in genesis_blocks() {
        saveBlock(block.clone())?;
        enact_block(block)?;
    }
    return Ok(());
}

fn database_present() -> bool {
    let get_res = getData(
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
    create_dir_all(config().db_path + &"/blocks".to_string())?;
    create_dir_all(config().db_path + &"/chains".to_string())?;
    create_dir_all(config().db_path + &"/wallets".to_string())?;
    return Ok(());
}

fn save_wallet(keypair: &Vec<String>) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let conf = config();
    let path = conf.db_path + &"/wallets/".to_owned() + &keypair[0];
    if conf.wallet_password == Config::default().wallet_password {
        warn!("Your wallet password is set to default, please change this password and run avrio daemon with --change-password-from-default <newpassword>");
    }
    let mut padded = conf.wallet_password.as_bytes().to_vec();
    while padded.len() != 32 && padded.len() < 33 {
        padded.push(b"n"[0]);
    }
    let padded_string = String::from_utf8(padded).unwrap();
    let key = GenericArray::clone_from_slice(padded_string.as_bytes());
    let aead = Aes256Gcm::new(key);
    let mut padded = b"nonce".to_vec();
    while padded.len() != 12 {
        padded.push(b"n"[0]);
    }
    let padded_string = String::from_utf8(padded).unwrap();
    let nonce = GenericArray::from_slice(padded_string.as_bytes()); // 96-bits; unique per message
    let publickey_en = hex::encode(
        aead.encrypt(nonce, keypair[0].as_bytes().as_ref())
            .expect("wallet public key encryption failure!"),
    );
    let privatekey_en = hex::encode(
        aead.encrypt(nonce, keypair[1].as_bytes().as_ref())
            .expect("wallet private key encryption failure!"),
    );
    let _ = saveData(publickey_en, path.clone(), "pubkey".to_owned());
    let _ = saveData(privatekey_en, path.clone(), "privkey".to_owned());
    info!("Saved wallet to {}", path);
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

fn main() {
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
                .multiple(true)
                .help("Sets the level of verbosity: 0: Error, 1: Warn, 2: Info, 3: debug"),
        )
        .get_matches();
    match matches.value_of("loglev").unwrap_or(&"2") {
        "0" => simple_logger::init_with_level(log::Level::Error).unwrap(),
        "1" => simple_logger::init_with_level(log::Level::Warn).unwrap(),
        "2" => simple_logger::init_with_level(log::Level::Info).unwrap(),
        "3" => simple_logger::init_with_level(log::Level::Debug).unwrap(),
        "4" => simple_logger::init_with_level(log::Level::Trace).unwrap(),
        _ => panic!("Unknown log-level: {} ", matches.occurrences_of("loglev")),
    }
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
    info!("Avrio Seednode Daemon Testnet v1.0.0 (pre-alpha)");
    let conf = config();
    let _ = conf.save();
    info!("Launching RPC server");
    let _rpc_server_handle = thread::spawn(|| {
        start_server();
    });
    let mut synced: bool = true;
    if !database_present() {
        create_file_structure().unwrap();
    }
    info!("Avrio Seednode Daemon successfully launched");
    let chainsdigest: String = generate_merkle_root_all().unwrap_or_default();
    if chainsdigest == "GKot5hBsd81kMupNCXHaqbhv3huEbxAFMLnpcX2hniwn".to_owned() {
        generate_chains().unwrap();
        info!("Saved genesis block(s)");
    }
    let chainsdigest: String = generate_merkle_root_all().unwrap_or_default();
    info!("Chain digest: {}", chainsdigest);
    let pl = get_peerlist();
    match pl {
        // do we need to sync
        Ok(_) => {
            let pl: Vec<SocketAddr> = get_peerlist().unwrap();
            for peer in pl {
                let res = new_connection(peer);
                if let Ok(mut peer_struct) = res {
                    let mut peers: Vec<&mut TcpStream> = vec![];
                    peers.push(&mut peer_struct.stream);
                    if let Ok(_) = sync(&mut peers) {
                        info!("Successfully synced with the network!");
                        synced = true;
                    } else {
                        error!("Syncing failed");
                        process::exit(1);
                    }
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
    if config().chain_key == "".to_owned() {
        info!("Generating a chain for self");
        let mut chain_key: Vec<String> = vec![]; // 0 = pubkey, 1 = privkey
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
        let e_code = saveBlock(genesis_block_clone);
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
    } else {
        info!("Using chain: {}", config().chain_key);
    }
    info!(
        " Launching P2p server on 127.0.0.1::{:?}",
        config().p2p_port
    );
    let _p2p_handler = thread::spawn(|| {
        if rec_server() != 1 {
            error!(
                "Error launching P2p server on 127.0.0.1::{:?} (Fatal)",
                config().p2p_port
            );
            process::exit(1);
        }
    });
    loop {
        // Now we loop until shutdown
    }
}
