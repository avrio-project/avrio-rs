// Testnet one,
// This testnet foucouses on the P2p code, on launch a node will conect to the seed node(/s),
// get the peer list and connect to the other nodes on this peerlist. The node then registers.
//

use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`

use std::time::Duration;

use std::thread;

extern crate clap;
use clap::{App, Arg, SubCommand};

use std::fs::create_dir_all;

use serde_json::*;

extern crate ring;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

pub extern crate avrio_config;
use avrio_config::{config, Config};

extern crate avrio_core;
use avrio_core::{
    account::{deltaFunds, getAccount, setAccount, Account},
    certificate::{certificateErrors, difficulty_bytes_as_u64, generateCertificate, Certificate},
    gas::*,
    transaction::Transaction,
};

extern crate avrio_p2p;
use avrio_p2p::{new_connection, prop_block, rec_server, sync, sync_needed};

extern crate avrio_blockchain;
use avrio_blockchain::{genesis::*, *};

extern crate avrio_database;
use avrio_database::{getData, getPeerList, saveData, savePeerlist};

#[macro_use]
extern crate log;
extern crate simple_logger;

extern crate hex;

fn save_wallet(keypair: &Vec<String>) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let config = config();
    let path = config.db_path + &"/wallets".to_owned() + &keypair[0];
    if config.wallet_password == Config::default().wallet_password {
        warn!("Your wallet password is set to default, please change this password and run avrio daemon with --change-password-from-default <newpassword>");
    }
    let key = GenericArray::clone_from_slice(config.wallet_password.as_bytes());
    let aead = Aes256Gcm::new(key);

    let nonce = GenericArray::from_slice(b"nonce"); // 96-bits; unique per message

    let publickey_en = String::from_utf8(
        aead.encrypt(nonce, keypair[0].as_bytes().as_ref())
            .expect("wallet public keyencryption failure!"),
    )?;
    let privatekey_en = String::from_utf8(
        aead.encrypt(nonce, keypair[1].as_bytes().as_ref())
            .expect("wallet private key encryption failure!"),
    )?;
    let _ = saveData(publickey_en, path.clone(), "pubkey".to_owned());
    let _ = saveData(privatekey_en, path.clone(), "privkey".to_owned());
    info!("Saved wallet to {}", path);
    return Ok(());
}

fn generateKeypair(out: &mut Vec<String>) {
    let rngc = randc::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let peer_public_key_bytes = key_pair.public_key().as_ref();
    out.push(hex::encode(peer_public_key_bytes));
    out.push(hex::encode(pkcs8_bytes));
    let mut config = config();
    config.chain_key = hex::encode(peer_public_key_bytes);
    let _ = config.save();
}

fn database_present() -> bool {
    let get_res = getData(
        config().db_path + &"/chainsindex".to_owned(),
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

fn createFileStructure() -> std::result::Result<(), Box<dyn std::error::Error>> {
    create_dir_all(config().db_path + &"/blocks".to_string())?;
    create_dir_all(config().db_path + &"/chains".to_string())?;
    create_dir_all(config().db_path + &"/wallets".to_string())?;
    return Ok(());
}

fn connectSeednodes(seednodes: Vec<SocketAddr>, connected_peers: &mut Vec<TcpStream>) -> u8 {
    let mut i: usize = 0;
    let mut conn_count: u8 = 0;
    while i < seednodes.iter().count() - 1 {
        let mut error = new_connection(seednodes[i]);
        match error {
            Ok(_) => {
                info!("Connected to {:?}::{:?}", seednodes[i], 11523);
                conn_count += 1;
                let mut peer = error.unwrap();
                let mut peer_cloned = peer.stream.try_clone().unwrap();
                connected_peers.push(peer_cloned);
            }
            _ => warn!(
                "Failed to connect to {:?}:: {:?}, returned error {:?}",
                seednodes[i], 11523, error
            ),
        };
        i += 1;
    }
    return conn_count;
}
fn firstStartUp() -> u16 {
    info!("First startup detected, creating file structure");
    let mut state = createFileStructure();
    if let Err(e) = state {
        error!("Failed to create  filestructure, recieved error: {:?}.  (Fatal). Try checking permissions.", e);
        process::exit(1); // Faling to create the file structure is fatal but probaly just a permisions error
    } else {
        info!("Succsesfuly created filestructure");
    }
    drop(state);
    info!("Creating Chain for self");
    let mut chainKey: Vec<String> = vec![]; // 0 = pubkey, 1 = privkey
    generateKeypair(&mut chainKey);
    if chainKey[0] == "0".to_owned() {
        error!("failed to create keypair (Fatal)");
        process::exit(1);
    } else {
        info!(
            "Succsessfully created keypair with chain key {}",
            chainKey[0]
        );
        if let Err(e) = save_wallet(&chainKey) {
            error!("Failed to save wallet: {}, gave error: {}", chainKey[0], e);
            process::exit(1);
        }
    }
    let mut genesis_block = getGenesisBlock(&chainKey[0]);
    if let Err(e) = genesis_block {
        if e == genesisBlockErrors::BlockNotFound {
            info!(
                "No genesis block found for chain: {}, generating",
                chainKey[0]
            );
            genesis_block = generateGenesisBlock(chainKey[0].clone(), chainKey[1].clone());
        } else {
            error!(
                "Database error occoured when trying to get genesisblock for chain: {}. (Fatal)",
                chainKey[0]
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
            "Succsessfully generated genesis block with hash {}",
            genesis_block_clone.hash
        ),
    }
    let e_code = saveBlock(genesis_block_clone);
    match e_code {
        Ok(_) => {
            info!("Sucsessfully saved genesis block!");
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
        " Launching P2p server on 127.0.0.1::{:?}",
        config().p2p_port
    );
    let p2p_handler = thread::spawn(|| {
        if rec_server() != 1 {
            error!(
                "Error launching P2p server on 127.0.0.1::{:?} (Fatal)",
                config().p2p_port
            );
            process::exit(1);
        }
    });
    thread::sleep(Duration::from_millis(500));
    let peerlist: Vec<SocketAddr>;
    let mut conn_nodes = 0;
    let mut trys: u8 = 0;
    let mut connected_peers: Vec<TcpStream> = vec![];
    while conn_nodes < 1 {
        let seednodes: Vec<SocketAddr> = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(126, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(123, 0, 0, 1)), 12345),
        ];
        if trys > 49 {
            process::exit(1);
        }
        if trys > 0 {
            warn!("Failed to connect to any seednodes, retrying");
        }
        conn_nodes = connectSeednodes(seednodes, &mut connected_peers);
        trys += 1;
    }
    info!("Connected to seednode(s), polling for peerlist (this may take some time)");
    //for peer in connected_peers.clone() {
    //peer.write()
    //}
    //peerlist = getPeerList().unwrap();
    //conn_nodes += connectSeednodes(peerlist, &mut connected_peers);
    thread::sleep(Duration::from_millis(2500));
    info!("Started syncing");
    let con_peer_len = connected_peers.len();
    for mut peer_val in connected_peers {
        let mut connected_peers_mut: Vec<&mut TcpStream> = vec![];
        connected_peers_mut.push(&mut peer_val);
        if connected_peers_mut.len() == con_peer_len {
            let sync = sync(&mut connected_peers_mut);
        }
    }
    info!("Generating Node Cerificate (for self)");
    // TODO: generate node certificate
    info!("Registering with network");
    // TODO: send the certificate to peers
    return 1;
}

fn send_block(chainKey: String, height: u64, private_key: String) {
    // create block
    let transactions: Vec<Transaction> = vec![
        //todo
    ];
    let prev_hash = "00000000".to_owned();
    if height != 0 {
        getData(
            config().db_path + &"/".to_owned() + &chainKey + &"-invs".to_owned(),
            &(height - 1).to_string(),
        );
    }
    let mut new_block = Block {
        header: Header {
            version_major: 0,
            version_breaking: 0,
            version_minor: 0,
            chain_key: chainKey.clone(),
            prev_hash,
            height,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64,
        },
        txns: transactions,
        hash: String::from(""),
        signature: String::from(""),
        nonce: "1234".to_owned(),
        node_signatures: vec![],
    };
    new_block.hash();
    new_block.sign(&private_key);
    let mut new_block_s: String = "".to_string();
    if let Ok(_) = check_block(new_block.clone()) {
        let state = prop_block(new_block.clone());
        if let Err(e) = state {
            // there was an error
            error!(
                "Failed to propiagte block {:?}, encountered error: {:?}",
                new_block.hash, e
            ); // tell them the error
            error!("Block dump: non serilised {:?}", new_block); // now flood their eyes
            process::exit(1);
        }
    }
}

// TODO: write existing start up code
fn existingStartup() -> u16 {
    return 1;
}

fn main() {
    let matches = App::new("Avrio Daemon")
        .version("Testnet Pre-alpha 0.0.1")
        .about("This is the offical daemon for the avrio network.")
        .author("Leo Cornelius")
        .arg(Arg::with_name("config")
                               .short("c")
                               .long("config-file")
                               .value_name("FILE")
                               .help("(DOESNT WORK YET!!) Sets a custom config file, if not set will use node.conf")
                               .takes_value(true))
                               .arg(Arg::with_name("loglev")
                               .long("log-level")
                               .short("v")
                               .multiple(true)
                               .help("Sets the level of verbosity: 0: Error, 1: Warn, 2: Info, 3: debug"))
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
    info!("Avrio Daemon Testnet v1.0.0 (pre-alpha)");
    let config_ = config();
    let _ =config_.save();
    info!("Checking for previous startup. DO NOT CLOSE PROGRAM NOW!!!");
    let startup_state: u16 = match database_present() {
        true => existingStartup(),
        false => firstStartUp(),
    };
    let mut synced: bool = false;
    if startup_state == 1 {
        // succsess
        info!("Avrio Daemon succsessfully launched");
        match sync_needed() {
            // do we need to sync
            true => {
                let pl: Vec<SocketAddr> = getPeerList().unwrap();
                for peer in pl {
                    let res = new_connection(peer);
                    if let Ok(mut peer_struct) = res {
                        let mut peers: Vec<&mut TcpStream> = vec![];
                        peers.push(&mut peer_struct.stream);
                        sync(&mut peers);
                        info!("Successfully synced with the network!");
                        synced = true;
                    }
                }
            }
            false => {
                info!("Succsessfully synced with the network!");
                synced = true;
            }
        }
    } else {
        error!("Failed to start avrio daemon (Fatal)");
        panic!();
    }
    if sync_needed() == false
    // check in case a new block has been released since we syned
    {
        // TODO: !!!URGENT!!!, use custom set password
        let key = GenericArray::clone_from_slice(b"wallet-password");
        let aead = Aes256Gcm::new(key);
        // TODO: use unique nonce
        let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = getData(
            config().db_path + &"/wallets/wallet".to_owned(),
            &"pubkey".to_owned(),
        );
        let pubkey = String::from_utf8(
            aead.decrypt(nonce, ciphertext.as_ref())
                .expect("decryption failure!"),
        )
        .expect("failed to parse utf8");
        // now priv key
        let key = GenericArray::clone_from_slice(b"wallet-password");
        let aead = Aes256Gcm::new(key);
        // TODO: use unique nonce
        let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = getData(
            config().db_path + &"/wallets/wallet".to_owned(),
            &"privkey".to_owned(),
        );
        let privkey = String::from_utf8(
            aead.decrypt(nonce, ciphertext.as_ref())
                .expect("decryption failure!"),
        )
        .expect("failed to parse utf8");
        // now send block
        send_block(pubkey, 0, privkey);
    } else {
        match sync_needed() {
            // do we need to sync
            true => {
                let pl: Vec<SocketAddr> = getPeerList().unwrap();
                for peer in pl {
                    let res = new_connection(peer);
                    if let Ok(mut peer_struct) = res {
                        let mut peers: Vec<&mut TcpStream> = vec![];
                        peers.push(&mut peer_struct.stream);
                        sync(&mut peers);
                        info!("Successfully synced with the network!");
                        synced = true;
                    }
                }
                // TODO: !!!URGENT!!!, use custom set password
                let key = GenericArray::clone_from_slice(b"wallet-password");
                let aead = Aes256Gcm::new(key);
                // TODO: use unique nonce
                let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
                let ciphertext = getData(
                    config().db_path + &"/wallets/wallet".to_owned(),
                    &"pubkey".to_owned(),
                );
                let pubkey = String::from_utf8(
                    aead.decrypt(nonce, ciphertext.as_ref())
                        .expect("decryption failure!"),
                )
                .expect("failed to parse utf8");
                // now priv key
                let key = GenericArray::clone_from_slice(b"wallet-password");
                let aead = Aes256Gcm::new(key);
                // TODO: use unique nonce
                let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
                let ciphertext = getData(
                    config().db_path + &"/wallets/wallet".to_owned(),
                    &"privkey".to_owned(),
                );
                let privkey = String::from_utf8(
                    aead.decrypt(nonce, ciphertext.as_ref())
                        .expect("decryption failure!"),
                )
                .expect("failed to parse utf8");
                // now send block
                send_block(pubkey, 0, privkey);
            }
            false => {
                synced = true;
                // TODO: !!!URGENT!!!, use custom set password
                let key = GenericArray::clone_from_slice(b"wallet-password");
                let aead = Aes256Gcm::new(key);
                // TODO: use unique nonce
                let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
                let ciphertext = getData(
                    config().db_path + &"/wallets/wallet".to_owned(),
                    &"pubkey".to_owned(),
                );
                let pubkey = String::from_utf8(
                    aead.decrypt(nonce, ciphertext.as_ref())
                        .expect("decryption failure!"),
                )
                .expect("failed to parse utf8");
                // now priv key
                let key = GenericArray::clone_from_slice(b"wallet-password");
                let aead = Aes256Gcm::new(key);
                // TODO: use unique nonce
                let nonce = GenericArray::from_slice(b"unique nonce"); // 96-bits; unique per message
                let ciphertext = getData(
                    config().db_path + &"/wallets/wallet".to_owned(),
                    &"privkey".to_owned(),
                );
                let privkey = String::from_utf8(
                    aead.decrypt(nonce, ciphertext.as_ref())
                        .expect("decryption failure!"),
                )
                .expect("failed to parse utf8");
                // now send block
                send_block(pubkey, 0, privkey);
            }
        };
    }
}
