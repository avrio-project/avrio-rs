use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`

use std::time::Duration;

use std::io::{self, BufRead, Write};

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
use avrio_core::{account::to_atomc, transaction::Transaction};

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

use text_io::read;

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
                .value_name("loglev-val")
                .help("Sets the level of verbosity: 0: Error, 1: Warn, 2: Info, 3: debug"),
        )
        .get_matches();
    match matches.value_of("loglev-val").unwrap_or(&"2") {
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
    let mut chain_key: Vec<String> = vec![]; // 0 = pubkey, 1 = privkey
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
        info!("Enacting genesis block");
        match enact_block(genesis_block_clone) {
            Ok(_) => {
                info!("Sucessfully enacted genesis block!");
            }
            Err(e) => {
                error!(
                    "Failed to enact genesis block gave error code: {:?} (fatal)!",
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
    let wall = Wallet::from_private_key(chain_key[1].clone());
    info!(
        "txn count for our chain: {}",
        avrio_database::getData(
            config().db_path
                + &"/chains/".to_owned()
                + &wall.public_key
                + &"-chainindex".to_owned(),
            &"txncount".to_owned(),
        )
    );
    let mut txn = Transaction {
        hash: String::from(""),
        amount: 500005, // 1234.5 AIO
        extra: String::from(""),
        flag: 'c',
        sender_key: wall.public_key.clone(),
        receive_key: String::from(""),
        access_key: String::from(""),
        unlock_time: 0,
        gas_price: 10, // 0.001 AIO
        gas: 0,        // claim uses 0 fee
        max_gas: u64::max_value(),
        nonce: 0,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64,
        signature: String::from(""),
    };
    txn.hash();
    let _ = txn.sign(&wall.private_key);
    txn.validate_transaction();
    let mut blk = Block {
        header: Header {
            version_major: 0,
            version_breaking: 0,
            version_minor: 0,
            chain_key: wall.public_key.clone(),
            prev_hash: getBlock(&wall.public_key, 0).hash,
            height: 1,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64,
            network: vec![97, 118, 114, 105, 111, 32, 110, 111, 111, 100, 108, 101],
        },
        txns: vec![txn],
        hash: "".to_owned(),
        signature: "".to_owned(),
        confimed: false,
        node_signatures: vec![],
    };
    blk.hash();
    let _ = blk.sign(&wall.private_key);
    let _ = check_block(blk.clone()).unwrap();
    let _ = enact_block(blk).unwrap();
    let ouracc = avrio_core::account::getAccount(&wall.public_key).unwrap();
    info!("Our balance: {}", ouracc.balance_ui().unwrap());
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
            info!("Please enter the reciever address");
            let addr: String = read!();
            let rec_wall = Wallet::from_address(addr);
            txn.receive_key = rec_wall.public_key;
            txn.nonce = avrio_database::getData(
                config().db_path
                    + &"/chains/".to_owned()
                    + &txn.sender_key
                    + &"-chainindex".to_owned(),
                &"txncount".to_owned(),
            )
            .parse()
            .unwrap();
            txn.hash();
            let _ = txn.sign(&wall.private_key);
            // TODO: FIX!!
            let inv_db = openDb(
                config().db_path + &"/chains".to_string() + &wall.public_key + &"-invs".to_string(),
            )
            .unwrap();
            let mut invIter = getIter(&inv_db);
            let mut highest_so_far: u64 = 0;
            invIter.seek_to_first();
            while invIter.valid() {
                let height: u64 = String::from_utf8(invIter.key().unwrap().into())
                    .unwrap()
                    .parse()
                    .unwrap();
                if height > highest_so_far {
                    highest_so_far = height
                }
                invIter.next();
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
                txns: vec![txn],
                hash: "".to_owned(),
                signature: "".to_owned(),
                confimed: false,
                node_signatures: vec![],
            };
            blk.hash();
            let _ = blk.sign(&wall.private_key);
            let _ = check_block(blk.clone()).unwrap();
            let _ = enact_block(blk.clone()).unwrap();
            let ouracc = avrio_core::account::getAccount(&wall.public_key).unwrap();
            info!(
                "Transaction sent! Txn hash: {}, Our new balance: {} AIO",
                blk.txns[0].hash,
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
            // TODO: save mempool to disk, close p2p conns, send kill to all threads.
            info!("Goodbye!");
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
                error!("Couldnt find a block with that hash.");
            } else {
                info!("{:#?}", blk);
            }
        } else if read == "get_transaction" {
            info!("Enter the transaction hash:");
            let hash: String = read!("{}\n");
            let block_txn_is_in = getData(config().db_path + &"/transactions".to_owned(), &hash);
            let blk: Block = getBlockFromRaw(block_txn_is_in);
            if blk == Block::default() {
                error!("Couldnt find a block with that hash.");
            } else {
                for txn in blk.txns {
                    if txn.hash == hash {
                        info!("Transaction with hash: {}", txn.hash);
                        info!("____________________________");
                        info!(
                            "To: {}, From: {}",
                            Wallet::new(txn.receive_key, "".to_owned()).address(),
                            Wallet::new(txn.sender_key, "".to_owned()).address()
                        );
                        info!("Amount: {} AIO", avrio_core::account::to_dec(txn.amount));
                        info!("Timestamp: {}, Nonce: {}", txn.timestamp, txn.nonce);
                        info!(
                            "Block height: {}, Block Hash: {}",
                            blk.header.height, blk.hash
                        );
                        info!("From chain: {}", blk.header.chain_key);
                        info!("____________________________");
                    }
                }
            }
        } else if read == "get_account" {
            info!("Enter the public key of the account:");
            let addr: String = read!("{}\n");
            let wall = Wallet::new(addr.clone(), "".to_owned());
            let acc =
                avrio_core::account::getAccount(&wall.public_key)
                    .unwrap_or_default();
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
        }else {
            info!("Unknown command: {}", read);
        }
    }
}
