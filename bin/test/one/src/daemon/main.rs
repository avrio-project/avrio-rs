extern crate avrio_blockchain;
pub extern crate avrio_config;
extern crate avrio_core;
extern crate avrio_crypto;
extern crate avrio_database;
extern crate clap;
extern crate hex;
extern crate simple_logger;

#[macro_use]
extern crate log;

use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use clap::{App, Arg};
use std::fs::create_dir_all;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use text_io::read;

use avrio_blockchain::{
    genesis::{generateGenesisBlock, genesisBlockErrors, genesis_blocks, getGenesisBlock},
    *,
};
use avrio_config::{config, Config};
use avrio_core::{account::to_atomc, transaction::Transaction};
use avrio_crypto::Wallet;
use avrio_database::{get_data, get_iterator, get_peerlist, open_database, save_data};
use avrio_p2p::{core::new_connection, core::rec_server, helper::prop_block, helper::sync};
use avrio_api::start_server;




fn connect_seednodes(
    seednodes: Vec<SocketAddr>,
    connected_peers: &mut Vec<TcpStream>,
) -> Vec<SocketAddr> {
    let mut conns: Vec<SocketAddr> = vec![];

    for peer in seednodes {
        let error = new_connection(&peer.to_string());

        match error {
            Ok(_) => {
                info!("Connected to {:?}::{:?}", peer, 11523);
                conns.push(peer);
                connected_peers.push(error.unwrap());
            }

            _ => warn!(
                "Failed to connect to {:?}:: {:?}, returned error {:?}",
                peer, 11523, error
            ),
        };
    }

    return conns;

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

    Ok(())
}

fn database_present() -> bool {
    let get_res = get_data(
        config().db_path + &"/chains/masterchainindex".to_owned(),
        &"digest".to_owned(),
    );

    if get_res == "-1".to_owned() {
        false
    } else if get_res == "0".to_string() {
        false
    } else {
        true
    }
}

fn create_file_structure() -> std::result::Result<(), Box<dyn std::error::Error>> {
    create_dir_all(config().db_path + &"/blocks".to_string())?;
    create_dir_all(config().db_path + &"/chains".to_string())?;
    create_dir_all(config().db_path + &"/wallets".to_string())?;
    create_dir_all(config().db_path + &"/accounts".to_string())?;
    create_dir_all(config().db_path + &"/usernames".to_string())?;

    Ok(())
}

pub fn safe_exit() {
    // TODO: save mempool to disk + send kill to all threads.

    info!("Good bye!");

    avrio_p2p::core::close_all();
    std::process::exit(0);
}

fn save_wallet(keypair: &Vec<String>) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut conf = config();
    let path = conf.db_path.clone() + &"/wallets/".to_owned() + &keypair[0];

    if conf.wallet_password == Config::default().wallet_password {
        warn!("Your wallet password is set to default, please change this password and run avrio daemon with --change-password-from-default <newpassword>");
    }

    let mut padded_password_bytes = conf.wallet_password.as_bytes().to_vec();

    while padded_password_bytes.len() != 32 && padded_password_bytes.len() < 33 {
        padded_password_bytes.push(b"n"[0]);
    }

    let padded_password = String::from_utf8(padded_password_bytes).unwrap();
    let key = GenericArray::clone_from_slice(padded_password.as_bytes());
    let password_key = Aes256Gcm::new(key);

    let mut padded_nonce_bytes = b"nonce".to_vec();

    while padded_nonce_bytes.len() != 12 {
        padded_nonce_bytes.push(b"n"[0]);
    }

    let padded_string = String::from_utf8(padded_nonce_bytes).unwrap();
    let nonce = GenericArray::from_slice(padded_string.as_bytes()); // 96-bits; unique per message

    let publickey_en = hex::encode(
        password_key
            .encrypt(nonce, keypair[0].as_bytes().as_ref())
            .expect("wallet public key encryption failure!"),
    );

    let privatekey_en = hex::encode(
        password_key
            .encrypt(nonce, keypair[1].as_bytes().as_ref())
            .expect("wallet private key encryption failure!"),
    );

    let _ = save_data(publickey_en, path.clone(), "pubkey".to_owned());
    let _ = save_data(privatekey_en, path.clone(), "privkey".to_owned());

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

    let _ = conf.create();
}

fn open_wallet(key: String, address: bool) -> Wallet {
    let wallet: Wallet;

    if address == true {
        wallet = Wallet::from_address(key);
    } else {
        wallet = Wallet::new(key, "".to_owned());
    }

    // TODO: use unique nonce
    let mut padded_password_bytes = config().wallet_password.as_bytes().to_vec();

    while padded_password_bytes.len() != 32 && padded_password_bytes.len() < 33 {
        padded_password_bytes.push(b"n"[0]);
    }

    let padded_password = String::from_utf8(padded_password_bytes).unwrap();
    let password = GenericArray::clone_from_slice(padded_password.as_bytes());
    let password_key = Aes256Gcm::new(password);

    let mut padded_nonce_bytes = b"nonce".to_vec();

    while padded_nonce_bytes.len() != 12 {
        padded_nonce_bytes.push(b"n"[0]);
    }

    let padded_nonce = String::from_utf8(padded_nonce_bytes).unwrap();
    let nonce = GenericArray::from_slice(padded_nonce.as_bytes()); // 96-bits; unique per message

    let ciphertext = hex::decode(get_data(
        config().db_path + &"/wallets/".to_owned() + &wallet.public_key,
        &"privkey".to_owned(),
    ))
    .expect("failed to parse hex");

    let privkey = String::from_utf8(
        password_key
            .decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!"),
    )
    .expect("failed to parse utf8 (i1)");

    Wallet::from_private_key(privkey)
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
                .takes_value(true)
                .help("Sets the level of verbosity: 0: Error, 1: Warn, 2: Info, 3: debug"),
        )
        .get_matches();

    match matches.value_of("loglev").unwrap_or(&"2") {
        "0" => simple_logger::init_with_level(log::Level::Error).unwrap(),
        "1" => simple_logger::init_with_level(log::Level::Warn).unwrap(),
        "2" => simple_logger::init_with_level(log::Level::Info).unwrap(),
        "3" => simple_logger::init_with_level(log::Level::Debug).unwrap(),
        "4" => simple_logger::init_with_level(log::Level::Trace).unwrap(),
        _ => {
            println!("Unknown log-level: {} ", matches.occurrences_of("loglev"));
            println!("Supported levels: 0: Error, 1: Warn, 2: Info, 3: Debug, 4: Trace");

            std::process::exit(1);
        }
    }

    let mut chain_key: Vec<String> = vec![]; // 0 = pubkey, 1 = privkey
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

    let conf = config();
    conf.create().unwrap();


    info!("Launching API server");

    let _api_server_handle = thread::spawn(|| {
        start_server();
    });

    let mut synced: bool = true;

    if !database_present() {
        create_file_structure().unwrap();
    }

    if config().chain_key == "".to_owned() {
        generate_chains().unwrap();

        let chain_digest: String = generate_merkle_root_all().unwrap_or_default();

        info!("Chain digest: {}", chain_digest);
    }

    info!("Launching P2P server on 0.0.0.0:{}", config().p2p_port);

    let _p2p_handler = thread::spawn(|| {
        if let Err(e) = rec_server(&format!("{}:{}", config().ip_host, config().p2p_port)) {
            error!(
                "Error: {} while launching P2P server on 0.0.0.0:{} (Fatal)",
                e,
                config().p2p_port
            );

            process::exit(1);
        }
    });

    let mut pl: Vec<SocketAddr> = get_peerlist().unwrap_or_default();

    if pl.len() < 1 {
        let seednodes: Vec<SocketAddr> = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            56788,
        )];

        for node in seednodes {
            pl.push(node);
        }
    }

    let mut connections: Vec<TcpStream> = vec![];

    let connected_addrs = connect_seednodes(pl.clone(), &mut connections);

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

    for peer in new_peers {
        pl.push(peer);
    }

    let deduplicated_peerlist: std::collections::HashSet<_> = pl.drain(..).collect(); // dedup
    pl.extend(deduplicated_peerlist.into_iter());

    for peer in pl {
        if !connected_addrs.contains(&peer) {
            info!("Connecting to new peer {}", peer);
            let _ = new_connection(&peer.to_string());
        } else {
            debug!("Not connecting to {}; Already connected", peer);
        }
    }

    let needs_sync = avrio_p2p::helper::sync_needed();

    match needs_sync {
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

    if synced == true {
        info!("Your avrio daemon is now synced and up to date with the network!");
    } else {
        return ();
    }

    let wallet: Wallet;

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

        let genesis_block_saving_result = saveBlock(genesis_block_clone.clone());

        match genesis_block_saving_result {
            Ok(_) => {
                info!("Sucessfully saved genesis block!");

                drop(genesis_block_saving_result);
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

        let _ = prop_block(&genesis_block_clone).unwrap();

        info!("Sent block to network");

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

        wallet = Wallet::from_private_key(chain_key[1].clone());
    } else {
        info!("Using chain: {}", config().chain_key);

        wallet = open_wallet(config().chain_key, false);
    }

    info!(
        "Transaction count for our chain: {}",
        avrio_database::get_data(
            config().db_path
                + &"/chains/".to_owned()
                + &wallet.public_key
                + &"-chainindex".to_owned(),
            &"txncount".to_owned(),
        )
    );

    let our_account = avrio_core::account::getAccount(&wallet.public_key).unwrap();

    info!("Our balance: {}", our_account.balance_ui().unwrap());

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
                sender_key: wallet.public_key.clone(),
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

            info!("Please enter the receiver address or username:");

            let receiver_address: String = read!();
            let receiver_wall;

            if avrio_crypto::valid_address(&receiver_address) {
                receiver_wall = Wallet::from_address(receiver_address);
            } else {
                receiver_wall = Wallet::new(
                    avrio_core::account::getByUsername(&receiver_address)
                        .unwrap()
                        .public_key,
                    "".to_owned(),
                );
            }

            txn.receive_key = receiver_wall.public_key;

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

            let _ = txn.sign(&wallet.private_key);
            let inv_db = open_database(
                config().db_path
                    + &"/chains/".to_string()
                    + &wallet.public_key
                    + &"-chainindex".to_string(),
            )
            .unwrap();

            let mut inv_iter = get_iterator(&inv_db);
            let mut highest_so_far: u64 = 0;

            inv_iter.seek_to_first();

            while inv_iter.valid() {
                if let Ok(height) = String::from_utf8(inv_iter.key().unwrap().into())
                    .unwrap()
                    .parse::<u64>()
                {
                    if height > highest_so_far {
                        highest_so_far = height
                    }
                }

                inv_iter.next();
            }

            drop(inv_iter);
            drop(inv_db);

            let height: u64 = highest_so_far;
            let mut blk = Block {
                header: Header {
                    version_major: 0,
                    version_breaking: 0,
                    version_minor: 0,
                    chain_key: wallet.public_key.clone(),
                    prev_hash: getBlock(&wallet.public_key, height).hash,
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

            let _ = blk.sign(&wallet.private_key);
            let _ = check_block(blk.clone()).unwrap();
            let _ = saveBlock(blk.clone()).unwrap();
            let _ = prop_block(&blk).unwrap();

            // now for each txn to a unique receiver form the rec block of the block we just formed and prob + enact that
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
                }
            }

            // all done

            let our_account = avrio_core::account::getAccount(&wallet.public_key).unwrap();

            info!(
                "Transaction sent! Hash: {}, Block hash: {}, New balance: {} AIO",
                blk.txns[0].hash,
                blk.hash,
                our_account.balance_ui().unwrap()
            );
        } else if read == "get_balance" {
            info!(
                "Your balance: {} AIO",
                avrio_core::account::getAccount(&wallet.public_key)
                    .unwrap()
                    .balance_ui()
                    .unwrap_or_default()
            );
        } else if read == "get_address" {
            info!("Your wallet address is: {}", wallet.address());
        } else if read == "exit" {
            safe_exit();
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
            error!("This doesn't work yet, make sure to keep an eye out for announcements by the developers!");
        } else if read == "get_block" {
            info!("Enter block hash:");

            let hash: String = read!("{}\n");
            let block: Block = getBlockFromRaw(hash);

            if block == Block::default() {
                error!("Couldn't find a block with that hash!");
            } else {
                info!("{:#?}", block);
            }
        } else if read == "get_transaction" {
            info!("Enter the transaction hash:");

            let hash: String = read!("{}\n");
            let raw_block = get_data(config().db_path + &"/transactions".to_owned(), &hash);

            if raw_block == "-1".to_owned() {
                error!("Couldn't find that transaction in the database!");
            } else {
                let block: Block = getBlockFromRaw(raw_block);

                if block == Block::default() {
                    error!("Couldn't find a block that contains this transaction!");
                } else {
                    for txn in block.txns {
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
                                block.header.height, block.hash
                            );
                            info!("From chain: {}", block.header.chain_key);
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

            if amount > 0 && amount < 15 {
                warn!("This will be very slow, especially on HDD. Continue? (Y/N)");

                let confirmation: String = read!();

                if confirmation.to_uppercase() == "Y".to_owned() {
                    info!("Enter the number of transactions per block (max 100):");

                    let transaction_amount: u64 = read!("{}\n");

                    if transaction_amount > 100 || transaction_amount == 1 {
                        error!("Transaction amount must be beetween (or equal to) 1 and 100");
                    } else {
                        info!(
                            "Generating {} blocks with {} txns in each",
                            amount, transaction_amount
                        );

                        let mut current_block: u64 = 0;

                        while current_block < amount {
                            let mut current_transaction: u64 = 0;
                            let mut txns: Vec<Transaction> = vec![];

                            while current_transaction < transaction_amount {
                                let mut txn = Transaction {
                                    hash: String::from(""),
                                    amount: 100,
                                    extra: String::from(""),
                                    flag: 'n',
                                    sender_key: wallet.public_key.clone(),
                                    receive_key: wallet.public_key.clone(),
                                    access_key: String::from(""),
                                    gas_price: 100,
                                    max_gas: 100,
                                    gas: 20,
                                    nonce: avrio_database::get_data(
                                        config().db_path
                                            + &"/chains/".to_owned()
                                            + &wallet.public_key.clone()
                                            + &"-chainindex".to_owned(),
                                        &"txncount".to_owned(),
                                    )
                                    .parse()
                                    .unwrap(),
                                    unlock_time: 0,
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .expect("Time went backwards")
                                        .as_millis()
                                        as u64,
                                    signature: String::from(""),
                                };

                                txn.hash();
                                txn.sign(&wallet.private_key).unwrap();
                                txns.push(txn);

                                current_transaction += 1;

                                info!("txn {}/{}", current_transaction, transaction_amount);
                            }

                            // TODO: FIX!!

                            let inv_db = open_database(
                                config().db_path
                                    + &"/chains/".to_string()
                                    + &wallet.public_key
                                    + &"-chainindex".to_string(),
                            )
                            .unwrap();

                            let mut inv_iter = get_iterator(&inv_db);
                            let mut highest_so_far: u64 = 0;

                            inv_iter.seek_to_first();

                            while inv_iter.valid() {
                                if let Ok(height) =
                                    String::from_utf8(inv_iter.key().unwrap().into())
                                        .unwrap()
                                        .parse::<u64>()
                                {
                                    if height > highest_so_far {
                                        highest_so_far = height
                                    }
                                }

                                inv_iter.next();
                            }

                            let height: u64 = highest_so_far;

                            drop(inv_iter);
                            drop(inv_db);

                            let mut blk = Block {
                                header: Header {
                                    version_major: 0,
                                    version_breaking: 0,
                                    version_minor: 0,
                                    chain_key: wallet.public_key.clone(),
                                    prev_hash: getBlock(&wallet.public_key, height).hash,
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

                            let _ = blk.sign(&wallet.private_key);
                            let _ = check_block(blk.clone()).unwrap();
                            let _ = saveBlock(blk.clone()).unwrap();
                            let _ = prop_block(&blk).unwrap();

                            // now for each txn to a unique receiver form the rec block of the block we just formed and prob + enact that
                            let processed_accounts: Vec<String> = vec![];

                            for txn in &blk.txns {
                                if !processed_accounts.contains(&txn.receive_key) {
                                    let rec_blk = blk
                                        .form_receive_block(Some(txn.receive_key.to_owned()))
                                        .unwrap();

                                    let _ = check_block(rec_blk.clone()).unwrap();
                                    let _ = saveBlock(rec_blk.clone()).unwrap();
                                    let _ = prop_block(&rec_blk).unwrap();
                                    let _ = enact_block(rec_blk.clone()).unwrap();
                                }
                            }

                            // all done

                            current_block += 1;
                        }

                        let our_account =
                            avrio_core::account::getAccount(&wallet.public_key).unwrap();

                        info!(
                            "Blocks sent! Our new balance: {} AIO",
                            our_account.balance_ui().unwrap()
                        );
                    }
                }
            } else {
                error!("The amount must be between 1 and 15!");
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
                sender_key: wallet.public_key.clone(),
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

            txn.receive_key = wallet.public_key.clone();

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

            let _ = txn.sign(&wallet.private_key);

            let inv_db = open_database(
                config().db_path
                    + &"/chains/".to_string()
                    + &wallet.public_key
                    + &"-chainindex".to_string(),
            )
            .unwrap();

            let mut inv_iter = get_iterator(&inv_db);
            let mut highest_so_far: u64 = 0;

            inv_iter.seek_to_first();

            while inv_iter.valid() {
                if let Ok(height) = String::from_utf8(inv_iter.key().unwrap().into())
                    .unwrap()
                    .parse::<u64>()
                {
                    if height > highest_so_far {
                        highest_so_far = height
                    }
                }

                inv_iter.next();
            }

            drop(inv_iter);
            drop(inv_db);

            let height: u64 = highest_so_far;

            let mut blk = Block {
                header: Header {
                    version_major: 0,
                    version_breaking: 0,
                    version_minor: 0,
                    chain_key: wallet.public_key.clone(),
                    prev_hash: getBlock(&wallet.public_key, height).hash,
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

            let _ = blk.sign(&wallet.private_key);
            let _ = check_block(blk.clone()).unwrap();
            let _ = saveBlock(blk.clone()).unwrap();
            let _ = prop_block(&blk).unwrap();

            // now for each txn to a unique receiver form the rec block of the block we just formed and prob + enact that
            let processed_accounts: Vec<String> = vec![];

            for txn in &blk.txns {
                if !processed_accounts.contains(&txn.receive_key) {
                    let rec_blk = blk
                        .form_receive_block(Some(txn.receive_key.to_owned()))
                        .unwrap();

                    let _ = check_block(rec_blk.clone()).unwrap();
                    let _ = saveBlock(rec_blk.clone()).unwrap();
                    let _ = prop_block(&rec_blk).unwrap();
                    let _ = enact_block(rec_blk.clone()).unwrap();
                }
            }

            // all done

            let out_account = avrio_core::account::getAccount(&wallet.public_key).unwrap();

            info!(
                "Transaction sent! Txn hash: {}, Our new balance: {} AIO",
                blk.txns[0].hash,
                out_account.balance_ui().unwrap()
            );
        } else if read == "register_username".to_owned() {
            info!("Please enter the username you would like to register:");

            let username: String = read!("{}\n");

            if let Ok(_) = avrio_core::account::getByUsername(&username) {
                error!("That username is already registered, please try another");
            } else {
                let acc = avrio_core::account::getAccount(&wallet.public_key).unwrap_or_default();

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
                            sender_key: wallet.public_key.clone(),
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

                        txn.receive_key = wallet.public_key.clone();

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

                        let _ = txn.sign(&wallet.private_key);

                        let inv_db = open_database(
                            config().db_path
                                + &"/chains/".to_string()
                                + &wallet.public_key
                                + &"-chainindex".to_string(),
                        )
                        .unwrap();

                        let mut inv_iter = get_iterator(&inv_db);
                        let mut highest_so_far: u64 = 0;

                        inv_iter.seek_to_first();

                        while inv_iter.valid() {
                            if let Ok(height) = String::from_utf8(inv_iter.key().unwrap().into())
                                .unwrap()
                                .parse::<u64>()
                            {
                                if height > highest_so_far {
                                    highest_so_far = height
                                }
                            }

                            inv_iter.next();
                        }

                        drop(inv_iter);
                        drop(inv_db);

                        let height: u64 = highest_so_far;

                        let mut blk = Block {
                            header: Header {
                                version_major: 0,
                                version_breaking: 0,
                                version_minor: 0,
                                chain_key: wallet.public_key.clone(),
                                prev_hash: getBlock(&wallet.public_key, height).hash,
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

                        let _ = blk.sign(&wallet.private_key);
                        let _ = check_block(blk.clone()).unwrap();
                        let _ = saveBlock(blk.clone()).unwrap();
                        let _ = prop_block(&blk).unwrap();

                        // now for each txn to a unique receiver form the rec block of the block we just formed and prob + enact that
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
                            }
                        }

                        // all done
                        let our_account = avrio_core::account::getAccount(&wallet.public_key).unwrap();

                        info!(
                            "Transaction sent! Txn hash: {}, Our new balance: {} AIO",
                            blk.txns[0].hash,
                            our_account.balance_ui().unwrap()
                        );
                    }
                }
            }
        } else {
            info!("Unknown command: {}", read);
        }
    }
}
