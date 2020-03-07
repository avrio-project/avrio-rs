// Testnet one,
// This testnet foucouses on the P2p code, on launch a node will conect to the seed node(/s),
// get the peer list and connect to the other nodes on this peerlist. Then every 5 mins they 
//generate a block and release it (to test the p2p propigation code). 

use std::net::SocketAddr
pub extern crate avrio_config;
use avrio_config::config;
pub extern crate avrio_core;
pub extern crate avrio_config;
pub extern crate avrio_p2p;
pub extern crate avrio_blockchain;
pub extern crate avrio_database;
extern crate simple_logger;
#[macro_use]
extern crate log;
use std::process;

fn connectSeednodes(seednodes: Vec<IpAddr::V4>) -> u8 {
    let mut i = 0;
    let mut conn_count = 0;
    while i < seednodes.iter.count() - 1 {
        let mut error: p2p_error = avrio_p2p::new_connection(seednodes[i]);
        match error {
            Ok(_) =>  { 
                info!("Connected and handshaked to {:?}::{:?}", seednode[i], 11523); 
                conn_count += 1;
            },
            _ => warn!("Failed to connect to {:?}:: {:?}, returned error {:?}", seednode[i], 11523, error),
        };
        i += 1;
    }
    return conn_count;
}
fn firstStartUp() -> u8 {
    info!("First startup detected, creating file structure");
    let mut state = database::createFileStructure();
    if state != Ok(_) {
        error!("Failed to create  filestructure, recieved error {:?}.  (Fatal) Try checking permissions.", state);
        process::exit(1); // Faling to create the file structure is fatal but probaly just a permisions error 
    } else {
        info!("Succsesfuly created filestructure");
    }
    drop(state);
    info!("Creating Chain for self");
    let mut chainKey = [""; 2]; // 0 = pubkey, 1 = privkey
    chainKey = generateKeypair();
    match chainKey[0] {
        "0" =>  { 
            error!("failed to create chain (Fatal)");
            process::exit(1);
        },
        _ => info!("Succsessfully created chain with chain key {}", chainKey[0]),
    }
    let genesis_block: Block = avrio_core::generateGenesisBlock(chainKey[0]);
    match avrio_blockchain::check_block(genesis_block) {
        Err(error) => { 
            error!("Failed to create genesis block gave error {:?}, block dump: {:?} (Fatal)", error, genesis_block);
            process::exit(1);
        },
        _ => info!("Succsessfully generated genesis block with hash {}", genesis_block.hash),
    }
    match avrio_database::saveData(serde_json::to_string(&genesis_block.unwrap()), config().db_path + &"/".to_string() + chainKey[0], genesis_block.hash.clone()) {
        1 => {
            info!("Sucsessfully saved genesis block!");
        }
        _ => {
            error!("Failed to save genesis block (fatal)!");
            process::exit(1);
        }
    };
    info!(" Launching P2p server on 127.0.0.1::{:?}", 11523); // Parsing config and having custom p2p ports to be added in 1.1.0 - 2.0.0
    match p2p::launchServer(11523) {
        0 => { error!("Error launching P2p server on 127.0.0.1::{:?} (Fatal)", 11523); panic!();},
        1 => info!("Launched P2p server on 127.0.0.1::{:?}" 11523),
    }
    let mut peerlist: Vec<SocketAddr>;
    let seednodes: Vec<SockerAddr> = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
    ];
    let mut conn_nodes =0;
    while (conn_nodes < 1) {
        warn!("Failed to connect to any seednodes, retrying");
        conn_nodes = connectSeednodes(seednodes);
    }
    info!("Connected to seednode(s), polling for peerlist (this may take some time)");
    drop(state);
    peerlist = p2p::getPeerList();
    conn_nodes += connectSeednodes(peerlist);
    info!("Started syncing");
    let mut sync = p2p::sync();
    info!("Generating Node Cerificate (for self)");
    // generate node certificate
    info!("Registering with network");
    return 1;
}

fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let art: String = "
   #    #     # ######  ### #######
  # #   #     # #     #  #  #     #
 #   #  #     # #     #  #  #     #
#     # #     # ######   #  #     #
#######  #   #  #   #    #  #     #
#     #   # #   #    #   #  #     #
#     #    #    #     # ### ####### ";
    println!("{}", art);
    info!("Avrio Daemon Testnet v1.0.0 (pre-alpha)");
    info!("Checking for previous startup");
    let startup_state: u16 = match database::database_present() {
        true => existingStartup(),
        false => firstStartUp(),
    };
    if startup_state == 1 { // succsess
        info!("Avrio Daemon succsessfully launched");
        match p2p::sync_needed() { // do we need to sync
            true => { p2p::sync(); println("[INFO] Successfully synced with the network!"); synced = true;},
            false => { println("[INFO] Succsessfully synced with the network!"); synced = true;},
        }
    }else {
        error!("Failed to start avrio daemon (Fatal)");
        panic!();
    }
    if p2p::sync_needed == false // check in case a new block has been released since we syned 
    {
        if p2p::message_buffer.len() != 0 {
            handle_new_messages(message_buffer);
        } else {
        // create block
            let new_block = Block
            {
                header: Header {
                    version_major: 0,
                    version_minor: 0,
                    chain_key: chainKey,
                    prev_hash: hex::encode(get_last_blockhash(chainKey)),
                    height: 0,
                    timestamp: 0,
                },
                txns: blank_txn,
                hash: String::from(""),
                signature: String::from(""),
            };
            new_block.hash = new_block.hash();
            new_block.signature = new_block.sign(private_key, new_block.hash);
            let mut new_block_s: String;
            if blockchain::check_block(new_block) {
                new_block_s = serde_json::to_string(&new_block).unwrap();
                new_block_s = hex::encode(new_block_s);
                let state = p2p::send_to_all(&new_block_s);
                if state != Err(p2pError::none) { // there was an error
                    error!("Failed to propiagte block {:?}, encountered error: {:?}", new_block_s, state); // tell them the error
                    error!("Block dump: non serilised {:?}, hex encoded serilised {:?}, hex decoded serilised {:?}", new_block, new_block_s, hex::decode(new_block_s)); // now flood their eyes with hex 
                }
            }
        }
   }else {
       match p2p::sync_needed() { // do we need to sync
            true =>  { p2p::sync(); println("[INFO] Successfully synced with the network!"); synced = true;},
            false => { println("[INFO] Succsessfully synced with the network!"); synced = true;},
        }
  }
}
