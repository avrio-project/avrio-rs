// Testnet one,
// This testnet foucouses on the P2p code, on launch a node will conect to the seed node(/s),
// get the peer list and connect to the other nodes on this peerlist. The node then registers. 
// 

use ring::{
    rand as randc,
    signature::{self, KeyPair},
};

use std::time::{SystemTime, UNIX_EPOCH};
use std::process;
use std::net::SocketAddr;

pub extern crate avrio_config;
use avrio_config::config;

extern crate avrio_core;
use avrio_core::
{
    transaction::
    {
        Transaction
    },
    certificate::
    {
        difficulty_bytes_as_u64, Certificate, generateCertificate, certificateErrors
    },
    gas::*,
    account::
    {
        Account, setAccount, getAccount, deltaFunds
    }
};

extern crate avrio_p2p;
use avrio_p2p::
{
    sync,
    sync_needed,
    new_connection,
    rec_server,
    prop_block 
};

extern crate avrio_blockchain;
use avrio_blockchain::*;

extern crate avrio_database;
use avrio_database::
{
    saveData,
    savePeerlist,
    getData
};

#[macro_use]
extern crate log;
extern crate simple_logger;

fn connectSeednodes(seednodes: Vec<SocketAddr>, connected_peers: Vec<SocketAd) -> u8 {
    let mut i: usize = 0;
    let mut conn_count:u8 = 0;
    while i < seednodes.iter.count() - 1 {
        let mut error: p2p_error = new_connection(seednodes[i]);
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
    let mut state = createFileStructure();
    if state != Ok(_) {
        error!("Failed to create  filestructure, recieved error: {:?}.  (Fatal). Try checking permissions.", state);
        process::exit(1); // Faling to create the file structure is fatal but probaly just a permisions error 
    } else {
        info!("Succsesfuly created filestructure");
    }
    drop(state);
    info!("Creating Chain for self");
    let mut chainKey = ["".to_String(); 2]; // 0 = pubkey, 1 = privkey
    generateKeypair(&mut chainKey);
    match chainKey[0] {
        "0" =>  { 
            error!("failed to create keypair (Fatal)");
            process::exit(1);
        },
        _ => info!("Succsessfully created keypair with chain key {}", chainKey[0]),
    }
    let mut genesis_block = avrio_core::getGenesisBlock(&chainKey[0]);
    if let Err(e) = genesis_block {
        if e == geneisBlockErrors::BlockNotFound {
            info!("No genesis block found for chain: {}, generating", chainKey[0]);
            genesis_block = generateGenesisBlock(chainKey[0].clone(), chainKey[1].clone());
        } else {
            error!("Database error occoured when trying to get genesisblock for chain: {}. (Fatal)", chainKey[0]);
            process::exit(1);
        }
    }
    match check_block(genesis_block) {
        Err(error) => { 
            error!("Failed to create/ get genesis block. Gave error: {:?}, block dump: {:?}. (Fatal)", error, genesis_block);
            process::exit(1);
        },
        _ => info!("Succsessfully generated/got genesis block with hash {}", genesis_block.hash),
    }
    let e_code = saveData(serde_json::to_string(&genesis_block.unwrap()), config().db_path + &"/".to_string() + chainKey[0], genesis_block.hash.clone());
    match e_code {
        1 => {
            info!("Sucsessfully saved genesis block!");
            drop(e_code);
        }
        _ => {
            error!("Failed to save genesis block with hash: {}, gave error code: {} (fatal)!", genesis_block.hash, e_code);
            process::exit(1);
        }
    };
    info!(" Launching P2p server on 127.0.0.1::{:?}", 11523); // Parsing config and having custom p2p ports to be added in 1.1.0 - 2.0.0
    match rec_server() {
        1 => {},
        _ => { 
            error!("Error launching P2p server on 127.0.0.1::{:?} (Fatal)", 11523);
            process::exit(1);
        },
    }
    let mut peerlist: Vec<SocketAddr>;
    let seednodes: Vec<SockerAddr> = vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
    ];
    let mut conn_nodes = 0;
    let trys: u8 = 0;
    while (conn_nodes < 1) {
        if trys > 49 {
            process::exit(1);
        }
        if trys > 0 {
            warn!("Failed to connect to any seednodes, retrying");
        }
        conn_nodes = connectSeednodes(seednodes);
        trys += 1;
    }
    info!("Connected to seednode(s), polling for peerlist (this may take some time)");
    drop(state);
    peerlist = getPeerList();
    conn_nodes += connectSeednodes(peerlist, connected_peers);
    info!("Started syncing");
    let mut sync = sync(connected_peers);
    info!("Generating Node Cerificate (for self)");
    // TODO: generate node certificate
    info!("Registering with network");
    // TODO: send the certificate to peers
    return 1;
}

fn send_block() { 
    // create block
            let transactions: Vec<transactions> = vec![
                //todo
            ];
            let new_block = Block
            {
                header: Header {
                    version_major: 0,
                    version_breaking: 0
                    version_minor: 0,
                    chain_key: chainKey[0],
                    prev_hash: getHashForHeight(height -1),
                    height: 1,
                    timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64,
                },
                txns: transactions,
                hash: String::from(""),
                signature: String::from(""),
            };
            new_block.hash = new_block.hash();
            new_block.signature = new_block.sign(private_key);
            let mut new_block_s: String = "".to_string();
            if check_block(new_block) {
                new_block_s = serde_json::to_string(&new_block).unwrap();
                new_block_s = new_block_s;
                let state = prop_block(&new_block_s);
                if state != Err(p2pError::none) { // there was an error
                    error!("Failed to propiagte block {:?}, encountered error: {:?}", new_block_s.hash, state); // tell them the error
                    error!("Block dump: non serilised {:?}, serilised {}", new_block, new_block_s); // now flood their eyes
                    process::exit(1);
                }
            }
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
    info!("Checking for previous startup. DO NOT CLOSE PROGRAM NOW!!!");
    let startup_state: u16 = match database_present() {
        true => existingStartup(),
        false => firstStartUp(),
    };
    let synced: bool = false;
    if startup_state == 1 { // succsess
        info!("Avrio Daemon succsessfully launched");
        match sync_needed() { // do we need to sync
            true => { 
                sync();
                info!("Successfully synced with the network!");
                synced = true;},
            false => { 
                info!("Succsessfully synced with the network!");
                synced = true;
            },
        }
    }else {
        error!("Failed to start avrio daemon (Fatal)");
        panic!();
    }
    if sync_needed == false // check in case a new block has been released since we syned 
    {
        send_block();
    } else 
    {
       match sync_needed() { // do we need to sync
            true =>  { 
                sync();
                info!("Successfully synced with the network!");
                synced = true;
                send_block();
           },
            false => {
                synced = true;
                send_block();
           },
       };
    }
}
