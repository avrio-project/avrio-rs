#[macro_use]
extern crate log;
#[macro_use]
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate unwrap;
extern crate avrio_blockchain;
extern crate avrio_config;
extern crate avrio_database;
use avrio_blockchain::{getBlockFromRaw, Block};
use avrio_config::config;
use avrio_core::epoch::Epoch;
use avrio_database::{getData, getIter, openDb, saveData};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process;
use std::str;
use std::thread;
extern crate hex;
use std::collections::HashMap;
use std::error::Error;
extern crate simple_logger;

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct Inventory {
    chain: String,
    hash: String,
    height: u64,
    timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct P2pdata {
    pub message_bytes: usize, // The length in bytes of message
    pub message_type: u16,    // The type of data
    pub message: String,      // The serialized data
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Peer {
    pub id: String,
    pub socket: SocketAddr, // socket (ip, port) of a peer
    pub info: PeerTracker,  // stats about recived and sent bytes from this peer
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Tracker {
    pub sent_bytes: u32,
    pub received_bytes: u32,
    pub peers: u32,
    pub uptime: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PeerTracker {
    pub sent_bytes: u32,
    pub recieved_bytes: u32,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct GetInventories {
    pub amount: u8,   // The amount of inventories to send back, max is 128
    pub from: String, // hash (or 00000000000 for ignore)
    pub to: String,   // hash (or 00000000000 for ignore)
}
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct GetBlocks {
    pub amount: u8,   // The amount of inventories to send back, max is 128
    pub from: String, // hash (or 00000000000 for ignore)
    pub to: String,   // hash (or 00000000000 for ignore)
}

/* TODO */
fn sendInventories(
    from: String,
    to: String,
    peer: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let firstInventory = getBlockFromRaw(from);
    let lastInventory = getBlockFromRaw(to);
    if firstInventory == Block::default() || lastInventory == Block::default() {
        return Err("err".into());
    } else {
        if let Ok(db) = openDb(config().db_path + &"/chains".to_owned()) {
            let mut iter = db.raw_iterator();
            iter.seek_to_first();
            while iter.valid() {
                let mut curr_chain = "".to_owned();
                if let Some(chain) = iter.value() {
                    if let Ok(chain_string) = String::from_utf8(chain) {
                        curr_chain = chain_string;
                    } else {
                        warn!("Found corrupted chain at key: {}", String::from_utf8(iter.key().unwrap_or(b"error getting index".to_owned().to_vec())).unwrap_or("error getting index".to_owned()));
                    }
                }
                println!("Saw {:?} {:?}", iter.key(), iter.value());
                iter.next();
            }
        }
        return Ok(());
    }
}
fn sendBlocks(from: String, to: String, peer: TcpStream) -> Result<(), std::io::Error> {
    return Ok(());
}
/* TODO end*/
pub fn syncack_peer(peer: &mut TcpStream) -> Result<TcpStream, Box<dyn Error>> {
    let mut peer_to_use_unwraped = peer.try_clone().unwrap();
    let syncreqres = sendData(
        "syncreq".to_string(),
        &mut peer_to_use_unwraped.try_clone().unwrap(),
        0x01,
    );
    match syncreqres {
        Ok(()) => {}
        Err(e) => {
            error!("Failed to end syncreq message to peer, gave error: {}. Check your internet connection and ensure port is not in use!", e);
            return Err("failed to send syncreq".into());
        }
        _ => {
            // i dont think this is possable but cargo wants it :)
            error!("Failed to end syncreq message to peer, gave a undefined error. Check your internet connection and ensure port is not in use! If you get this error the developers have proabably messed up!");
            return Err("failed to send syncreq, undefined error".into());
        }
    };
    let mut buf = [0; 1024];
    let mut no_read = true;
    while no_read == true {
        if let Ok(a) = peer_to_use_unwraped.try_clone().unwrap().peek(&mut buf) {
            if a == 0 {
            } else {
                no_read = false;
            }
        }
    }
    // There are now bytes waiting in the stream
    let _ = peer_to_use_unwraped.try_clone().unwrap().read(&mut buf);
    let mut _reselect_needed = false;
    let deformed: P2pdata =
        serde_json::from_str(&String::from_utf8(buf.to_vec()).unwrap_or("".to_string()))
            .unwrap_or(P2pdata::default());
    if deformed.message == "syncack".to_string() {
        debug!("Got syncack from selected peer. Continuing");
        return Ok(peer_to_use_unwraped);
    } else if deformed.message == "syncdec".to_string() {
        info!("Peer rejected sync request, choosing new peer...");
        // choose the next fasted peer from our socket list
        return Err("rejected syncack".into());
    } else {
        info!("Recieved incorect message from peer (in context syncrequest). Message: {}. This could be caused by outdated software - check you are up to date!", deformed.message);
        info!("Treating message aschainDigests sync decline, choosing new peer...");
        // choose the next fasted peer from our socket list
        return Err("assumed rejected syncack".into());
    }
}

fn getChainDigest(peer: &mut TcpStream) -> ChainDigestPeer {
    let mut i: i32 = 0;
    loop {
        let mut buffer = [0; 128];
        let e_r = peer.read(&mut buffer);
        if let Err(e) = e_r {
            if i >= 5 {
                let peer_n = peer.try_clone();
                if let Ok(peerNew) = peer_n {
                    break ChainDigestPeer {
                        digest: "".to_string(),
                        peer: Some(peerNew),
                    };
                } else {
                    break ChainDigestPeer {
                        digest: "".to_string(),
                        peer: None,
                    };
                }
            }
            i += 1;
            continue;
        } else {
            let peer_n = peer.try_clone();
            if let Ok(peerNew) = peer_n {
                break ChainDigestPeer {
                    peer: Some(peerNew),
                    digest: String::from_utf8(buffer.to_vec())
                        .unwrap_or_else(|e| return "".to_string()),
                };
            } else {
                break ChainDigestPeer {
                    digest: "".to_string(),
                    peer: None,
                };
            }
        }
    }
}

fn get_mode(v: Vec<String>) -> String {
    let mut map = HashMap::new();
    for num in v {
        let count = map.entry(num).or_insert(0);
        *count += 1;
    }
    return (**map.iter().max_by_key(|(_, v)| *v).unwrap().0).to_string();
}
#[derive(Debug, Default)]
pub struct ChainDigestPeer {
    pub peer: Option<TcpStream>,
    pub digest: String,
}

pub fn sync(pl: &mut Vec<&mut TcpStream>) -> Result<u64, String> {
    let mut peers: Vec<TcpStream> = vec![];
    let mut pc: u32 = 0;
    let mut i: usize = 0;
    for i in 0..pl.len() {
        let res = sendData("getChainDigest".to_string(), &mut pl[i], 0x01);
        match res {
            Ok(_) => {
                let mut peer_copy = pl[i].try_clone();
                if let Ok(mut np) = peer_copy {
                    peers.push(np);
                    pc += 1;
                }
            }
            Err(e) => {}
        }
    }
    trace!("Sent getChainDigest to {} peers", pc);
    let mut chainDigests: Vec<ChainDigestPeer> = vec![];
    let empty_string = "".to_string();
    for peer in peers.iter_mut() {
        if let Ok(mut peer_new) = peer.try_clone() {
            let handle = thread::Builder::new()
                .name("getChainDigest".to_string())
                .spawn(move || {
                    let chainDigest = getChainDigest(&mut peer_new);
                    match chainDigest.digest {
                        empty_string => {
                            return ChainDigestPeer {
                                peer: Some(peer_new),
                                digest: "".to_string(),
                            };
                        }
                        _ => {
                            return chainDigest;
                        }
                    };
                });
            if let Ok(handle_) = handle {
                if let Ok(result) = handle_.join() {
                    chainDigests.push(result);
                }
            }
        }
    }
    let mut hashes: Vec<String> = vec![];
    let chainDigestsLen = chainDigests.len();
    for hash in chainDigests.iter() {
        hashes.push(hash.digest.clone());
    }
    let mode_hash = get_mode(hashes);
    let mut peer_to_use: Option<TcpStream> = None;
    let mut i: u64 = 0;
    for i in 0..chainDigests.len() {
        if chainDigests[i].digest == mode_hash {
            if let Some(peer_) = &chainDigests[i].peer {
                peer_to_use = Some(peer_.try_clone().unwrap());
            }
        }
    }
    let mut peer_to_use_unwraped: TcpStream = peer_to_use.unwrap().try_clone().unwrap();
    let try_ack = syncack_peer(&mut peer_to_use_unwraped.try_clone().unwrap());
    if let Ok(stream) = try_ack {
        peer_to_use_unwraped = stream;
    } else {
        let mut lastpeer: &TcpStream = &(peer_to_use_unwraped.try_clone().unwrap());
        loop {
            let mut peer_to_use: Option<TcpStream> = None;
            let mut i: u64 = 0;
            for mut i in 0..chainDigestsLen {
                if chainDigests[i].digest == mode_hash {
                    if let Some(peer_) = &chainDigests[i].peer {
                        if peer_.peer_addr().unwrap() == lastpeer.peer_addr().unwrap() {
                            i += 1;
                            lastpeer = peer_;
                            continue;
                        }
                        peer_to_use = Some(peer_.try_clone().unwrap());
                    }
                }
            }
            let mut peer_to_use_unwraped: TcpStream;
            let try_ack = syncack_peer(&mut peer_to_use.unwrap().try_clone().unwrap());
            if let Ok(stream) = try_ack {
                peer_to_use_unwraped = stream;
                break;
            } else {
                i += 1;
                if i >= chainDigestsLen as u64 {
                    break;
                }
                continue;
            }
        }
    }
    let mut inventorys_to_ignore: Vec<String> = vec![];
    // now we need to get the last time we were fully synced - if ever - so we know where to sync from
    let mut last_hash_fully_synced = "0000000000".to_string();
    let mut chainsindex = "0000000000".to_string();
    let mut amount_synced: u64 = 0;
    let mut amount_to_sync: u64 = 0;
    let get_ci_res = getData(
        config().db_path + &"/chainindex".to_owned(),
        "lastsyncedepoch".to_owned(),
    );
    if get_ci_res == "-1".to_owned() {
        // the db is likley corupted, we will resync
        warn!("Failed to get last synced epoch from chains state db, probably corupted. Syncing from zero...");
    } else if get_ci_res == "0" {
        info!("First time sync detected.");
    } else {
        let res = getData(config().db_path + &"/epochs".to_owned(), get_ci_res.clone());
        if res == "-1".to_owned() || res == "0".to_owned() {
            warn!("Failed to epoch number for hash: {} from epoches db, probably corupted. Syncing from zero...", get_ci_res);
        } else if res == "0".to_owned() {
            warn!("Cant find epoch with hash: {} in epoches db. probably a result of a terminated sync", get_ci_res);
        } else {
            let epoch: Epoch = Epoch::default();
        }
        let from_hash: String = "".to_owned();

        info!(
            "Last synced epoch: {}. Syncing from block hash: {}",
            get_ci_res, from_hash
        );
    }
    let _ = sendData(
        "".to_string(),
        &mut peer_to_use_unwraped.try_clone().unwrap(),
        0x45,
    );
    let mut buf = [0; 1024];
    let mut no_read = true;
    while no_read == true {
        if let Ok(a) = peer_to_use_unwraped.try_clone().unwrap().peek(&mut buf) {
            if a == 0 {
            } else {
                no_read = false;
            }
        }
    }
    // There are now bytes waiting in the stream
    let _ = peer_to_use_unwraped.try_clone().unwrap().read(&mut buf);
    let mut _reselect_needed = false;
    let deformed: P2pdata =
        serde_json::from_str(&String::from_utf8(buf.to_vec()).unwrap_or("".to_string()))
            .unwrap_or(P2pdata::default());
    if deformed.message_type != 0x46 {
        amount_to_sync = 0;
    } else {
        amount_to_sync = deformed.message.parse().unwrap();
    }
    let mut print_synced_every: u64;
    match amount_to_sync {
        0..=100 => print_synced_every = 10,
        100..=500 => print_synced_every = 50,
        500..=1000 => print_synced_every = 100,
        1000..=10000 => print_synced_every = 500,
        10000..=50000 => print_synced_every = 2000,
        _ => print_synced_every = 5000,
    }
    let mut inventories_downloaded = false;
    loop {
        // until we break out of the loop we are syncing inventories
        let peer_to_use_clone = Some((peer_to_use_unwraped.try_clone()).unwrap());
        if let Some(mut peer_to_poll) = peer_to_use_clone {
            let mut peer = peer_to_poll.try_clone().unwrap();
            let mut chainsindex = getData(
                config().db_path + &"/chainindexmaster".to_string(),
                "topblockhash".to_string(),
            );
            if chainsindex == "-1".to_string() || chainsindex == "0".to_string() {
                // we are probably a new startup and so have no blocks
                chainsindex = "0".to_string();
            }
            let getInventoriesMsg: GetInventories = GetInventories {
                amount: 128,
                from: chainsindex,
                to: "0000000000".to_string(),
            };
            let gims: String = // gims stands for getInventoriesMsgSerilized
                serde_json::to_string(&getInventoriesMsg).unwrap_or("err".to_string());
            if gims == "err".to_string() {
                // retry
                let gims = serde_json::to_string(&getInventoriesMsg).unwrap_or("err".to_string());
                if gims == "err".to_string() {
                    break; // syncing failed :(
                }
            }
            let result = sendData(gims, &mut peer, 0x04);
            if let Err(_) = result {
                //try again
                let result_again = sendData("0".to_string(), &mut peer, 0x04);
                if let Err(e_again) = result_again {
                    debug!(
                        "Failed to send message: {}, to peer. Gave error:{}",
                        "0", e_again
                    );
                    error!("Syncing Failed. Try restarting your node and ensure you are connected to internet!");
                    break;
                }
            }
            let mut buf = [0; 1024];
            let mut no_read = true;
            while no_read == true {
                if let Ok(a) = peer_to_poll.peek(&mut buf) {
                    if a == 0 {
                        no_read = true;
                    } else {
                        no_read = false;
                    }
                }
            }
            // There are now bytes waiting in the stream
            let _ = peer_to_poll.read(&mut buf);
            let deformed: P2pdata =
                serde_json::from_str(&String::from_utf8(buf.to_vec()).unwrap_or("".to_string()))
                    .unwrap_or(P2pdata::default());
            if deformed.message_type != 0x49 {
                continue;
            }
            //else
            let inventory: Inventory =
                serde_json::from_str(&deformed.message).unwrap_or(Inventory::default());
            if inventory == Inventory::default() {
                break;
            } else {
                //else
                // check if we allready have that inventory
                let try_get = getData(
                    config().db_path
                        + &"/".to_string()
                        + &inventory.chain
                        + &"-inventorys".to_string(),
                    inventory.height.to_string(),
                );
                if try_get == "-1".to_string() {
                    debug!(
                      "Inventory with hash: {}, chain: {}, height: {}, not found in db, saving...",
                      inventory.hash, inventory.chain, inventory.height,
                    );
                } else if try_get == "0".to_string() {
                    debug!(
                    "Failed to get (from db) inventory: hash: {}, chain: {}, height: {}. Presuming we do not have it...",
                    inventory.hash,
                    inventory.chain,
                    inventory.height,
                );
                } else {
                    debug!(
                        "Found matching inventory with hash: {}, chain: {}, height: {}, skipping",
                        inventory.hash, inventory.chain, inventory.height,
                    );
                    inventorys_to_ignore.push(inventory.hash.clone());
                    continue;
                }
                let save_res = saveData(
                    inventory.hash.clone(),
                    config().db_path
                        + &"/".to_string()
                        + &inventory.chain
                        + &"-inventorys".to_string(),
                    inventory.height.to_string(),
                );
                match save_res {
                    1 => {
                        debug!(
                            "Saved inventory: hash: {}, chain: {}, height: {}",
                            inventory.hash, inventory.chain, inventory.height,
                        );
                    }
                    _ => {
                        error!(
                            "Failed to save inventory: hash: {}, chain: {}, height: {}. Gave unknown error code: {}", 
                            inventory.hash,
                            inventory.chain,
                            inventory.height,
                            save_res,
                        );
                        break;
                    }
                };
                if amount_synced == amount_to_sync {
                    info!(
                        "Downloaded {} out of {} inventories, moving onto block data",
                        amount_synced, amount_to_sync
                    );
                    inventories_downloaded = true;
                    break;
                }
                if amount_synced % print_synced_every == 0 {
                    info!(
                        "Synced {} / {}. Only {} to go!",
                        amount_synced,
                        amount_to_sync,
                        amount_to_sync - amount_synced
                    );
                }
                amount_synced += 1;
            }
        } else {
            debug!(
                "Failed to gather a node to use from digests: {:?}.",
                chainDigests
            );
            error!("Syncing Failed. Try waiting some time restarting your node and ensure you are connected to internet!");
            break;
        }
    }
    if inventories_downloaded == false {
        //syncing failed
        return Err("syncing failed".into());
    }
    return Ok(0);
    // else - poll the peer for the raw blocks!
}

fn handle_client(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    loop {
        let mut data = [0 as u8; 200];
        let mut peer_clone: TcpStream;
        if let Ok(peer) = stream.try_clone() {
            peer_clone = peer;
        } else {
            return Err("failed to clone stream".into());
        }
        match stream.read(&mut data) {
            Ok(_) => {
                match deformMsg(&String::from_utf8(data.to_vec()).unwrap(), peer_clone) {
                    Some(a) => {
                        /* we just recieved a handshake, now we send ours
                        This is in the following format
                        network id, our peer id, our node type;
                        */
                        let msg = hex::encode(config().network_id)
                            + "*"
                            + &config().identitiy
                            + "*"
                            + &config().node_type.to_string();
                        info!("Our handshake: {}", msg);
                        let _ = stream.write_all(formMsg(msg.to_owned(), 0x1a).as_bytes());
                        // send our handshake
                    }
                    _ => {} // TODO: handle the clients rather than ignoring them if its not a handshake!!
                }
            }
            Err(_) => {
                debug!(
                    "Terminating connection with {}",
                    stream.peer_addr().unwrap()
                );
                stream.shutdown(Shutdown::Both).unwrap();
                return Err("undefined".into());
            }
        }
        {}
    }
}
fn rec_server() -> u8 {
    let listener = TcpListener::bind("0.0.0.0:56789").unwrap();
    // accept connections and process them, spawning a new thread for each one
    info!("P2P Server Launched on 0.0.0.0:{}", 56789);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!(
                    "New incoming connection to peer: {}",
                    stream.peer_addr().unwrap()
                );

                thread::spawn(move || {
                    // connection succeeded
                    let _ = handle_client(stream);
                });
            }
            Err(e) => {
                warn!("handling peer connection to peer resulted in  error: {}", e);
                /* connection failed */
            }
        }
    }
    // close the socket server
    drop(listener);
    return 1;
}
fn new_connection(socket: SocketAddr) -> Result<Peer, Box<dyn Error>> {
    // This Fucntion handles all the details of conecting to a peer, geting id and constructing a Peer struct
    let mut stream = TcpStream::connect(socket)?;
    let self_config = config();
    /*Once we have established a connection over TCP we now send vital data as a hanshake,
    This is in the following format
    network id,our peer id, our node type;
    The recipitent then verifyes this then they send the same hand shake back to us;
    */
    let msg = hex::encode(self_config.network_id)
        + "*"
        + &self_config.identitiy
        + "*"
        + &self_config.node_type.to_string();
    let _ = stream.write(formMsg(msg, 0x1a).as_bytes()); // send our handshake
    let mut buffer_n = [0; 200];
    //error!("{:?}", buffer_n.len());
    let read = stream.read(&mut buffer_n);
    match read {
        Ok(0) => {
            error!("Got No Data, retrying");
            let read_retry = stream.read(&mut buffer_n);
            match read_retry {
                Ok(0) => {
                    warn!("Got No Data on retry.");
                    return Err("no data read".into());
                }
                Ok(_) => {
                    info!("Retry worked");
                }
                _ => warn!("Failed"),
            }
        }
        _ => {}
    }
    trace!("stream read = {:?}", read);
    debug!(
        "recived handshake, as string {}",
        String::from_utf8(buffer_n.to_vec()).unwrap()
    );
    let pid: String;
    let mut peer_clone: TcpStream;
    if let Ok(peer) = stream.try_clone() {
        peer_clone = peer;
    } else {
        return Err("failed to clone stream".into());
    }
    match deformMsg(&String::from_utf8(buffer_n.to_vec())?, peer_clone) {
        Some(x) => {
            pid = x;
        }
        None => {
            warn!("Got no Id from peer");
            return Err("Got no id".into());
        }
    };
    let mut info = PeerTracker {
        sent_bytes: 200,
        recieved_bytes: 200,
    };
    return Ok(Peer {
        id: pid,
        socket,
        info,
    });
}

fn process_message(s: String) {
    info!("Message:{}", s);
}

fn process_block(s: String) {
    info!("Block {}", s);
}

fn process_transaction(s: String) {
    info!("Transaction {}", s);
}

fn process_registration(s: String) {
    info!("Certificate {}", s);
}

fn process_handshake(s: String) -> Result<String, String> {
    trace!("Handshake: {}", s);
    let id: String;
    let network_id_hex = hex::encode(config().network_id);
    let network_id_hex_len = network_id_hex.len();
    if s.len() < network_id_hex_len {
        warn!(
            "Bad handshake recived from peer (too short. Len: {}, Should be: {}), handshake: {}",
            s.len(),
            network_id_hex_len,
            s
        );
        //return Err("Handshake too short".to_string());
    }
    let peer_network_id_hex: &String = &s[0..network_id_hex.len()].to_string();
    if network_id_hex != peer_network_id_hex.to_owned() {
        debug!("Recived erroness network id {}", peer_network_id_hex);
        return Err(String::from("Incorrect network id"));
    } else {
        let val = s[peer_network_id_hex.len() + 1..s.len()].to_string();
        drop(s);
        let v: Vec<&str> = val.split("*").collect();
        id = v[0].to_string();
    }
    info!("Handshook with peer, gave id {}", id);
    return Ok(id);
}

pub enum p2p_errors {
    None,
    TimeOut,
    InvalidSocket,
    Other,
}

fn sendData(data: String, peer: &mut TcpStream, msg_type: u16) -> Result<(), std::io::Error> {
    // This function takes some data as a string and places it into a struct before sending to the peer
    let data_s: String = formMsg(data, msg_type);
    let sent = peer.write_all(data_s.as_bytes());
    return sent;
}

fn formMsg(data_s: String, data_type: u16) -> String {
    let data_len = data_s.len();
    let msg: P2pdata = P2pdata {
        message_bytes: data_len,
        message_type: data_type,
        message: data_s,
    };
    return serde_json::to_string(&msg).unwrap();
}

fn deformMsg(msg: &String, peer: TcpStream) -> Option<String> {
    // deforms message and excutes appropriate function to handle resultant data
    let v: Vec<&str> = msg.split("}").collect();
    let msg_c = v[0].to_string() + &"}".to_string();
    trace!("recive: {}", msg_c);
    drop(v);
    let mut msg_d: P2pdata = serde_json::from_str(&msg_c).unwrap_or_else(|e| {
        debug!(
            "Bad Packets recieved from peer, packets: {}. Parsing this gave error: {}",
            msg, e
        );
        return P2pdata::default();
    });
    match msg_d.message_type {
        0x04 => {
            let config = config();
            let d: GetInventories = serde_json::from_str(&msg_d.message).unwrap_or_default();
            if d == GetInventories::default() {
                return None;
            }
            let mut to: String = d.to;
            let mut from = d.from;
            if from == "0000000000".to_string() {
                from = config.first_block_hash;
            }
            if to == "0000000000" {
                let height_from: u64 = getBlockFromRaw(from.clone()).header.height;
                let b = getData(
                    config.db_path + &"/hashbynetworkheight".to_string(),
                    (height_from + d.amount as u64).to_string(),
                );
                if b == "-1".to_string() || b == "0".to_string() {
                    return None;
                } else {
                    let block: Block = serde_json::from_str(&b).unwrap_or_default();
                    to = block.hash;
                }
            }
            sendInventories(from, to, peer);
            return None;
        }
        0x05 => {
            let config = config();
            let d: GetBlocks = serde_json::from_str(&msg_d.message).unwrap_or_default();
            if d == GetBlocks::default() {
                return None;
            }
            let mut to: String = d.to;
            let mut from = d.from;
            if from == "0000000000".to_string() {
                from = config.first_block_hash;
            }
            if to == "0000000000" {
                let height_from: u64 = getBlockFromRaw(from.clone()).header.height;
                let b = getData(
                    config.db_path + &"/hashbynetworkheight".to_string(),
                    (height_from + d.amount as u64).to_string(),
                );
                if b == "-1".to_string() || b == "0".to_string() {
                    return None;
                } else {
                    let block: Block = serde_json::from_str(&b).unwrap_or_default();
                    to = block.hash;
                }
            }
            sendBlocks(from, to, peer);
            return None;
        }
        0x01 => {
            process_message(msg_d.message);
            return None;
        }
        0x0a => {
            process_block(msg_d.message);
            return None;
        }
        0x0b => {
            process_transaction(msg_d.message);
            return None;
        }
        0x0c => {
            process_registration(msg_d.message);
            return None;
        }
        0x1a => {
            return Some(process_handshake(msg_d.message).unwrap());
        }
        _ => {
            warn!("Bad Messge type from peer. Message type: {}. (If you are getting, lots of these check for updates)", msg_d.message_type.to_string());
            return None;
        }
    }
}
