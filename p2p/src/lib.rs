#[macro_use]
extern crate log;
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate unwrap;
extern crate avrio_blockchain;
extern crate avrio_config;
extern crate avrio_database;
use avrio_blockchain::{
    check_block, enact_block, generate_merkle_root_all, getBlock, getBlockFromRaw, saveBlock, Block,
};
use avrio_config::config;
use avrio_core::epoch::Epoch;
use avrio_database::{getData, getDataDb, getIter, openDb, saveData, setDataDb};
use std::borrow::{Cow, ToOwned};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::str;
use std::thread;
extern crate hex;
use std::collections::HashMap;
use std::error::Error;
extern crate rocksdb;
extern crate simple_logger;

#[macro_use]
extern crate lazy_static;

use std::sync::Mutex;

lazy_static! {
    static ref HANDSHAKES: Mutex<Vec<String>> = Mutex::new(vec![]);
}

fn add_handsake(hs: String) {
    HANDSHAKES.lock().unwrap().push(hs);
}

fn get_handshakes() -> Vec<String> {
    return HANDSHAKES.lock().unwrap().clone();
}

fn in_handshakes(hs: &String) -> bool {
    trace!("hs: {}", hs);
    for shake in get_handshakes() {
        if &shake == hs {
            trace!("Handshake found");
            return true;
        }
        trace!("shake: {}", shake);
    }
    trace!("Handshake not found");
    return false;
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct P2pdata {
    /// The length in bytes of message
    pub message_bytes: usize,
    /// The type of data
    pub message_type: u16,
    /// The serialized data
    pub message: String,
}
#[derive(Debug)]
pub struct Peer {
    pub id: String,
    /// socket (ip, port) of a peer
    pub socket: SocketAddr,
    /// stats about recived and sent bytes from this peer
    pub info: PeerTracker,
    /// The stream its self - for reading and writing
    pub stream: TcpStream,
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
    /// The amount of inventories to get back, max is 128
    /// if this value is 0 it uses the from and to hashes instead
    pub amount: u8,
    /// hash (or 00000000000 for ignore)
    /// if this value is 00000000000 it uses the first block
    pub from: String,
    /// hash (or 00000000000 for ignore)
    /// if this value is 00000000000 it will take the block that is *amount* blocks ahead of from and use that
    pub to: String,
}
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct GetBlocks {
    /// The hash of the block you want to get
    pub hash: String,
}

#[derive(Debug, Default)]
pub struct ChainDigestPeer {
    pub peer: Option<TcpStream>,
    pub digest: String,
}

// TODO: Sync needed function
pub fn sync_needed() -> bool {
    return true;
}

/// # prop_block
/// This function sends a block to all peers it has from the comitee that is currently handeling the shard
/// In testnet 0.0.1 It simply sent to all conected peers
pub fn prop_block(
    blk: &Block,
    peers: Vec<&mut TcpStream>,
) -> Result<(), Box<dyn std::error::Error>> {
    for peer in peers {
        sendBlockStruct(blk, peer)?;
    }
    return Ok(());
}

/// Sends block with hash to _peer
pub fn sendBlock(hash: String, _peer: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let block: Block = getBlockFromRaw(hash);
    if block == Block::default() {
        return Err("could not get block".into());
    } else {
        let block_ser = serde_json::to_string(&block).unwrap_or(" ".to_owned());
        if block_ser == " ".to_owned() {
            return Err("Could not ser block".into());
        } else {
            if let Err(e) = sendData(&block_ser, _peer, 0x0a) {
                return Err(e.into());
            } else {
                return Ok(());
            }
        }
    }
}

pub fn sendBlockStruct(
    block: &Block,
    peer: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    if block.hash == Block::default().hash {
        return Err("tryied to send default block".into());
    } else {
        let block_ser = serde_json::to_string(block).unwrap_or(" ".to_owned());
        if block_ser == " " {
            return Err("Could not ser block".into());
        } else {
            if let Err(e) = sendData(&block_ser, peer, 0x0a) {
                return Err(e.into());
            } else {
                return Ok(());
            }
        }
    }
}
/// This function asks the peer to sync, if they accept you can begin syncing
pub fn syncack_peer(peer: &mut TcpStream) -> Result<TcpStream, Box<dyn Error>> {
    let mut peer_to_use_unwraped = peer.try_clone().unwrap();
    let syncreqres = sendData(
        &"syncreq".to_owned(),
        &mut peer_to_use_unwraped.try_clone().unwrap(),
        0x22,
    );
    match syncreqres {
        Ok(()) => {}
        Err(e) => {
            error!("Failed to end syncreq message to peer, gave error: {}. Check your internet connection and ensure port is not in use!", e);
            return Err("failed to send syncreq".into());
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
    let msg = String::from_utf8(buf.to_vec()).unwrap_or("utf8 failed".to_string());
    let v: Vec<&str> = msg.split("}").collect();
    let msg_c = v[0].to_string() + &"}".to_string();
    drop(v);
    trace!(
        "(SYNC REQ) Recieved: {}",
        String::from_utf8(buf.to_vec()).unwrap_or("utf8 failed".to_string())
    );
    let deformed: P2pdata = serde_json::from_str(&msg_c).unwrap_or(P2pdata::default());
    if deformed.message == "syncack".to_string() {
        debug!("Got syncack from selected peer. Continuing");
        return Ok(peer_to_use_unwraped);
    } else if deformed.message == "syncdec".to_string() {
        info!("Peer rejected sync request, choosing new peer...");
        // choose the next fasted peer from our socket list
        return Err("rejected syncack".into());
    } else {
        info!("Recieved incorect message from peer (in context syncrequest). Message: {}. This could be caused by outdated software - check you are up to date!", deformed.message);
        info!("Retrying syncack with same peer...");
        // try again
        return syncack_peer(&mut peer_to_use_unwraped);
    }
}
/// Sends our chain digest, this is a merkle root of all the blocks we have.avrio_blockchain.avrio_blockchain
/// it is calculated with the generateChainDigest function which is auto called every time we get a new block
fn sendChainDigest(peer: &mut TcpStream) {
    let chains_digest = getData(
        config().db_path + &"/chains/masterchainindex",
        &"digest".to_string(),
    );
    if chains_digest == "-1".to_owned() || chains_digest == "0".to_owned() {
        let _ = sendData(
            &generate_merkle_root_all().unwrap_or("".to_owned()),
            peer,
            0x01,
        );
    } else {
        let _ = sendData(&chains_digest, peer, 0x01);
    }
}
/// this asks the peer for thier chain digest
fn getChainDigest(peer: &mut TcpStream) -> ChainDigestPeer {
    let _ = sendData(&"".to_owned(), peer, 0x1c);
    let mut i: i32 = 0;
    loop {
        let mut buffer = [0; 128];
        let e_r = peer.read(&mut buffer);
        if let Err(_e) = e_r {
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
                        .unwrap_or_else(|_e| return "".to_string()),
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
/// this calculates the most common string in a list
fn get_mode(v: Vec<String>) -> String {
    let mut map = HashMap::new();
    for num in v {
        let count = map.entry(num).or_insert(0);
        *count += 1;
    }
    return (**map.iter().max_by_key(|(_, v)| *v).unwrap().0).to_string();
}

// TODO sync specific chain func
/// This function syncs the specifyed chain only from the peer specifyed.
/// It returns Ok(()) on succsess and handles the inventory generation, inventory saving, block geting, block validation,
/// block saving, block enacting and informing the user of the progress.
/// If you simply want to sync all chains then use the sync function bellow.
pub fn sync_chain(chain: &String, peer: &mut TcpStream) -> Result<u64, Box<dyn std::error::Error>> {
    let _ = sendData(chain, &mut peer.try_clone().unwrap(), 0x45);
    let mut buf = [0; 1024];
    let mut no_read = true;
    while no_read == true {
        if let Ok(a) = peer.try_clone().unwrap().peek(&mut buf) {
            if a == 0 {
            } else {
                no_read = false;
            }
        }
    }
    // There are now bytes waiting in the stream
    let _ = peer.read(&mut buf);
    let _ = peer.flush()?;
    let amount_to_sync: u64;
    let as_s = String::from_utf8(buf.to_vec()).unwrap_or_else(|e| {
        error!(
            "Failed to parse to_sync_count message from utf8, error: {}",
            e
        );
        "".to_string()
    });
    let deformed: P2pdata = serde_json::from_str(&strip_msg(&as_s)).unwrap_or_else(|e| {
        error!(
            "Failed to parse p2pdata struct from message: {}, error: {}",
            as_s, e
        );
        P2pdata::default()
    });
    if deformed.message_type != 0x46 {
        amount_to_sync = 0;
    } else {
        amount_to_sync = deformed.message.parse().unwrap_or(0);
    }
    let print_synced_every: u64;
    info!("Got to get {} blocks for chain: {}", amount_to_sync, chain);
    match amount_to_sync {
        0..=9 => print_synced_every = 1,
        10..=100 => print_synced_every = 10,
        101..=500 => print_synced_every = 50,
        501..=1000 => print_synced_every = 100,
        1001..=10000 => print_synced_every = 500,
        10001..=50000 => print_synced_every = 2000,
        _ => print_synced_every = 5000,
    }
    let top_block_hash: String;
    let opened_db: rocksdb::DB;
    if let Ok(chain_db) = openDb(config().db_path + "/chains/" + &chain + &"-chainindex".to_owned())
    {
        opened_db = chain_db;
        top_block_hash = getDataDb(&opened_db, &"topblockhash");
    } else {
        error!("Failed to get get top block hash for chain. Could not open db");
        return Err("failed to get topblockhash for chain, failed to open db".into());
    }
    if top_block_hash == "-1" {
        if let Err(e) = sendData(
            &serde_json::to_string(&(&"0".to_owned(), &chain))?,
            peer,
            0x6f,
        ) {
            error!(
                "Asking peer for their blocks above hash: {} for chain: {} gave error: {}",
                top_block_hash, chain, e
            );
            return Err(e.into());
        }
    } else if let Err(e) = sendData(
        &serde_json::to_string(&(&top_block_hash, &chain))?,
        peer,
        0x6f,
    ) {
        error!(
            "Asking peer for their blocks above hash: {} for chain: {} gave error: {}",
            top_block_hash, chain, e
        );
        return Err(e.into());
    } else {
        let mut synced_blocks: u64 = 0;
        let mut invalid_blocks: u64 = 0;
        info!(
            "Getting {} blocks from peer: {}, from block hash: {}",
            amount_to_sync,
            peer.peer_addr().unwrap(),
            top_block_hash
        );
        loop {
            let mut buf = [0; 1000000];
            let mut no_read = true;
            let _ = peer.flush();
            while no_read == true {
                if let Ok(a) = peer.peek(&mut buf) {
                    if a == 0 {
                    } else {
                        no_read = false;
                    }
                }
            }
            // There are now bytes waiting in the stream
            let _ = peer.read(&mut buf);
            let as_s = String::from_utf8(buf.to_vec()).unwrap_or_else(|e| {
                error!("Failed to parse blocks message from utf8, error: {}", e);
                "".to_string()
            });
            let deformed: P2pdata = serde_json::from_str(&strip_msg(&as_s)).unwrap_or_else(|e| {
                error!(
                    "Failed to parse p2pdata struct from message: {}, error: {}",
                    as_s, e
                );
                P2pdata::default()
            });
            trace!(target: "avrio_p2p::sync", "got blocks: {:#?}", deformed);
            if deformed.message_type != 0x0a {
                // TODO: Ask for block(s) again rather than returning err
                error!(
                    "Failed to get block, wrong message type: {}",
                    deformed.message_type
                );
                return Err("failed to get block".into());
            } else {
                let blocks: Vec<Block> =
                    serde_json::from_str(&deformed.message).unwrap_or_default();
                if blocks.len() == 0 {
                    error!("Got 0 blocks from peer when expecting at least 1");
                    return Err("Got 0 blocks from peer when expecting at least 1".into());
                }
                trace!(
                    "Got: {} blocks from peer. Hash: {} up to: {}",
                    blocks.len(),
                    blocks[0].hash,
                    blocks[blocks.len() - 1].hash
                );
                for block in blocks {
                    if let Err(e) = check_block(block.clone()) {
                        error!("Recieved invalid block with hash: {} from peer, validation gave error: {:#?}. Invalid blocks from peer: {}", block.hash, e, invalid_blocks);
                        invalid_blocks += 1;
                    } else {
                        saveBlock(block.clone())?;
                        enact_block(block)?;
                        synced_blocks += 1;
                    }
                }
            }
            let top_block_hash: String;
            top_block_hash = getDataDb(&opened_db, &"topblockhash");
            trace!("Asking peer for blocks above hash: {}", top_block_hash);
            if top_block_hash == "-1" {
                if let Err(e) = sendData(&"0".to_owned(), peer, 0x6f) {
                    error!(
                        "Asking peer for their blocks above hash: {} for chain: {} gave error: {}",
                        top_block_hash, chain, e
                    );
                    return Err(e.into());
                }
            } else if let Err(e) = sendData(&top_block_hash, peer, 0x6f) {
                error!(
                    "Asking peer for their blocks above hash: {} for chain: {} gave error: {}",
                    top_block_hash, chain, e
                );
                return Err(e.into());
            }
            if synced_blocks <= amount_to_sync {
                info!("Synced all {} blocks for chain: {}", synced_blocks, chain);
                break;
            }
            if synced_blocks % print_synced_every == 0 {
                info!(
                    "Synced {} / {} blocks (chain: {}). {} more to go",
                    synced_blocks,
                    amount_to_sync,
                    chain,
                    amount_to_sync - synced_blocks
                );
            }
        }
    }
    return Ok(amount_to_sync);
}

// TODO: Finish syncing code
/// This is a cover all sync function that will sync all chains and covers getting the top index and syncing from there
/// for more controll over your sync you should call the sync_chain function which will sync only the chain specifyed.
/// pl is a vector of mutable refrences of TcpStreams (Vec<&mut TcpStream>), thi function finds the most common chain digest
/// and then chooses the fasted peer with that chain digest and uses it. After it thinks it has finished syncing it will choose
/// a random peer and check random blocks are the same. If you wish to use the sync function with only one peer pass a vector
/// containing only that peer. Please note this means it will not be able to verify that it has not missed blocks afterwards if
/// the peer is malicously withholding them. For this reason only do this if you trust the peer or will be checking the blockchain
/// with a diferent peer afterwards.
pub fn sync(pl: &mut Vec<&mut TcpStream>) -> Result<u64, String> {
    let _peers: Vec<TcpStream> = vec![];
    let _pc: u32 = 0;
    let _i: usize = 0;
    let mut chain_digests: Vec<ChainDigestPeer> = vec![];
    for peer in pl.iter_mut() {
        if let Ok(mut peer_new) = peer.try_clone() {
            let handle = thread::Builder::new()
                .name("getChainDigest".to_string())
                .spawn(move || {
                    let chain_digest = getChainDigest(&mut peer_new);
                    if chain_digest.digest == " " {
                        return ChainDigestPeer {
                            peer: Some(peer_new),
                            digest: " ".to_string(),
                        };
                    } else {
                        return chain_digest;
                    }
                });
            if let Ok(handle_) = handle {
                if let Ok(result) = handle_.join() {
                    chain_digests.push(result);
                }
            }
        }
    }
    let mut hashes: Vec<String> = vec![];
    let chainDigestsLen = chain_digests.len();
    for hash in chain_digests.iter() {
        hashes.push(hash.digest.clone());
    }
    let mode_hash = get_mode(hashes);
    let mut peer_to_use: Option<TcpStream> = None;
    let _i: u64 = 0;
    for i in 0..chain_digests.len() {
        if chain_digests[i].digest == mode_hash {
            if let Some(peer_) = &chain_digests[i].peer {
                peer_to_use = Some(peer_.try_clone().unwrap());
            }
        }
    }
    let mut peer_to_use_unwraped: TcpStream = peer_to_use.unwrap().try_clone().unwrap();
    let try_ack = syncack_peer(&mut peer_to_use_unwraped);
    if let Err(e) = try_ack {
        error!("Got error: {} when sync acking peer", e);
        // TODO sync ack the next fastest peer until we have peer (1)
        return Err("rejected sync ack".into());
    } else {
        // We have a peer now we ask them for their list of chains
        // They send their list of chains as a vec of strings
        if let Err(e) = sendData(&"".to_owned(), &mut peer_to_use_unwraped, 0x60) {
            error!("Failed to request chains list from peer gave error: {}", e);
            // TODO: *1
            return Err("failed to send get chain list message".into());
        } else {
            let mut buf = [0; 10024];
            let mut no_read = true;
            while no_read == true {
                if let Ok(a) = peer_to_use_unwraped.peek(&mut buf) {
                    if a == 0 {
                    } else {
                        no_read = false;
                    }
                }
            }
            // There are now bytes waiting in the stream
            let _ = peer_to_use_unwraped.read(&mut buf);
            let as_string = String::from_utf8(buf.to_vec()).unwrap_or("".to_string());
            trace!("Chain list got: {}", as_string);
            let deformed: P2pdata =
                serde_json::from_str(&strip_msg(&as_string)).unwrap_or_else(|e| {
                    error!("Failed to decode returned message, gave error: {:?}", e);
                    return P2pdata::default();
                });
            if deformed.message_type != 0x61 {
                error!(
                    "Failed to get chain list from peer (got wrong message type back: {})",
                    deformed.message_type
                );
                //TODO: *1
                return Err("got wrong message response (context get chain list)".into());
            } else {
                let chain_list: Vec<String> =
                    serde_json::from_str(&deformed.message).unwrap_or_default();
                if chain_list.len() == 0 {
                    return Err("empty chain list".into());
                } else {
                    for chain in chain_list.iter() {
                        if let Err(e) = sync_chain(chain, &mut peer_to_use_unwraped) {
                            error!("Failed to sync chain: {}, gave error: {}", chain, e);
                            return Err(format!("failed to sync chain {}", chain));
                        }
                    }
                }
            }
        }
    }
    return Ok(1);
}

fn handle_client(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    loop {
        let mut data = [0 as u8; 2000];
        let mut peer_clone: TcpStream;
        if let Ok(peer) = stream.try_clone() {
            peer_clone = peer;
        } else {
            return Err("failed to clone stream".into());
        }
        match stream.read(&mut data) {
            Ok(_) => {
                match deformMsg(&String::from_utf8(data.to_vec()).unwrap(), &mut peer_clone) {
                    Some(a) => {
                        if a == "handshake" {
                            /* we just recieved a handshake, now we send ours
                            This is in the following format
                            network id, our peer id, our node type;
                            */
                            let msg = hex::encode(config().network_id)
                                + "*"
                                + &config().identitiy
                                + "*"
                                + &config().node_type.to_string();
                            debug!("Our handshake: {}", msg);
                            let _ = stream.write_all(formMsg(msg.to_owned(), 0x1a).as_bytes());
                            let _ = stream.flush();
                            // send our handshake
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => {
                debug!(
                    "Terminating connection with {}, gave error {}",
                    stream.peer_addr().unwrap(),
                    e
                );
                stream.shutdown(Shutdown::Both).unwrap();
                return Err(e.into());
            }
        }
        {}
    }
}
pub fn rec_server() -> u8 {
    let config = config();
    let listener = TcpListener::bind(
        config.ip_host.to_string() + &":".to_string() + &config.p2p_port.to_string(),
    )
    .unwrap();
    // accept connections and process them, spawning a new thread for each one
    info!(
        "P2P Server Launched on {}",
        config.ip_host.to_string() + &":".to_string() + &config.p2p_port.to_string()
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!(
                    "New incoming connection to peer: {}",
                    stream.peer_addr().unwrap()
                );
                if let Err(e) = avrio_database::add_peer(stream.peer_addr().unwrap()) {
                    error!(
                        "Failed to add peer: {} to peer list, gave error: {}",
                        stream.peer_addr().unwrap(),
                        e
                    );
                    drop(listener);
                    return 0;
                } else {
                    thread::spawn(move || {
                        // connection succeeded
                        let _ = handle_client(stream);
                    });
                }
            }
            Err(e) => {
                warn!("Handling peer connection to peer resulted in  error: {}", e);
                /* connection failed */
            }
        }
    }
    // close the socket server
    drop(listener);
    return 1;
}
pub fn new_connection(socket: SocketAddr) -> Result<Peer, Box<dyn Error>> {
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
    let read = stream.read(&mut buffer_n);
    match read {
        Ok(0) => {
            debug!("Got No Data, retrying");
            let read_retry = stream.read(&mut buffer_n);
            match read_retry {
                Ok(0) => {
                    debug!("Got No Data on retry.");
                    return Err("no data read".into());
                }
                Ok(_) => {
                    debug!("Retry worked");
                }
                _ => debug!("New Connection failed"),
            }
        }
        _ => {}
    }
    trace!("stream read = {:?}", read);
    let pid: String;
    let msg = String::from_utf8(buffer_n.to_vec())?;
    let v: Vec<&str> = msg.split("}").collect();
    let msg_c = v[0].to_string() + &"}".to_string();
    let v: Vec<&str> = msg_c.split("{").collect();
    let msg_c = "{".to_string() + &v[1].to_string();
    drop(v);
    debug!("recived handshake, as string {}", msg_c);
    let p2p_data: P2pdata = serde_json::from_str(&msg_c).unwrap_or_else(|e| {
        debug!(
            "Bad Packets recieved from peer, packets: {}. Parsing this gave error: {}",
            msg, e
        );
        return P2pdata::default();
    });
    match process_handshake(p2p_data.message) {
        Ok(x) => {
            pid = x;
        }
        _ => {
            debug!("Got no id from peer");
            return Err("Got no id".into());
        }
    };
    let info = PeerTracker {
        sent_bytes: 0,
        recieved_bytes: 0,
    };
    avrio_database::add_peer(socket)?;
    let _ = stream.flush();
    return Ok(Peer {
        id: pid,
        socket,
        stream,
        info,
    });
}

fn process_message(s: String, p: &mut TcpStream) {
    if s == "getChainDigest".to_string() {
        let merkle_root = "sorry nothing".to_owned();
        let _ = sendData(&merkle_root, p, 0x01);
    }
}

fn process_block(s: String) {
    info!("Block {}", s);
}

fn process_handshake(s: String) -> Result<String, String> {
    trace!("Handshake: {}", s);
    if in_handshakes(&s) {
        return Err("already handshook".into());
    }
    let id: String;
    let network_id_hex = hex::encode(config().network_id);
    let network_id_hex_len = network_id_hex.len();
    if s.len() < network_id_hex_len {
        debug!(
            "Bad handshake recived from peer (too short. Len: {}, Should be: {}), handshake: {}",
            s.len(),
            network_id_hex_len,
            s
        );
        return Err("Handshake too short".to_string());
    }
    let peer_network_id_hex: &String = &s[0..network_id_hex.len()].to_string();
    if network_id_hex != peer_network_id_hex.to_owned() {
        debug!("Recived erroness network id {}", peer_network_id_hex);
        return Err(String::from("Incorrect network id"));
    } else {
        let val = s[peer_network_id_hex.len() + 1..s.len()].to_string();
        let v: Vec<&str> = val.split("*").collect();
        id = v[0].to_string();
    }
    info!("Handshook with peer, gave id {}", id);
    let id_cow = Cow::from(&id);
    add_handsake(s);
    return Ok((&id_cow).to_string());
}

pub enum p2p_errors {
    None,
    TimeOut,
    InvalidSocket,
    Other,
}

pub fn sendData(data: &String, peer: &mut TcpStream, msg_type: u16) -> Result<(), std::io::Error> {
    // This function takes some data as a string and places it into a struct before sending to the peer
    let data_s: String = formMsg(data.clone(), msg_type);
    trace!("Sent data: {}", data_s);
    let sent = peer.write_all(data_s.as_bytes());
    let _ = peer.flush()?;
    return sent;
}

pub fn formMsg(data_s: String, data_type: u16) -> String {
    let data_len = data_s.len();
    let msg: P2pdata = P2pdata {
        message_bytes: data_len,
        message_type: data_type,
        message: data_s,
    };
    return serde_json::to_string(&msg).unwrap();
}

fn strip_msg(msg: &String) -> String {
    info!("striping: {}", msg);
    let v: Vec<&str> = msg.split("}").collect();
    return v[0].to_string() + &"}".to_string();
}

pub fn deformMsg(msg: &String, peer: &mut TcpStream) -> Option<String> {
    // deforms message and excutes appropriate function to handle resultant data
    let msg_c = strip_msg(&msg);
    let msg_d: P2pdata = serde_json::from_str(&msg_c).unwrap_or_else(|e| {
        debug!(
            "Bad Packets recieved from peer, packets: {}. Parsing this gave error: {}",
            msg_c, e
        );
        return P2pdata::default();
    });
    match msg_d.message_type {
        0x22 => {
            let _ = sendData(&"syncack".to_owned(), peer, 0x01);
            return Some("syncreq".to_owned());
        }
        0x05 => {
            sendBlock(msg_d.message, peer);
            return Some("sendblock".into());
        }
        0x01 => {
            process_message(msg_d.message, peer);
            return Some("message".into());
        }
        0x0a => {
            process_block(msg_d.message);
            return Some("getblock".into());
        }
        0x1a => {
            if !in_handshakes(&msg_d.message) {
                if let Ok(_) = process_handshake(msg_d.message) {
                    return Some("handshake".to_string());
                } else {
                    return None;
                }
            } else {
                debug!("Peer already in handshake list");
                return None;
            }
        }
        0x1b | 0x1c => {
            sendChainDigest(peer);
            return Some("sendchaindigest".into());
        }
        0 => {
            debug!(
                "Unsupported application or malformed packets (zero type code) from peer: {}",
                peer.peer_addr().expect("Could not get addr for peer")
            );
            debug!("raw recieved: {}", msg_c);
            return None;
        }
        0x45 => {
            // send block count
            let bc = getData(
                config().db_path + &"/chaindigest".to_owned(),
                &"blockcount".to_owned(),
            );
            if bc == "-1".to_owned() {
                let _ = sendData(&"0".into(), peer, 0x46);
            } else {
                let _ = sendData(&bc, peer, 0x46);
            }
            return None;
        }
        0x6f => {
            let (hash, chain): (String, String) =
                serde_json::from_str(&msg_d.message).unwrap_or_default();
            if chain == String::default() || hash == String::default() {
                debug!(
                    "Got malformed getblocksabovehash hash request (invalid body: {})",
                    msg_d.message
                );
                return None;
            } else {
                let block_from: Block;
                if hash == "0" {
                    trace!("Getting genesis block for chain: {}", chain);
                    block_from = getBlock(&chain, 0);
                    trace!("Block from: {:#?}", block_from);
                } else {
                    block_from = getBlockFromRaw(hash);
                }
                if block_from == Default::default() {
                    debug!("Cant find block (context getblocksabovehash)");
                    return None;
                } else {
                    let mut got: u64 = 0;
                    let mut prev: Block = block_from;
                    let mut blks: Vec<Block> = vec![];
                    while prev != Default::default() {
                        blks.push(prev);
                        got += 1;
                        trace!("Sent block at height: {}", got);
                        prev = getBlock(&chain, got);
                    }
                    if let Ok(_) = sendData(
                        &serde_json::to_string(&blks).unwrap_or_default(),
                        peer,
                        0x0a,
                    ) {
                        trace!(
                            "Sent all blocks (amount: {}) for chain: {} to peer",
                            got - 1,
                            chain
                        );
                    }
                }
            }
            return Some("getblocksabovehash".into());
        }
        0x60 => {
            trace!(
                "Peer: {} has requested our chains list",
                peer.peer_addr().expect("Could not get addr for peer")
            );
            if let Ok(db) = openDb(config().db_path + &"/chainlist".to_owned()) {
                let mut iter = db.raw_iterator();
                iter.seek_to_first();
                let mut chains: Vec<String> = vec![];
                while iter.valid() {
                    if let Some(key_utf8) = iter.key() {
                        if let Ok(key) = String::from_utf8(key_utf8.to_vec()) {
                            chains.push(key);
                        }
                    }
                    iter.next();
                }
                trace!("Our chain list: {:#?}", chains);
                let s = serde_json::to_string(&chains).unwrap_or_default();
                if s == String::default() {
                    trace!("Failed to ser list");
                    return None;
                } else if let Err(e) = sendData(&s, peer, 0x61) {
                    debug!("Failed to send chain list to peer, gave error: {}", e);
                    return None;
                }
            }
            return Some("getchainslist".into());
        }
        _ => {
            warn!("Bad Message type from peer. Message type: {}. (If you are getting, lots of these check for updates)", msg_d.message_type.to_string());
            return None;
        }
    }
}
