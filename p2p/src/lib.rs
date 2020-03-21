#[macro_use]
extern crate log;
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate unwrap;
extern crate avrio_blockchain;
extern crate avrio_config;
extern crate avrio_database;
use avrio_blockchain::{getBlockFromRaw, Block};
use avrio_config::config;
use avrio_core::epoch::Epoch;
use avrio_database::{getData, openDb, saveData};
use std::borrow::{Cow, ToOwned};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::str;
use std::thread;
extern crate hex;
use std::collections::HashMap;
use std::error::Error;
extern crate simple_logger;

/// # Inventorys
/// This is save to the CHAIN_KEY-invs db (where CHAIN_KEY is the public key of the chain)
/// They key is the height of the block and the value is the following struct serialized
/// Serializing this should produce a string like this:
/// { "hash" : "...", "timestamp" : "124353632"}
/// To then get the struct set chain to the name of the db (remove the -invs bit) and the height should be the key
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct Inventory {
    #[serde(skip)]
    /// this is got via the name of the db
    chain: String,
    /// the hash of the block
    hash: String,
    #[serde(skip)]
    /// this is the key of the entry
    height: u64,
    /// the timestamp of the block
    timestamp: u64,
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
#[derive(Serialize, Deserialize, Debug)]
pub struct Peer {
    pub id: String,
    /// socket (ip, port) of a peer
    pub socket: SocketAddr,
    /// stats about recived and sent bytes from this peer
    pub info: PeerTracker,
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

fn sendInventories(
    from: String,
    to: String,
    _peer: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let firstInventory = getBlockFromRaw(from);
    let lastInventory = getBlockFromRaw(to);
    if firstInventory == Block::default() || lastInventory == Block::default() {
        return Err("err".into());
    } else {
        let from_t = firstInventory.header.timestamp;
        let to_t = firstInventory.header.timestamp;
        if let Ok(db) = openDb(config().db_path + &"/chains".to_owned()) {
            let mut iter = db.raw_iterator();
            iter.seek_to_first();
            while iter.valid() {
                if let Some(chain) = iter.value() {
                    if let Ok(chain_string) = String::from_utf8(chain) {
                        if let Ok(inv_db) = openDb(
                            config().db_path + &"/".to_owned() + &chain_string + &"-inv".to_owned(),
                        ) {
                            let mut inviter = inv_db.raw_iterator();
                            inviter.seek_to_first();
                            while inviter.valid() {
                                if let Some(inv) = iter.value() {
                                    if let Ok(inv_string) = String::from_utf8(inv) {
                                        let inv_des: Inventory =
                                            serde_json::from_str(&inv_string).unwrap_or_default();
                                        if inv_des == Inventory::default() {
                                            warn!("Failed to parse inventory from: {}, likley corrupted DB", inv_string);
                                        } else {
                                            trace!(
                                                "Saw inv: index: {:?}, value: {:?}",
                                                iter.key(),
                                                iter.value()
                                            );
                                            if inv_des.timestamp >= from_t
                                                && inv_des.timestamp <= to_t
                                            {
                                                use std::borrow::Cow; // Cow = clone on write -  a much more efficent way of having multiple defrenced refrences to strings.
                                                let inv_string_cow = Cow::from(inv_string);
                                                if let Err(_) = sendData(
                                                    (&inv_string_cow).to_string(),
                                                    _peer,
                                                    0x1a,
                                                ) {
                                                    // try again
                                                    sendData(
                                                        (&inv_string_cow).to_string(),
                                                        _peer,
                                                        0x1a,
                                                    )?
                                                } else {
                                                    return Ok(());
                                                }
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "Found corrupted inventory at key: {}",
                                            String::from_utf8(
                                                iter.key().unwrap_or(
                                                    b"error getting index, (key err)"
                                                        .to_owned()
                                                        .to_vec()
                                                )
                                            )
                                            .unwrap_or("error getting index (utf8 err)".to_owned())
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        warn!(
                            "Found corrupted chain at key: {}",
                            String::from_utf8(
                                iter.key()
                                    .unwrap_or(b"error getting index".to_owned().to_vec())
                            )
                            .unwrap_or("error getting index".to_owned())
                        );
                    }
                } else {
                    warn!(
                        "Found corrupted chain at key: {}",
                        String::from_utf8(
                            iter.key()
                                .unwrap_or(b"error getting index".to_owned().to_vec())
                        )
                        .unwrap_or("error getting index".to_owned())
                    );
                }
                trace!(
                    "Saw chain: number: {:?}, hash: {:?}",
                    iter.key(),
                    iter.value()
                );
                iter.next();
            }
        }
        return Ok(());
    }
}
/// Sends block with hash to _peer
fn sendBlock(hash: String, _peer: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let block: Block = getBlockFromRaw(hash);
    if block == Block::default() {
        return Err("could not get block".into());
    } else {
        let block_ser = serde_json::to_string(&block).unwrap_or(" ".to_owned());
        if block_ser == " ".to_owned() {
            return Err("Could not ser block".into());
        } else {
            if let Err(e) = sendData(block_ser, _peer, 0x0a) {
                return Err(e.into());
            } else {
                return Ok(());
            }
        }
    }
}
/// This function asks the peer to sync, if they accept you can begin syncing
pub fn syncack_peer(peer: &mut TcpStream) -> Result<TcpStream, Box<dyn Error>> {
    let peer_to_use_unwraped = peer.try_clone().unwrap();
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
/// Sends our chain digest, this is a merkle root of all the blocks we have.avrio_blockchain.avrio_blockchain
/// it is calculated with the generateChainDigest function which is auto called every time we get a new block
fn sendChainDigest(peer: &mut TcpStream) {
    let chains_digest = getData(config().db_path + &"/chainsindex", &"digest".to_string());
    let buf = chains_digest.as_bytes();
    let _ = peer.write(buf);
}
/// this asks the peer for thier chain digest
fn getChainDigest(peer: &mut TcpStream) -> ChainDigestPeer {
    let _ = sendData("".to_string(), peer, 0x1c);
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

// TODO
/// This function syncs the specifyed chain only from the peer specifyed.
/// It returns Ok(()) on succsess and handles the inventory generation, inventory saving, block geting, block validation,
/// block saving, block enacting and informing the user of the progress.
/// If you simply want to sync all chains then use the sync function bellow.
fn sync_chain(chain: String, peer: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    return Ok(());
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
    let mut peers: Vec<TcpStream> = vec![];
    let mut pc: u32 = 0;
    let _i: usize = 0;
    for i in 0..pl.len() {
        let res = sendData("getChainDigest".to_string(), &mut pl[i], 0x01);
        match res {
            Ok(_) => {
                let peer_copy = pl[i].try_clone();
                if let Ok(np) = peer_copy {
                    peers.push(np);
                    pc += 1;
                }
            }
            Err(_e) => {}
        }
    }
    trace!("Sent getChainDigest to {} peers", pc);
    let mut chainDigests: Vec<ChainDigestPeer> = vec![];
    let _empty_string = "".to_string();
    for peer in peers.iter_mut() {
        if let Ok(mut peer_new) = peer.try_clone() {
            let handle = thread::Builder::new()
                .name("getChainDigest".to_string())
                .spawn(move || {
                    let chainDigest = getChainDigest(&mut peer_new);
                    match chainDigest.digest {
                        _empty_string => {
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
    let _i: u64 = 0;
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
            let peer_to_use_unwraped: TcpStream;
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
    let _last_hash_fully_synced = "0000000000".to_string();
    let _chainsindex = "0000000000".to_string();
    let mut amount_synced: u64 = 0;
    let mut amount_to_sync: u64 = 0;
    let get_ci_res = getData(
        config().db_path + &"/chainindex".to_owned(),
        &"lastsyncedepoch".to_owned(),
    );
    if get_ci_res == "-1".to_owned() {
        // the db is likley corupted, we will resync
        warn!("Failed to get last synced epoch from chains state db, probably corupted. Syncing from zero...");
    } else if get_ci_res == "0" {
        info!("First time sync detected.");
    } else {
        let res = getData(config().db_path + &"/epochs".to_owned(), &get_ci_res);
        if res == "-1".to_owned() || res == "0".to_owned() {
            warn!("Failed to epoch number for hash: {} from epoches db, probably corupted. Syncing from zero...", get_ci_res);
        } else if res == "0".to_owned() {
            warn!("Cant find epoch with hash: {} in epoches db. probably a result of a terminated sync", get_ci_res);
        } else {
            let _epoch: Epoch = Epoch::default();
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
    let print_synced_every: u64;
    match amount_to_sync {
        0..=100 => print_synced_every = 10,
        101..=500 => print_synced_every = 50,
        501..=1000 => print_synced_every = 100,
        1001..=10000 => print_synced_every = 500,
        10001..=50000 => print_synced_every = 2000,
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
                &"topblockhash".to_string(),
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
                    &inventory.height.to_string(),
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
                        "Synced {} / {} inventories. Only {} to go!",
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
    } else {
        // now we check that we have got all the inventories
        // we ask the peer we just synce from for a merkle root hash of their inventories db and do the same on ours
        if let Ok(mut a) = peer_to_use_unwraped.try_clone() {
            sendData("*".to_owned(), &mut a, 0x1b).unwrap();
            let mut buf = [0; 128];
            // TODO: if the peer does not respond with a hash within say 20 secconds choose a new peer, get sync ack and start asking them for blocks (not invs though)
            loop {
                let peek_res = a.peek(&mut buf);
                if let Ok(amount) = peek_res {
                    if amount != 0 {
                        break;
                    }
                }
            }
            // we can now read the hash
            if let Err(_) = a.read(&mut buf) {
                if let Err(_) = a.read(&mut buf) {
                    // TODO: choose a new peer, get sync ack and start asking them for blocks (not invs though)
                }
            }
            let hash = String::from_utf8(buf.to_vec()).unwrap_or("error".to_owned());
            if hash != "error".to_owned() {}
        }
        // time to download blocks
        // first we make a iter of all the invs we have saved
        if let Ok(db) = openDb(config().db_path + &"/chains".to_owned()) {
            let mut chainiter = db.raw_iterator();
            chainiter.seek_to_first();
            while chainiter.valid() {
                if let Some(chain) = chainiter.value() {
                    if let Ok(chain_string) = String::from_utf8(chain) {
                        if let Ok(inv_db) = openDb(
                            config().db_path + &"/".to_owned() + &chain_string + &"-inv".to_owned(),
                        ) {
                            let mut iter = inv_db.raw_iterator();
                            iter.seek_to_first();
                            if let Some(inv) = iter.value() {
                                if let Ok(inv_string) = String::from_utf8(inv) {
                                    let inv_des: Inventory =
                                        serde_json::from_str(&inv_string).unwrap_or_default();
                                    if inv_des == Inventory::default() {
                                        warn!(
                                            "Failed to parse inventory from: {}, likley corrupted DB",
                                            inv_string
                                        );
                                    } else {
                                        trace!(
                                            "Saw inv: index: {:?}, value: {:?}",
                                            iter.key(),
                                            iter.value()
                                        );
                                        let block: String = String::from_utf8(
                                            iter.value().unwrap_or(b"get value failed".to_vec()),
                                        )
                                        .unwrap_or("get value failed".to_string());
                                        if getBlockFromRaw((&block).to_string()) != Block::default()
                                        {
                                            // we have this block already
                                            iter.next();
                                        } else {
                                            if let Ok(mut a) = peer_to_use_unwraped.try_clone() {
                                                sendData(block, &mut a, 0x1a).unwrap();
                                                let mut buf = [0; 2048];
                                                // TODO: if the peer does not respond with a block within say 20 secconds choose a new peer, get sync ack and start asking them for blocks (not invs though)
                                                loop {
                                                    let peek_res = a.peek(&mut buf);
                                                    if let Ok(amount) = peek_res {
                                                        if amount != 0 {
                                                            break;
                                                        }
                                                    }
                                                }
                                                // we can now read the block
                                                if let Err(_) = a.read(&mut buf) {
                                                    if let Err(_) = a.read(&mut buf) {
                                                        // TODO: choose a new peer, get sync ack and start asking them for blocks (not invs though)
                                                    }
                                                }
                                                let block: Block = serde_json::from_str(
                                                    &(String::from_utf8(buf.to_vec())
                                                        .unwrap_or_default()),
                                                )
                                                .unwrap_or_default();
                                                if block == Block::default() {
                                                    // TODO: reget the block, if this fails 3 or more times then choose a new peer and try again with them
                                                } else {
                                                    // TODO: validate the block, if valid save it then enact the block and its transacions
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    warn!(
                                        "Found corrupted inventory at key: {}",
                                        String::from_utf8(iter.key().unwrap_or(
                                            b"error getting index, (key err)".to_owned().to_vec()
                                        ))
                                        .unwrap_or("error getting index (utf8 err)".to_owned())
                                    );
                                }
                            }
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
        let mut data = [0 as u8; 200];
        let mut peer_clone: TcpStream;
        if let Ok(peer) = stream.try_clone() {
            peer_clone = peer;
        } else {
            return Err("failed to clone stream".into());
        }
        match stream.read(&mut data) {
            Ok(_) => {
                match deformMsg(&String::from_utf8(data.to_vec()).unwrap(), &mut peer_clone) {
                    Some(_a) => {
                        let handshake_string = "handshake".to_owned();
                        match _a {
                            handshake_string => {
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
                                // send our handshake
                            }
                            _ => {
                                // we can ignore all other things bcause they don't require our action :), deform message does it.
                            }
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
fn rec_server() -> u8 {
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
    match deformMsg(&String::from_utf8(buffer_n.to_vec())?, &mut peer_clone) {
        Some(x) => {
            pid = x;
        }
        None => {
            warn!("Got no Id from peer");
            return Err("Got no id".into());
        }
    };
    let info = PeerTracker {
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

fn process_handshake(s: String, peer: &mut TcpStream) -> Result<String, String> {
    trace!("Handshake: {}", s);
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
        drop(s);
        let v: Vec<&str> = val.split("*").collect();
        id = v[0].to_string();
    }
    debug!("Handshook with peer, gave id {}", id);
    let id_cow = Cow::from(&id);
    if let Ok(addr) = peer.peer_addr() {
        let _ = saveData(
            addr.ip().to_string() + &":".to_string() + &addr.port().to_string(),
            config().db_path + &"/peers".to_owned(),
            (&id_cow).to_string(),
        );
        return Ok((&id_cow).to_string());
    } else {
        return Err("Failed to get peer addr".into());
    }
}
pub fn sendInventoriesDigest(peer: &mut TcpStream, amount: String) {
    ()
}

pub enum p2p_errors {
    None,
    TimeOut,
    InvalidSocket,
    Other,
}

pub fn sendData(data: String, peer: &mut TcpStream, msg_type: u16) -> Result<(), std::io::Error> {
    // This function takes some data as a string and places it into a struct before sending to the peer
    let data_s: String = formMsg(data, msg_type);
    let sent = peer.write_all(data_s.as_bytes());
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

fn deformMsg(msg: &String, peer: &mut TcpStream) -> Option<String> {
    // deforms message and excutes appropriate function to handle resultant data
    let v: Vec<&str> = msg.split("}").collect();
    let msg_c = v[0].to_string() + &"}".to_string();
    trace!("recive: {}", msg_c);
    drop(v);
    let msg_d: P2pdata = serde_json::from_str(&msg_c).unwrap_or_else(|e| {
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
                let path = config.db_path;
                let height_from: u64 = getBlockFromRaw(from.clone()).header.height;
                let b = getData(
                    path + &"/hashbynetworkheight".to_string(),
                    &(height_from + d.amount as u64).to_string(),
                );
                if b == "-1".to_string() || b == "0".to_string() {
                    return None;
                } else {
                    let block: Block = serde_json::from_str(&b).unwrap_or_default();
                    to = block.hash;
                }
            }
            sendInventories(from, to, peer);
            return Some("inventories".to_owned());
        }
        0x05 => {
            sendBlock(msg_d.message, peer);
            return Some("sendblock".into());
        }
        0x01 => {
            process_message(msg_d.message);
            return Some("message".into());
        }
        0x0a => {
            process_block(msg_d.message);
            return Some("getblock".into());
        }
        0x1a => {
            if let Ok(_) = process_handshake(msg_d.message, peer) {
                return Some("handshake".to_string());
            } else {
                return None;
            }
        }
        0x1b => {
            sendInventoriesDigest(peer, msg_d.message);
            return Some("sendinvdig".into());
        }
        0x1c => {
            sendChainDigest(peer);
            return Some("sendchaindigest".into());
        }
        _ => {
            warn!("Bad Messge type from peer. Message type: {}. (If you are getting, lots of these check for updates)", "0x".to_owned() + &hex::encode(msg_d.message_type.to_string()));
            return None;
        }
    }
}
