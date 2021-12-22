use crate::{
    format::P2pData,
    io::{read, send},
    peer::{get_peers_addr, lock, locked, unlock_peer},
    utils::*,
};
use avrio_config::config;
use avrio_core::{block::{from_compact, get_block_from_raw, save_block, Block}, chunk::BlockChunk, states::form_state_digest, validate::Verifiable};
use avrio_database::get_data;

//use bson;
use log::*;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::net::{SocketAddr, TcpStream};
use std::thread;

pub fn get_peerlist_from_peer(peer: &SocketAddr) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    debug!("Prelocked");
    let mut peer_lock = lock(peer, 1000)?;
    trace!("Locked");
    send("".to_string(), &mut peer_lock, 0x8f, true, None)?;
    let peerlist_ser = read(&mut peer_lock, Some(20000), None)?; // wait for 20 secs
    let peerlist: Vec<SocketAddr> = serde_json::from_str(&peerlist_ser.message)?;
    unlock_peer(peer_lock).unwrap();
    Ok(peerlist)
}

pub fn sync_needed() -> Result<bool, Box<dyn Error>> {
    let mut chain_digests: Vec<String> = vec![];
    for peer in get_peers_addr().unwrap_or_default() {
        // ask every connected peer for their chain digest
        trace!("Getting chain digest for peer: {:?}", peer);
        let mut peer_stream = lock(&peer, 1000)?;
        chain_digests.push(get_chain_digest_string(&mut peer_stream, true));
        unlock_peer(peer_stream)?;
    }
    if chain_digests.is_empty() {
        // if we get no chain digests
        trace!("Got not chain digests");
        Ok(true) // should we not return an error or at least false?
    } else {
        // we got at least one chain digest
        // find the most common chain digest
        let mode: String = get_mode(chain_digests.clone());
        let ours = get_data(config().db_path + &"/chaindigest".to_owned(), &"master");
        debug!(
            "Chain digests: {:#?}, mode: {}, ours: {}",
            chain_digests, mode, ours
        );
        if ours == mode {
            // we have the most common chain digest, we are 'up-to date'
            Ok(false)
        } else {
            //  we are not on the most common chain digest, sync with any peers with that digest
            Ok(true)
        }
    }
}

/// # Prop_block
/// Sends a block to all connected peers.
/// # Returns
/// a result enum conatining the error encountered or a u64 of the number of peers we sent to and got a block ack response from
/// Once proof of node is in place it will send it only to the relevant comitee.
pub fn prop_block(blk: &Block) -> Result<u64, Box<dyn std::error::Error>> {
    let mut i: u64 = 0;
    for peer in get_peers_addr()?.iter_mut() {
        debug!("Sending block to peer: {:?}", peer);
        let mut peer_stream = lock(peer, 10000)?;
        let send_res = send_block_struct(blk, &mut peer_stream);
        if send_res.is_ok() {
            i += 1;
        } else {
            trace!(
                "error sending block to peer {}, error={}",
                peer_stream.peer_addr()?,
                send_res.unwrap_err()
            );
        }
        let _ = unlock_peer(peer_stream)?;
    }
    trace!("Sent block {} to {} peers", blk.hash, i);
    let _ = avrio_rpc::block_announce(blk.clone());
    Ok(i)
}

/// # Prop_block_chunk
/// Sends a block chunk to all connected peers.
/// # Returns
/// a result enum conatining the error encountered or a u64 of the number of peers we sent to and got a block chunk ack response from
pub fn prop_block_chunk(bc: &BlockChunk) -> Result<u64, Box<dyn std::error::Error>> {
    let mut i: u64 = 0;
    for peer in get_peers_addr()?.iter_mut() {
        debug!("Sending block to peer: {:?}", peer);
        let mut peer_stream = lock(peer, 10000)?;
        let send_res = send_block_chunk_struct(bc, &mut peer_stream);
        if send_res.is_ok() {
            i += 1;
        } else {
            trace!(
                "error sending block chunk to peer {}, error={}",
                peer_stream.peer_addr()?,
                send_res.unwrap_err()
            );
        }
        let _ = unlock_peer(peer_stream)?;
    }
    trace!("Sent block {} to {} peers", bc.hash, i);
    Ok(i)
}

/// # Prop_block
/// Sends a block to all connected peers.
/// # Returns
/// a result enum conatining the error encountered or a u64 of the number of peers we sent to and got a block ack response from
/// Once proof of node is in place it will send it only to the relevant comitee.
pub fn prop_block_with_ignore(
    blk: &Block,
    ignore_peer: &SocketAddr,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut i: u64 = 0;
    for peer in get_peers_addr()?.iter() {
        if peer != ignore_peer {
            debug!("Sending block to peer: {:?}", peer);
            let mut peer_stream = lock(peer, 5000)?;
            let send_res = send_block_struct(blk, &mut peer_stream);
            if send_res.is_ok() {
                i += 1;
            } else {
                trace!(
                    "error sending block to peer {}, error={}",
                    peer_stream.peer_addr()?,
                    send_res.unwrap_err()
                );
            }
            let _ = unlock_peer(peer_stream)?;
        }
    }
    trace!("Sent block {} to {} peers", blk.hash, i);
    Ok(i)
}

/// This is a cover all sync function that will sync all chains and covers getting the top index and syncing from there
/// for more controll over your sync you should call the sync_chain function which will sync only the chain specifyed.
/// pl is a vector of mutable refrences of TcpStreams (Vec<&mut TcpStream>), this function finds the most common chain digest
/// and then chooses the fasted peer with that chain digest and uses it. After it thinks it has finished syncing it will choose
/// a random peer and check random blocks are the same. If you wish to use the sync function with only one peer pass a vector
/// containing only that peer. Please note this means it will not be able to verify that it has not missed blocks afterwards if
/// the peer is malicously withholding them. For this reason only do this if you trust the peer or will be checking the blockchain
/// with a diferent peer afterwards.
pub fn sync() -> Result<u64, String> {
    error!("You probably meant to call sync_in_order()");
    let mut pl = get_peers_addr().unwrap_or_default(); // list of all socket addrs
    std::thread::sleep(std::time::Duration::from_millis(500)); // wait 0.5 (500ms) seccond to ensure handler thread is paused
    if pl.is_empty() {
        return Err("Must have at least one peer to sync from".into());
    }

    let mut _peers: Vec<TcpStream> = vec![];
    let _pc: u32 = 0;
    let _i: usize = 0;
    let mut chain_digests: Vec<ChainDigestPeer> = vec![];

    for peer in pl.iter_mut() {
        //let _ = lock_peer(&peer.peer_addr().unwrap().to_string()).unwrap();

        if let Ok(peer_new) = lock(peer, 1000) {
            let mut cloned_peer = peer_new.try_clone().unwrap();
            _peers.push(peer_new);
            let handle = thread::Builder::new()
                .name("getChainDigest".to_string())
                .spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(1000)); // wait 350ms for the handler thread to see our message and stop. TODO: wait for a response from the thread instead
                    log::trace!("Get chain digest waited 100ms, proceeding");
                    let chain_digest = get_chain_digest(&mut cloned_peer, false);

                    if chain_digest.digest == " " {
                        ChainDigestPeer {
                            peer: Some(cloned_peer),
                            digest: " ".to_string(),
                        }
                    } else {
                        chain_digest
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
    // let chainDigestsLen = chain_digests.len();

    for hash in chain_digests.iter() {
        hashes.push(hash.digest.clone());
    }

    let mode_hash = get_mode(hashes);
    let mut peer_to_use: Option<TcpStream> = None;
    let _i: u64 = 0;

    for i in &chain_digests {
        if *i.digest == mode_hash {
            if let Some(peer_) = &i.peer {
                peer_to_use = Some(peer_.try_clone().unwrap());
            }
        }
    }

    drop(chain_digests);
    let mut peer_to_use_unwraped: TcpStream = peer_to_use.unwrap();

    // Now unlock all peers we are not going to be using
    let peer_to_use_addr = peer_to_use_unwraped.peer_addr().unwrap();
    for peer in _peers.iter_mut() {
        if peer.peer_addr().unwrap() != peer_to_use_addr {
            // Clone the peer var to get a Stream object (rather than a mutable refrence), pass that to unlock_peer then
            // after this loop drop the _peers list to destroy all the og streams
            unlock_peer(peer.try_clone().unwrap()).unwrap();
        }
    }
    drop(_peers); // destroy all remaining streams

    let try_ack = syncack_peer(&mut peer_to_use_unwraped);
    if let Err(e) = try_ack {
        error!("Got error: {} when sync acking peer. Releasing lock", e);
        unlock_peer(peer_to_use_unwraped).unwrap();
        // TODO sync ack the next fastest peer until we have peer (1)
        return Err("rejected sync ack".into());
    } else {
        // Relock peer
        //lock_peer(&peer_to_use_unwraped.peer_addr().unwrap().to_string()).unwrap();

        // We have locked the peer now we ask them for their list of chains
        // They send their list of chains as a vec of strings
        if let Err(e) = send("".to_owned(), &mut peer_to_use_unwraped, 0x60, true, None) {
            error!("Failed to request chains list from peer gave error: {}", e);
            // TODO: *1
            return Err("failed to send get chain list message".into());
        } else {
            let mut buf = [0; 10024];
            let mut no_read = true;

            while no_read {
                if let Ok(a) = peer_to_use_unwraped.peek(&mut buf) {
                    if a == 0 {
                    } else {
                        no_read = false;
                    }
                }
            }

            // There are now bytes waiting in the stream
            let deformed = read(&mut peer_to_use_unwraped, Some(10000), None).unwrap_or_default();
            debug!("Chain list got: {:#?}", deformed);

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

                if chain_list.is_empty() {
                    return Err("empty chain list".into());
                } else {
                    for chain in chain_list.iter() {
                        info!("Starting to sync chain: {}", chain);

                        if let Err(e) = sync_chain(chain.to_owned(), &mut peer_to_use_unwraped) {
                            error!("Failed to sync chain: {}, gave error: {}", chain, e);
                            return Err(format!("failed to sync chain {}", chain));
                        } else {
                            info!("Synced chain {}, moving onto next chain", chain);
                        }
                    }
                }
            }
        }
    }

    info!("Synced all chains, checking chain digest with peers");
    let cd = form_state_digest(config().db_path + "/chaindigest").unwrap(); //  recalculate our state digest
    if cd != mode_hash {
        error!("Synced blocks do not result in mode block hash, if you have appended blocks (using send_txn or generate etc) then ignore this. If not please delete your data dir and resync");
        error!("Our CD: {}, expected: {}", cd, mode_hash);

        return sync(); // this should sync again, why is it not?
    } else {
        info!("Finalised syncing, releasing lock on peer");
        let _ = unlock_peer(peer_to_use_unwraped).unwrap();
    }

    Ok(1)
}
pub fn sync_in_order() -> Result<u64, Box<dyn std::error::Error>> {
    let mut pl = get_peers_addr().unwrap_or_default(); // list of all socket addrs
    std::thread::sleep(std::time::Duration::from_millis(500)); // wait 0.5 (500ms) seccond to ensure handler thread is paused
    if pl.is_empty() {
        return Err("Must have at least one peer to sync from".into());
    }

    let mut _peers: Vec<TcpStream> = vec![];
    let _pc: u32 = 0;
    let _i: usize = 0;
    let mut chain_digests: Vec<ChainDigestPeer> = vec![];

    for peer in pl.iter_mut() {
        if let Ok(peer_new) = lock(peer, 1000) {
            let mut cloned_peer = peer_new.try_clone().unwrap();
            _peers.push(peer_new);
            let handle = thread::Builder::new()
                .name("getChainDigest".to_string())
                .spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(1000)); // wait 350ms for the handler thread to see our message and stop. TODO: wait for a response from the thread instead
                    log::trace!("Get chain digest waited 100ms, proceeding");
                    let chain_digest = get_chain_digest(&mut cloned_peer, false);

                    if chain_digest.digest == " " {
                        ChainDigestPeer {
                            peer: Some(cloned_peer),
                            digest: " ".to_string(),
                        }
                    } else {
                        chain_digest
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
    // let chainDigestsLen = chain_digests.len();

    for hash in chain_digests.iter() {
        hashes.push(hash.digest.clone());
    }

    let mode_hash = get_mode(hashes);
    let mut peer_to_use: Option<TcpStream> = None;
    let _i: u64 = 0;

    for i in &chain_digests {
        if *i.digest == mode_hash {
            if let Some(peer_) = &i.peer {
                peer_to_use = Some(peer_.try_clone().unwrap());
            }
        }
    }

    drop(chain_digests);
    let mut peer_to_use_unwraped: TcpStream = peer_to_use.unwrap();

    // Now unlock all peers we are not going to be using
    let peer_to_use_addr = peer_to_use_unwraped.peer_addr().unwrap();
    for peer in _peers.iter_mut() {
        if peer.peer_addr().unwrap() != peer_to_use_addr {
            // Clone the peer var to get a Stream object (rather than a mutable refrence), pass that to unlock_peer then
            // after this loop drop the _peers list to destroy all the og streams
            unlock_peer(peer.try_clone().unwrap()).unwrap();
        }
    }
    drop(_peers); // destroy all remaining stream clones

    let try_ack = syncack_peer(&mut peer_to_use_unwraped);
    if let Err(e) = try_ack {
        error!("Got error: {} when sync acking peer. Releasing lock", e);
        unlock_peer(peer_to_use_unwraped).unwrap();
        // TODO sync ack the next fastest peer until we have peer (1)
        return Err("rejected sync ack".into());
    } else {
        // as we are syncing in ordered mode, we now ask the peer for their total block count
        if let Err(e) = send(
            "".to_string(),
            &mut &mut peer_to_use_unwraped,
            0x47,
            true,
            None,
        ) {
            error!(
                "Failed to ask peer for their global block height, error={}",
                e
            );
            return Err("could not get global block height".into());
        } else {
            let try_read_gh = read(&mut &mut peer_to_use_unwraped, Some(1000), None);
            if let Ok(global_block_height) = try_read_gh {
                if let Ok(amount_to_sync) = global_block_height.message.parse::<u64>() {
                    info!("Got global block height from peer: {}", amount_to_sync);
                    if amount_to_sync == 0 {
                        let _ = unlock_peer(peer_to_use_unwraped).unwrap();
                        return Ok(0);
                    }
                    let print_synced_every: u64;
                    match amount_to_sync {
                        0..=49 => print_synced_every = 1,
                        50..=100 => print_synced_every = 5,
                        101..=500 => print_synced_every = 10,
                        501..=1000 => print_synced_every = 50,
                        1001..=10000 => print_synced_every = 100,
                        10001..=50000 => print_synced_every = 500,
                        _ => print_synced_every = 5000,
                    }
                    let mut buf = [0; 2048];

                    let mut top_block_hash: String;
                    let peer = &mut peer_to_use_unwraped;
                    top_block_hash =
                        get_data(config().db_path + "/globalindex", "globaltopblockhash");
                    if top_block_hash == "-1" {
                        top_block_hash = "0".to_string();
                        if let Err(e) = send(serde_json::to_string(&0)?, peer, 0x7f, true, None) {
                            error!(
                                "Asking peer for their blocks above hash: {} (globally) gave error: {}",
                                top_block_hash, e
                            );
                            let _ =
                                send("".to_string(), &mut peer_to_use_unwraped, 0x23, true, None);
                            return Err(e);
                        }
                    } else if let Err(e) = send(
                        serde_json::to_string(&top_block_hash)?,
                        peer,
                        0x7f,
                        true,
                        None,
                    ) {
                        error!(
                            "Asking peer for their blocks above hash: {} (globally) gave error: {}",
                            top_block_hash, e
                        );
                        let _ = send("".to_string(), &mut peer_to_use_unwraped, 0x23, true, None);
                        return Err(e);
                    }

                    let mut synced_blocks: u64 = 0;
                    let mut invalid_blocks: u64 = 0;

                    info!(
                        "Getting {} blocks from peer: {}, from block hash: {}",
                        amount_to_sync,
                        peer.peer_addr().unwrap(),
                        top_block_hash
                    );

                    loop {
                        let mut no_read: bool = true;

                        while no_read {
                            if let Ok(a) = peer.peek(&mut buf) {
                                if a == 0 {
                                } else {
                                    no_read = false;
                                }
                            }
                        }

                        // There are now bytes waiting in the stream
                        let deformed: P2pData = read(peer, Some(1000), None).unwrap_or_else(|e| {
                            error!("Failed to read p2pdata: {}", e);
                            P2pData::default()
                        });

                        trace!(target: "avrio_p2p::sync", "got blocks: {:#?}", deformed);

                        if deformed.message_type == 0x04 {
                            let blocks_encoded: Vec<String> =
                                serde_json::from_str(&deformed.message).unwrap_or_default();
                            let mut blocks: Vec<Block> = vec![];
                            for encoded in blocks_encoded {
                                match from_compact(encoded.clone()) {
                                    Ok(block) => blocks.push(block),
                                    Err(e) => error!("Failed to decode compact block from peer, gave error={}, encoded={}", e, encoded),
                                }
                            }
                            if !blocks.is_empty() {
                                trace!(
                                    "Got: {} blocks from peer. Hash: {} up to: {}",
                                    blocks.len(),
                                    blocks[0].hash,
                                    blocks[blocks.len() - 1].hash
                                );

                                for block in blocks {
                                    if let Err(e) = block.valid() {
                                        error!("Recieved invalid block with hash: {} from peer, validation gave error: {:#?}. Invalid blocks from peer: {}", block.hash, e, invalid_blocks);
                                        invalid_blocks += 1;
                                    } else {
                                        save_block(block.clone())?;
                                        block.enact()?;
                                        synced_blocks += 1;
                                    }
                                    if synced_blocks % print_synced_every == 0 {
                                        info!(
                                            "Synced {} / {} blocks (global) {} more to go",
                                            synced_blocks,
                                            amount_to_sync,
                                            amount_to_sync - synced_blocks
                                        );
                                    }
                                }
                            } else {
                                error!(
                                    "Got empty block vec from peer, synced={}, expected={}",
                                    synced_blocks, amount_to_sync
                                );
                                warn!("Assuming done");
                                break;
                            }
                        }

                        if synced_blocks >= amount_to_sync {
                            info!("Synced all {} blocks", synced_blocks);
                            break;
                        }

                        let top_block_hash: String;

                        top_block_hash =
                            get_data(config().db_path + "/globalindex", "globaltopblockhash");

                        trace!("Asking peer for blocks above hash: {}", top_block_hash);

                        if top_block_hash == "-1" {
                            if let Err(e) = send(serde_json::to_string(&0)?, peer, 0x7f, true, None)
                            {
                                error!(
                                    "Asking peer for their blocks above hash: {} (globally) gave error: {}",
                                    top_block_hash, e
                                );
                                let _ = send(
                                    "".to_string(),
                                    &mut peer_to_use_unwraped,
                                    0x23,
                                    true,
                                    None,
                                );
                                return Err(e);
                            }
                        } else if let Err(e) = send(
                            serde_json::to_string(&top_block_hash)?,
                            peer,
                            0x7f,
                            true,
                            None,
                        ) {
                            error!(
                                "Asking peer for their blocks above hash: {} (globally) gave error: {}",
                                top_block_hash, e
                            );
                            let _ =
                                send("".to_string(), &mut peer_to_use_unwraped, 0x23, true, None);
                            return Err(e);
                        }
                    }
                    info!("Synced all blocks, checking chain digest with peers");
                    let cd = form_state_digest(config().db_path + "/chaindigest").unwrap(); //  recalculate our state digest
                    if cd != mode_hash {
                        error!("Synced blocks do not result in mode block hash, if you have appended blocks (using send_txn or register_username etc) then ignore this. If not please delete your data dir and resync");
                        error!("Our CD: {}, expected: {}", cd, mode_hash);
                        let _ = send("".to_string(), &mut peer_to_use_unwraped, 0x23, true, None);
                        return sync_in_order(); // try syncing again
                    } else {
                        info!("Finalised syncing, releasing lock on peer");
                        let _ = send("".to_string(), &mut peer_to_use_unwraped, 0x23, true, None)
                            .unwrap();
                        let _ = unlock_peer(peer_to_use_unwraped).unwrap();
                    }

                    return Ok(1);
                }
            }
        }
    }

    info!("Synced all chains, checking chain digest with peers");
    let cd = form_state_digest(config().db_path + "/chaindigest").unwrap(); //  recalculate our state digest
    if cd != mode_hash {
        error!("Synced blocks do not result in mode block hash, if you have appended blocks (using send_txn or generate etc) then ignore this. If not please delete your data dir and resync");
        error!("Our SD: {}, expected: {}", cd, mode_hash);
    } else {
        info!("Finalised syncing, releasing lock on peer");
        let _ = unlock_peer(peer_to_use_unwraped).unwrap();
    }

    Ok(1)
}
/// This function syncs the specifyed chain only from the peer specifyed.
/// It returns Ok(()) on succsess and handles the inventory generation, inventory saving, block geting, block validation,
/// block saving, block enacting and informing the user of the progress.
/// If you simply want to sync all chains then use the sync function bellow.
pub fn sync_chain(chain: String, peer: &mut TcpStream) -> Result<u64, Box<dyn std::error::Error>> {
    let _ = send(
        chain.to_owned(),
        &mut peer.try_clone().unwrap(),
        0x45,
        true,
        None,
    );
    let mut buf = [0; 2048];
    let mut no_read = true;

    while no_read {
        if let Ok(a) = peer.try_clone().unwrap().peek(&mut buf) {
            if a == 0 {
            } else {
                no_read = false;
            }
        }
    }

    // There are now bytes waiting in the stream
    let deformed: P2pData = read(peer, Some(10000), None).unwrap_or_else(|e| {
        error!("Failed to read p2pdata: {}", e);
        P2pData::default()
    });

    let amount_to_sync: u64;

    if deformed.message_type != 0x46 {
        warn!("Got wrong block count message from peer, this could cause syncing issues!");
        amount_to_sync = 0;
    } else {
        amount_to_sync = deformed.message.parse().unwrap_or_else(|e| {
            warn!("Failed to parse block count msg, gave error: {}", e);
            0
        });
    }

    let print_synced_every: u64;
    info!("Got to get {} blocks for chain: {}", amount_to_sync, chain);

    match amount_to_sync {
        0..=49 => print_synced_every = 1,
        50..=100 => print_synced_every = 5,
        101..=500 => print_synced_every = 10,
        501..=1000 => print_synced_every = 50,
        1001..=10000 => print_synced_every = 100,
        10001..=50000 => print_synced_every = 500,
        _ => print_synced_every = 5000,
    }

    let top_block_hash: String;
    // let opened_db: rocksdb::DB;
    top_block_hash = get_data(
        config().db_path + "/chains/" + &chain + "-chainindex",
        "topblockhash",
    );

    if top_block_hash == "-1" {
        if let Err(e) = send(
            serde_json::to_string(&(&"0".to_owned(), &chain))?,
            peer,
            0x6f,
            true,
            None,
        ) {
            error!(
                "Asking peer for their blocks above hash: {} for chain: {} gave error: {}",
                top_block_hash, chain, e
            );
            return Err(e);
        }
    } else if let Err(e) = send(
        serde_json::to_string(&(&top_block_hash, &chain))?,
        peer,
        0x6f,
        true,
        None,
    ) {
        error!(
            "Asking peer for their blocks above hash: {} for chain: {} gave error: {}",
            top_block_hash, chain, e
        );
        return Err(e);
    }

    let mut synced_blocks: u64 = 0;
    let mut invalid_blocks: u64 = 0;

    info!(
        "Getting {} blocks from peer: {}, from block hash: {}",
        amount_to_sync,
        peer.peer_addr().unwrap(),
        top_block_hash
    );

    loop {
        let mut no_read: bool = true;
        while no_read {
            if let Ok(a) = peer.peek(&mut buf) {
                if a == 0 {
                } else {
                    no_read = false;
                }
            }
        }

        // There are now bytes waiting in the stream
        let deformed: P2pData = read(peer, Some(10000), None).unwrap_or_else(|e| {
            error!("Failed to read p2pdata: {}", e);
            P2pData::default()
        });

        trace!(target: "avrio_p2p::sync", "got blocks: {:#?}", deformed);

        if deformed.message_type == 0x04 {
            let blocks_encoded: Vec<String> =
                serde_json::from_str(&deformed.message).unwrap_or_default();
            let mut blocks: Vec<Block> = vec![];
            for encoded in blocks_encoded {
                match from_compact(encoded.clone()) {
                    Ok(block) => blocks.push(block),
                    Err(e) => error!(
                        "Failed to decode compact block from peer, gave error={}, encoded={}",
                        e, encoded
                    ),
                }
            }
            if !blocks.is_empty() {
                trace!(
                    "Got: {} blocks from peer. Hash: {} up to: {}",
                    blocks.len(),
                    blocks[0].hash,
                    blocks[blocks.len() - 1].hash
                );

                for block in blocks {
                    if let Err(e) = block.valid() {
                        error!("Recieved invalid block with hash: {} from peer, validation gave error: {:#?}. Invalid blocks from peer: {}", block.hash, e, invalid_blocks);
                        invalid_blocks += 1;
                    } else {
                        save_block(block.clone())?;
                        block.enact()?;
                        synced_blocks += 1;
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
            } else {
                error!(
                    "Got empty block vec from peer, synced={}, expected={}",
                    synced_blocks, amount_to_sync
                );
                warn!("Assuming done");
                break;
            }
        }

        if synced_blocks >= amount_to_sync {
            info!("Synced all {} blocks for chain: {}", synced_blocks, chain);
            break;
        }

        let top_block_hash: String;

        top_block_hash = get_data(
            config().db_path + "/chains/" + &chain + "-chainindex",
            "topblockhash",
        );

        trace!("Asking peer for blocks above hash: {}", top_block_hash);

        if top_block_hash == "-1" {
            if let Err(e) = send(
                serde_json::to_string(&(&"0", &chain))?,
                peer,
                0x6f,
                true,
                None,
            ) {
                error!(
                    "Asking peer for their blocks above hash: {} for chain: {} gave error: {}",
                    top_block_hash, chain, e
                );
                return Err(e);
            }
        } else if let Err(e) = send(
            serde_json::to_string(&(&top_block_hash, &chain))?,
            peer,
            0x6f,
            true,
            None,
        ) {
            error!(
                "Asking peer for their blocks above hash: {} for chain: {} gave error: {}",
                top_block_hash, chain, e
            );
            return Err(e);
        }
    }
    Ok(amount_to_sync)
}

pub fn send_block_struct(block: &Block, peer: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    if block.hash == Block::default().hash {
        Err("tried to send default block".into())
    } else {
        let block_ser: String = block.encode_compressed(); // serilise the block into bson

        if let Err(e) = send(block_ser, peer, 0x04, true, None) {
            Err(e)
        } else {
            Ok(())
        }
    }
}

pub fn send_block_chunk_struct(bc: &BlockChunk, peer: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    if bc.hash == String::default() {
        Err("tried to send default block chunk".into())
    } else {
        let block_ser: String = bc.encode()?; // serilise the block into bson

        if let Err(e) = send(block_ser, peer, 0x50, true, None) {
            Err(e)
        } else {
            Ok(())
        }
    }
}

pub fn send_block_with_hash(hash: String, peer: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let block = get_block_from_raw(hash);
    if block.hash == Block::default().hash {
        Err("block does not exist".into())
    } else {
        let block_ser: String = bson::to_bson(&block)?.to_string();

        if let Err(e) = send(block_ser, peer, 0x04, true, None) {
            Err(e)
        } else {
            Ok(())
        }
    }
}

// -- Sync assist functions and structures-- //
// these should all be private, DO NOT PUBLICIZE THEM //

/// This function asks the peer to sync, if they accept you can begin syncing
fn syncack_peer(peer: &mut TcpStream) -> Result<TcpStream, Box<dyn Error>> {
    //lock(&peer.peer_addr().unwrap(), 10000);

    let syncreqres = send(
        "syncreq".to_owned(),
        &mut peer.try_clone().unwrap(),
        0x22,
        true,
        None,
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

    while no_read {
        if let Ok(a) = peer.peek(&mut buf) {
            if a == 0 {
            } else {
                no_read = false;
            }
        }
    }

    // There are now bytes waiting in the stream
    let deformed: P2pData = read(peer, Some(10000), None).unwrap_or_default();

    if deformed.message == *"syncack" {
        info!("Got syncack from selected peer. Continuing");

        Ok(peer.try_clone()?)
    } else if deformed.message == *"syncdec" {
        info!("Peer rejected sync request, choosing new peer...");

        // choose the next fastest peer from our socket list
        Err("rejected syncack".into())
    } else {
        info!("Recieved incorect message from peer (in context syncrequest). Message: {}. This could be caused by outdated software - check you are up to date!", deformed.message);
        info!("Retrying syncack with same peer...");

        // try again
        syncack_peer(&mut peer.try_clone()?)
    }
}

fn get_chain_digest_string(peer: &mut TcpStream, _unlock: bool) -> String {
    let mut tries = 0;
    loop {
        let _ = send("".to_owned(), peer, 0x1c, true, None);
        let msg = read(peer, Some(10000), None).unwrap_or_else(|e| {
            error!("Failed to read p2pdata: {}", e);
            P2pData::default()
        });
        if msg.message_type == 0xcd {
            return msg.message;
        }
        tries += 1;
        if tries >= 5 {
            return String::from("-1");
        }
    }
}

/// this asks the peer for their chain digest
fn get_chain_digest(peer: &mut TcpStream, _unlock: bool) -> ChainDigestPeer {
    while !locked(&peer.peer_addr().unwrap()).unwrap() {
        log::trace!("NOT LOCKED GCD");
    }
    let _ = send("".to_owned(), peer, 0x1c, true, None);

    let read = read(peer, Some(10000), None).unwrap_or_else(|e| {
        error!("Failed to read p2pdata: {}", e);
        P2pData::default()
    });

    let peer_n = peer.try_clone();

    if let Ok(peer_new) = peer_n {
        ChainDigestPeer {
            peer: Some(peer_new),
            digest: read.message,
        }
    } else {
        ChainDigestPeer {
            digest: "".to_string(),
            peer: None,
        }
    }
}

/// Struct for easily encoding data needed for the sorting of chain digests (used for choosing which peer/s to sync from)
#[derive(Debug, Default)]
pub struct ChainDigestPeer {
    pub peer: Option<TcpStream>,
    pub digest: String,
}

/// Struct for easily encoding data needed when askign for inventories
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

/// Struct for easily encoding data needed for asking for blocks
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct GetBlocks {
    /// The hash of the block you want to get
    pub hash: String,
}

// -- End sync assist functions and structures-- //

// -- Fullnode assist functions and structures -- //


// -- End fullnode assist functions and structures -- //
