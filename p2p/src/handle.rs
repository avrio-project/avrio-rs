use crate::{
    core,
    format::P2pData,
    io::{peek, read, send},
    peer::remove_peer,
};

use std::{
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream},
    sync::Mutex,
    thread,
    time::{Duration, SystemTime},
};

use avrio_config::config;
use avrio_core::{
    block::{from_compact, get_block, get_block_from_raw, Block},
    chunk::BlockChunk,
    epoch::get_top_epoch,
};
use avrio_core::{
    mempool::{add_block, get_block as get_block_mempool, Caller},
    validate::Verifiable,
};
use avrio_database::{get_data, iter_database};
use avrio_rpc::block_announce;
use lazy_static::lazy_static;
use log::{debug, error, info, trace};
extern crate rand;
extern crate x25519_dalek;

pub fn block_enacted_callback(rec_from: SocketAddr, block: Block) {
    let _ = block_announce(block.clone());
    let _ = crate::helper::prop_block_with_ignore(&block, &rec_from);
}

lazy_static! {
    static ref SYNCING_PEERS: Mutex<(u64, Vec<String>)> = Mutex::new((0, vec![]));
}

fn get_syncing_peers_count() -> Result<u64, Box<dyn std::error::Error>> {
    return Ok(SYNCING_PEERS.lock()?.0);
}

fn _set_syncing_peers_count(new: u64) -> Result<(), Box<dyn std::error::Error>> {
    SYNCING_PEERS.lock()?.0 = new;
    Ok(())
}

fn increment_sync_count() -> Result<(), Box<dyn std::error::Error>> {
    let new = get_syncing_peers_count()? + 1;
    SYNCING_PEERS.lock()?.0 = new;
    Ok(())
}

fn add_peer_to_sync_list(peer: &SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let peer_no_port = crate::peer::strip_port(peer);
    if !SYNCING_PEERS.lock()?.1.iter().any(|i| i == &peer_no_port) {
        increment_sync_count()?;
        SYNCING_PEERS.lock()?.1.push(peer_no_port);
    } else {
        return Err("Peer already in syncing peers list".into());
    }
    Ok(())
}
fn peer_syncing(peer: &SocketAddr) -> Result<bool, Box<dyn std::error::Error>> {
    return Ok(SYNCING_PEERS
        .lock()?
        .1
        .iter()
        .any(|i| i == &crate::peer::strip_port(peer)));
}

fn remove_peer_from_sync_list(peer: &SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let peer_no_port = crate::peer::strip_port(peer);
    if SYNCING_PEERS.lock()?.1.iter().any(|i| i == &peer_no_port) {
        deincrement_sync_count()?;
        SYNCING_PEERS.lock()?.1.retain(|x| x != &peer_no_port);
    } else {
        return Err("Peer not in syncing peers list".into());
    }
    Ok(())
}

fn deincrement_sync_count() -> Result<(), Box<dyn std::error::Error>> {
    let new = {
        let spc = get_syncing_peers_count()?;
        if spc == 0 {
            0
        } else {
            spc - 1
        }
    };
    SYNCING_PEERS.lock()?.0 = new;
    Ok(())
}

pub fn launch_handle_client(
    rx: std::sync::mpsc::Receiver<String>,
    stream: &mut TcpStream,
    incoming: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = stream.try_clone()?;
    let ping_every: Duration = Duration::from_millis(5 * 60 * 1000);
    trace!("Cloned stream, launching thread");
    let builder = thread::Builder::new()
        .name("peer_handler".into())
        .stack_size(10 * 1000000);

    let _handler = builder.spawn(
        // thread code
        move || {
            trace!("Thread spawned");
            let mut ping_nonce = 0;
            let mut paused = false;
            let mut last_ping_time = SystemTime::now();
            loop {
                if let Ok(msg) = rx.try_recv() {
                    // check if we have been told to 'pause' and stop reading from stream
                    log::debug!("Read msg={}", msg);
                    if msg == "pause" {
                        log::trace!("Pausing stream for peer");
                        loop {
                            if let Ok(msg) = rx.try_recv() {
                                // check if we have been told to resume checking and reading from the stream
                                if msg == "run" {
                                    log::trace!("Resuming stream for peer");
                                    paused = true;
                                    break;
                                }
                            }
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    } else {
                        // this shouldnt happen so log it
                        log::error!("Got illegal rx msg {}", msg);
                    }
                } 
                
                let mut to_process_after_ping: Vec<P2pData> = vec![];
                if SystemTime::now()
                    .duration_since(last_ping_time)
                    .unwrap_or_default()
                    .as_millis()
                    >= ping_every.as_millis()
                    && !incoming
                {
                    debug!(
                        "Waited 5 mins, sending ping message with nonce: {}",
                        ping_nonce
                    );
                    if peer_syncing(&stream.peer_addr().unwrap()).unwrap_or(true) {
                        debug!("Aborting ping message: reason=Peer Syncing");
                        last_ping_time = SystemTime::now();
                    } else {
                        match send(ping_nonce.to_string(), &mut stream, 0x91, true, None) {
                            Ok(_) => {
                                debug!("Sent ping message to peer, waiting for pong");
                                let mut tries = 0;
                                const MAX_TRIES: i32 = 5;
                                loop {
                                    match read(&mut stream, Some(10000), None) {
                                        Ok(pong) => {
                                            if pong.message != ping_nonce.to_string()
                                                || pong.message_type != 0x92
                                            {
                                                if pong.message_type == 0x91 {
                                                    // the peer pinged our ping, pong them back
                                                    let _ = send(
                                                        pong.message,
                                                        &mut stream,
                                                        0x92,
                                                        true,
                                                        None,
                                                    );
                                                    last_ping_time = SystemTime::now();
                                                    break;
                                                }
                                                tries += 1;
                                                if tries == MAX_TRIES {
                                                    // close the stream
                                                    info!("Disonnected to peer {}, {} incorrect responses to PONG", stream.peer_addr()
                                                        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)), MAX_TRIES
                                                    );
                                                    let _ = send(
                                                        "".to_string(),
                                                        &mut stream,
                                                        0xff,
                                                        true,
                                                        None,
                                                    );
                                                    thread::sleep(Duration::from_micros(1000));
                                                    let _ = remove_peer(
                                                        stream.peer_addr().unwrap(),
                                                        true,
                                                    );
                                                    let _ = remove_peer(
                                                        stream.peer_addr().unwrap(),
                                                        false,
                                                    );
                                                    let _ = stream.shutdown(Shutdown::Both);
                                                    return Err("Incorrect pong response");
                                                } else {
                                                    error!("Incorrect pong response, appending to 'to_process_after_ping' vec (tries = {}/{}) (type={}, nonce={})", tries, MAX_TRIES, pong.message_type, pong.message);
                                                    to_process_after_ping.push(pong);
                                                }
                                            } else {
                                                ping_nonce += 1;
                                                debug!(
                                                    "Got pong response, new nonce={}",
                                                    ping_nonce
                                                );
                                                last_ping_time = SystemTime::now();
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!("Got error while trying to read pong message for peer, error={}", e);
                                            // close the stream
                                            let _ =
                                                send("".to_string(), &mut stream, 0xff, true, None);
                                            thread::sleep(Duration::from_micros(1000));
                                            let _ = remove_peer(stream.peer_addr().unwrap(), true);
                                            let _ = remove_peer(stream.peer_addr().unwrap(), false);
                                            let _ = stream.shutdown(Shutdown::Both);
                                            return Err("Failed to read pong message");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to send ping message to peer, gave error={}", e);
                                // close the stream
                                let _ = send("".to_string(), &mut stream, 0xff, true, None);
                                thread::sleep(Duration::from_micros(1000));
                                let _ = remove_peer(stream.peer_addr().unwrap(), true);
                                let _ = remove_peer(stream.peer_addr().unwrap(), false);
                                let _ = stream.shutdown(Shutdown::Both);
                                return Err("Failed to send ping message");
                            }
                        }
                    }
                }
                if to_process_after_ping.len() != 0 {
                    debug!(
                        "{} messages to process in to_process_after_ping vec",
                        to_process_after_ping.len()
                    );
                    for msg_to_proc in to_process_after_ping {
                        trace!("Processing msg_to_proc {}", msg_to_proc.checksum());
                        if process_handle_msg(msg_to_proc, &mut stream, &mut last_ping_time)
                            .is_some()
                        {
                            debug!("Got some while handling peer, returning");
                            return Ok(());
                        }
                    }
                }
                if let Ok(a) = peek(&mut stream) {
                    if let Ok(msg) = rx.try_recv() {
                        log::debug!("Read msg={}", msg);
                        if msg == "pause" {
                            log::trace!("Pausing stream for peer");
                            loop {
                                if let Ok(msg) = rx.try_recv() {
                                    if msg == "run" {
                                        log::trace!("Resuming stream for peer");
                                        paused = true;
                                        break;
                                    }
                                }
                                std::thread::sleep(std::time::Duration::from_millis(10));
                            }
                        } else {
                            log::error!("illegal rx msg rec={}", msg)
                        }
                    }
                    if a != 0 && !paused {
                        let read_data = read(&mut stream, Some(1000), None);
                        if let Ok(read_msg) = read_data {
                            if process_handle_msg(read_msg, &mut stream, &mut last_ping_time)
                                .is_some()
                            {
                                debug!("Got some while handling peer, returning");
                                return Ok(());
                            }
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                paused = false;
                std::thread::sleep(Duration::from_millis(50));
            }
        },
    )
    .unwrap()
    ;
    Ok(())
}

pub fn process_handle_msg(
    read_msg: P2pData,
    stream: &mut TcpStream,
    last_ping_time: &mut SystemTime,
) -> Option<String> {
    match read_msg.message_type {
        // zero type msg
        0 => {
            debug!(
                "Received a p2p message with type 0. Likeley corrupted"
            );
        }
        // generate Epoch Salt seed
        0x06 => {
            debug!("Asked to create epoch salt");
            // check if we are in the consensus commtiee and in a valid position (not round leader) to produce a epoch salt seed VRF
            let top_epoch = get_top_epoch().unwrap();
            if top_epoch.committees[0].get_round_leader().unwrap_or_default() == config().chain_key || !top_epoch.committees[0].members.contains(&config().chain_key) {
                error!("Asked to create epoch salt by {} but not in valid position", stream.peer_addr()
                .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)));
                let _ = send(
                    "ivp".to_string(),
                    stream,
                    0x07,
                    true,
                    None,
                );
            } else {
                debug!("Creating epoch salt seed VRF");
                // call the callback for creating epoch salt seed VRF
                if let Some(callback) = &*crate::core::FORM_SALT_SEED.lock().unwrap() {
                    let res = (callback)();
                    match res {
                        Ok(salt_seed) => {
                            let _ = send(
                                salt_seed,
                                stream,
                                0x07,
                                true,
                                None,
                            );
                        }
                        Err(e) => {
                            error!("Failed to create epoch salt seed VRF, error={}", e);
                            let _ = send(
                                "ftg".to_string(),
                                stream,
                                0x07,
                                true,
                                None,
                            );
                        }
                    }
                }
            }
        }
        // Get block chunk 
        0x49 => {
            // params: commitee, epoch, start_round, end_round (checksum = sum(params))
            let (committee, epoch, start, end, checksum): (u64, u64, u64, u64, u64) = serde_json::from_str(&read_msg.message).unwrap_or_default();
            if committee + epoch + start + end != checksum {
                error!("Failed to parse get block chunks params");
            } else {
                let mut chunks: Vec<String> = vec![];
                for round in start..=end {
                    trace!("Getting chunk for round {}", round);
                    if let Ok(chunk) = BlockChunk::get_by_round(round, epoch, committee) {
                        chunks.push((*chunk).encode().unwrap_or_default());
                    }
                }
                trace!("Found {} chunks from {} to {} (epoch={}, committee={})", chunks.len(), start, end, epoch, committee);
                if let Ok(encoded_payload) = serde_json::to_string(&chunks) {
                    trace!("Encoded block chunks payload: {}", encoded_payload);             
                    if let Err(send_error) = send(encoded_payload, stream, 0x50, true, None) {
                        error!("Failed to respond to get block chunks (range) request, got error={} while sending response", send_error);
                    } else {
                        debug!("Responded to peer={:?}'s get block chunks request", stream.peer_addr()
                        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)));
                    }
                } else {
                    error!("Failed to encode block chunks vector");
                }
            }
        }
        0x64 => {
            // this is a chunk proposal
            // TODO: Include search in the chunk signatures cache
            /*if let Ok(committee_index_lock) = core::COMMITTEE_INDEX.lock() {
                if *committee_index_lock == 0 {
                    // either unset or we are part of the consensus commitee, eitherway we do not need to handle this message
                    log::warn!("Asked to vote on chunk, but not in valid position");
                } else {
                    // decode the chunk
                    let chunk_decode = BlockChunk::decode(read_msg.message.to_owned());
                    if let Ok(chunk) = chunk_decode {
                        // check if we are not round leader
                        let top_epoch = get_top_epoch().unwrap();
                        if top_epoch.committees[*committee_index_lock as usize].get_round_leader().unwrap_or_default() == config().chain_key {
                            error!("Asked to vote on chunk by {} but not in valid position (is round leader)", stream.peer_addr()
                            .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)));
                        } else {
                                // check if we are in the same committee as the chunk
                                if chunk.committee != *committee_index_lock {
                                    error!("Asked to vote on chunk by {} but not in the same committee as the chunk (chunk commitee: {}, our commitee: {})", stream.peer_addr()
                                    .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)), chunk.committee, *committee_index_lock);
                                } else {
                                    // we are in a valid position, proceed
                                    // TODO: validate chunk
                                    let chunk_validation_res = chunk.valid();
                                    if let Err(chunk_validation_error) = chunk_validation_res {
                                        error!("Chunk {} invalid, got error={} while validating", chunk.hash, chunk_validation_error);
                                        // send a chunk invaid message
                                        if let Err(send_error) = send(chunk.hash, stream, 0x55, true, None) {
                                            error!("Failed to respond to invalid chunk proposal request, got error={} while sending response", send_error);
                                        }
                                    } else {

                                        let mut signatures: Vec<(String, String)> = vec![];
                                        let mut already_processed = false;
                                        // check if we have already processed this chunk, by checking in the chunk signatures cache stack
                                        if let Ok(cache_lock) = core::CACHED_BLOCKCHUNK_SIGNATURES.lock() {
                                            let mut found_index= 6; // there is at most 5 signatures in the cache, so 6 would never be a valid index
                                            for (index, item) in cache_lock.iter().enumerate() {
                                                if item.0 == chunk.hash {
                                                    found_index = index;
                                                }
                                            }
                                            if found_index != 6 { // see above comment as to why we are using 6
                                                // already signed this, get the other signatures we have
                                                signatures.push((cache_lock[found_index].0.to_owned(), cache_lock[found_index].1.to_owned())); // push a tuple (signature, public key) to our local signature list for this chunk
                                                if let Ok(peer_signatures_cache) = core::TOP_CHUNK_SIGNATURES_CACHE.lock() {
                                                    for signature in peer_signatures_cache.iter() {
                                                        if signature.0 == &chunk.hash {
                                                            signatures.push((signature.0.to_owned(), signature.1.to_owned()));
                                                        }
                                                    }
                                                }
                                                already_processed = true;
                                            }
                                        }
                                        if !already_processed {
                                            // we have not yet processed this chunk, so we need to sign it
                                            if let Some(callback) = &*core::HANDLE_CHUNK_CALLBACK.lock().unwrap() {
                                                if let Ok((pk, signature)) = (callback)(chunk.clone()) {
                                                    debug!("Processed block chunk {} from peer {:?}, created signature {}", chunk.hash, stream.peer_addr(), signature);
                                                    signatures.push((pk, signature)); // put our newly created signature to the local signature list for this chunk
                                                    // TODO: ask our LOWER GUID peers to sign this chunk as well (V2 goal)
                                                }
                                            }
                                            // only run if this is a debug build, this is a slow O(n^2) operation
                                            if cfg!(debug_assertions) {
                                                debug!("Detected debug build, running test");
                                                // test if there are any duplicate pubkeys in the signatures list
                                                for (public_key, signature) in signatures.iter() {
                                                    for (public_key2, signature2) in signatures.iter() {
                                                        if public_key == public_key2 {
                                                            error!("Detected duplicate public key in signatures list, sig1={}, sig2={}", signature, signature2);
                                                        }
                                                    }

                                                }
                                            }
                                            if signatures.len() != 0 {
                                                // send our vector of signatures to the peer
                                                let _ = send(match serde_json::to_string(&signatures) {
                                                    Ok(it) => it,
                                                    _ => unreachable!(),
                                                }, stream, 0x53, true, None);
                                                return None;
                                            } else {
                                                let _ = send(String::from("us"), stream, 0x54, true, None);
                                                return None;
                                            }
                                        }
                                    }
                                }
                        }
                    } else {
                        error!("Failed to decode chunk from peer, error: {}", chunk_decode.unwrap_err());
                    }
                }
            }*/
            if let Ok(callback_lock) = core::HANDLE_CHUNK_CALLBACK.lock() {
                let callback_option = &*callback_lock;
                if let Some(callback) = callback_option {
                    // decode the chunk 
                    let chunk_decode = BlockChunk::decode(read_msg.message.to_owned());
                    if let Err(chunk_decode_error) = chunk_decode {
                        error!("Failed to decode chunk from peer, error: {}", chunk_decode_error);
                    } else {
                        let chunk = chunk_decode.unwrap();
                        let callback_res = (callback)(chunk.clone());
                        if let Err(error) = callback_res {
                            error!("Failed to process chunk from peer, error: {}", error);
                            // send a chunk invalid message
                            if let Err(send_error) = send(chunk.hash.to_string(), stream, 0x55, true, None) {
                                error!("Failed to respond to invalid chunk proposal request, got error={} while sending response", send_error);
                            } else {
                                debug!("Responded to invalid chunk proposal request {}", chunk.hash);
                            }
                        } else {
                            debug!("Processed proposed block chunk {} from peer {:?} (fullnode identitiy: {})", chunk.hash, stream.peer_addr(), chunk.proposer().unwrap_or_default());
                            let signature  = vec![callback_res.unwrap()]; // (publickey, signature)
                            // send the signature to the peer
                            if let Err(send_error) = send(match serde_json::to_string(&signature) {
                                Ok(it) => it,
                                _ => unreachable!(),
                            }, stream, 0x53, true, None) {
                                error!("Failed to respond to chunk proposal request, got error={} while sending signature vector: {:?}", send_error, signature);
                            } else {
                                debug!("Responded to chunk proposal request {} with signature vector: {:?}", chunk.hash, signature);
                            }
                        }
                    }
                }
            } else {
                error!("Failed to get lock on HANDLE CHUNK CALLBACK mutex");
            }
        }
        0xa4 => {
            debug!("Peer asked for our prechunk block list");
            let mut list = get_data("sync".to_owned(), "prechunk-blocks");
            if list == "-1" {
                list = String::from("[]");
            }
            let _ = send(list, stream, 0xa5, true, None);
        }
        0xa5 => {
            error!("P2p handler loop recieved a prechunk block list, this probably means a function has leaked its lock. Please contact the avrio developers if you encounter futher issues");
        }
        0x50 => {
            // we just got a block chunk, validate it and ask for any blocks we dont have yet
            // If the chunk is valid & has enough signatures enact it and all included blocks
            // Otherwise place in the mempool chunk overflow untill it is valid or expires
            let block_chunk_decode = BlockChunk::decode(read_msg.message.clone());
            if let Ok(chunk) = block_chunk_decode {
                trace!("Decoded block chunk {} from peer", chunk.hash);
                // TODO: Just validate the signature and delta list of the chunk (minimal validation)
                if let Err(block_chunk_error) = chunk.valid() {
                    debug!("Recieved block chunk {}, invalid. reason={}", chunk.hash, block_chunk_error)
                } else {
                    debug!("Recieved block chunk {}, valid", chunk.hash);
                    // check we have all blocks
                    let mut to_get: Vec<&String> = vec![];
                    let mut got_blocks: Vec<Block> = vec![];

                    for block_hash in &chunk.blocks {
                        trace!("Checking if we have {} in mempool", block_hash);
                        let mempool_block = get_block_mempool(block_hash);
                        if mempool_block.is_err() {
                            trace!("{} not found in mempool, getting", block_hash);
                            to_get.push(block_hash);
                        } else  {
                            trace!("{} found in mempool", block_hash);
                        }
                    }
                    debug!("Have to get {} blocks for chunk {}", to_get.len(), chunk.hash);
                    // get the blocks we dont have yet
                    for block_hash in &to_get {
                        // ask peer
                        if let Err(e) = send(block_hash.to_string(), stream, 0x05, true, None) {
                            error!("Failed to send block request for block {} to peer {:?}, error: {}", block_hash, stream.peer_addr(), e);
                            continue;
                        } else {
                            debug!("Sent block request for block {} to peer {:?}", block_hash, stream.peer_addr());
                        }
                        let block_get = read(stream, Some(10000), None);
                        if let Ok(block) = block_get {
                            let blk = Block::from_compressed(block.message.to_owned());
                            if let Err(e) = blk {
                                error!("Failed to decode block from peer {:?}, error: {}", stream.peer_addr(), e);
                                continue;
                            } else {
                                let blk = blk.unwrap();
                                debug!("Got block {} from peer {:?}", blk.hash, stream.peer_addr());
                                got_blocks.push( blk);
                            }
                        }
                    }
                    debug!("Got {} blocks (expected={}) for chunk {}", got_blocks.len(), to_get.len(), chunk.hash);
                    // now add all the blocks we had to get to the mempool#
                    for block in &got_blocks {
                        
                            debug!("Adding block {} to mempool", block.hash);
                            add_block(block, Caller::blank());
                    
                    }
                    // now we enact the chunk
                    if let Err(chunk_enacting_error) = chunk.enact() {
                        error!("Failed to enact valid block chunk {} (recieved over p2p), error={}", chunk.hash, chunk_enacting_error);
                        error!("Chunk: {:?}", chunk);
                    } else {
                        debug!("Enacted chunk {}", chunk.hash);                        
                        let _ = send(String::from("ns"), stream, 0x54, true, None);
                        return None;
                    }
                }
            } else {
                error!("Failed to decode block chunk from peer, error: {}", block_chunk_decode.unwrap_err());
            }
        }
        0x91 => {
            debug!("Got ping message from peer");
            *last_ping_time = SystemTime::now();
            if let Err(e) =  send(read_msg.message, stream, 0x92, true, None) {
                error!("Failed to respond to ping, error={}", e);
            }
        }
        0xff => {
            // shutdown
            info!("Disconnected to peer {}, connection closed by peer", stream.peer_addr()
                .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0))
            );
            let _ = remove_peer(stream.peer_addr().unwrap(), true);
            let _ = remove_peer(stream.peer_addr().unwrap(), false);
            thread::sleep(Duration::from_micros(1000));
            let _ = stream.shutdown(Shutdown::Both);
            return Some("closed by peer".into());
        }
        // sync req message
        0x22 => {
            let used_slots =
                get_syncing_peers_count().unwrap_or(config().max_syncing_peers);
            let slots_left = config().max_syncing_peers - used_slots;
            log::trace!("Recieved sync request from peer, current syncing peers: {}, slots left: {}", used_slots, slots_left);
            if slots_left > 0 {
                if add_peer_to_sync_list(
                    &stream.peer_addr().unwrap_or_else(|_| SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                        0,
                    )),
                ).is_ok() {
                    let _ =
                        send("syncack".into(), stream, 0x01, true, None);
                } else {
                    let _ =
                        send("syncdec".into(), stream, 0x01, true, None);
                }
            } else {
                let _ = send("syncdec".into(), stream, 0x01, true, None);
            }
        }
        0x23 => {
            // end syncing
            debug!("Peer no longer syncing");
            let _ = remove_peer_from_sync_list(&stream.peer_addr().unwrap_or_else(|_|
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            ));
        }
        0x1b | 0x1c => {
            // send the peer our chain digest
            log::trace!("Sending chain digest to peer");
            let chain_digest = avrio_database::get_data(
                "chaindigest".to_owned(),
                "master",
            );
            let _ = send(chain_digest, stream, 0xcd, true, None);
        }
        0x05 => {
            // check if the peer has set the spiral tag (if we ask peers in our GUID table for the block as well)
            let split_message = read_msg.message.split('.').collect::<Vec<&str>>();
            if split_message.len() == 2 {
                trace!("Peer has asked for block with spiral, hash={}", split_message[0]);
                // first see if we have the block ourselves
                let block = get_block_from_raw(split_message[0].to_string());
                if block.is_default() {
                    trace!("Cannot find {} on disk, trying mempool", split_message[0]);
                    let block_mempool = avrio_core::mempool::get_block(split_message[0]);
                    if block_mempool.is_err() {
                        trace!("Cannot find {} on disk or in mempool, asking GUID peers", split_message[0]);
                        // ask all peers in our GUID table for this block (with the same spiral tag)
                        if let Ok(responses) = crate::guid::send_to_all(read_msg.message, read_msg.message_type, true, false) {
                            let mut blocks: Vec<Block> = vec![];
                            for block_encoded in responses {
                                let mut block = Block::default();
                                if let Ok(_) = block.decode_compressed(block_encoded.message) {
                                    blocks.push(block);
                                }
                            }
                            let mut hashes: Vec<String> = vec![];
                            for (index, block) in blocks.clone().into_iter().enumerate() {
                                // check the hash is valid
                                if block.hash_return() != block.hash{
                                    // remove this block, its hash is not correct
                                    blocks.remove(index);
                                } else {
                                    hashes.push(block.hash);
                                }
                            }
                            // find the most common hash
                            let mode_hash = crate::utils::get_mode(hashes);
                            for block in &blocks {
                                if block.hash == mode_hash {
                                    // send this block
                                    let _ = crate::helper::send_block_struct(block, stream);
                                    break;
                                }
                            }
                        }
                    }
                }
            } else {
            // send the peer the block with the hash they specifyed in the message field
            let _ = crate::helper::send_block_with_hash(
                read_msg.message,
                stream,
            );
        }
        }
        0x0b => { // peer accepted our block
            if let Ok(addr) =  stream.peer_addr() {
                info!("Peer={} accepted our block={}", addr, read_msg.message);
            } else {
                info!("Peer (failed to get addr) accepted our block {}", read_msg.message);
            }
        }
        0x0c => { // peer rejected our block
            if let Ok(addr) =  stream.peer_addr() {
                debug!("Peer={} rejected our block, reason={}", addr, read_msg.message);
            } else if read_msg.message != "ahb" {
                debug!("Peer (failed to get addr) rejeted our reason={}", read_msg.message);
            }
        }
        0x04 => {
            // the peer just sent us a block,
            // add it to the mempool
            log::trace!("Got block from peer");
            let block: Block = from_compact(read_msg.message).unwrap_or_default();
            if block.is_default() {
                log::trace!("Could not decode block");
                let _ = send("dsf".to_owned(), stream, 0x0c, true, None);
            } else if !get_block_from_raw(block.hash.clone()).is_default() {
                debug!("Already have block {}, ignoring", block.hash);
                let _ = send(
                    "ahb".to_owned(),
                    stream,
                    0x0c,
                    true,
                    None,
                );
            } else {
                let callback_struct = Caller {
                    callback: Box::new(block_enacted_callback),
                    rec_from: stream.peer_addr().unwrap()
                };
                let _ = add_block(&block, callback_struct);
            }
        }
        0x60 => {
            log::trace!(
                "Peer: {} has requested our chains list",
                stream.peer_addr().expect("Could not get addr for peer")
            );

            if let Ok(db) = iter_database("chainlist".to_owned()) {
                let mut chains: Vec<String> = vec![];

                for (key, _) in db.iter() {
                    chains.push(key.to_owned());
                }

                log::trace!("Our chain list: {:#?}", chains);
                let s = serde_json::to_string(&chains).unwrap_or_default();

                if s == String::default() {
                    log::trace!("Failed to ser list");
                } else if let Err(e) = send(s, stream, 0x61, true, None) {
                    log::debug!("Failed to send chain list to peer, gave error: {}", e);
                }
            }
        }
        0x62 => {
            log::trace!(
                "Peer: {} has requested our epoch salt",
                stream.peer_addr().expect("(Could not get addr for peer)") 
            );
            // TODO: call the registered callback, producing a vrf proof
            let salt: Result<String, Box<dyn std::error::Error>>  = Ok(String::default());
            if let Ok(salt_proof) = salt {
                let _ = send(salt_proof, stream, 0x62, true, None);
            } else {
                let salt_err = salt.unwrap_err();
                error!("Failed to produce salt seed for peer, callback returned error: {}", salt_err);
                let _ = send(format!("{}", salt_err), stream, 0x62, true, None);
            }
        }
        0x45 => {
            // send block count
            let bc = get_data(
                "chains/".to_owned()
                    + &read_msg.message
                    + &"-chainindex".to_owned(),
                &"blockcount".to_owned(),
            );
            log::trace!("Blockcount={} for chain={}", bc, read_msg.message);

            if bc == *"-1" {
                let _ = send("0".into(), stream, 0x46, true, None);
            } else {
                let _ = send(bc, stream, 0x46, true, None);
            }

        }
        0x47 => {
            // send global block count
            let gbc = get_data(
                "globalindex".to_owned(),
                "globalblockcount",
            );
            log::trace!("Global blockcount={}", gbc);

            if gbc == *"-1" {
                let _ = send("0".into(), stream, 0x48, true, None);
            } else {
                let _ = send(gbc, stream, 0x48, true, None);
            }

        }
        0x6f => {
            let (hash, chain): (String, String) =
                serde_json::from_str(&read_msg.message).unwrap_or_default();

            if chain == String::default() || hash == String::default() {
                log::debug!(
                    "Got malformed getblocksabovehash hash request (invalid body: {})",
                    read_msg.message
                );
            } else {
                let block_from: Block;

                if hash == "0" {
                    log::trace!("Getting genesis block for chain: {}", chain);
                    block_from = get_block(&chain, 0);
                    log::trace!("Block from: {:#?}", block_from);
                } else {
                    block_from = get_block_from_raw(hash.clone());
                }

                if block_from == Default::default() {
                    log::debug!("Cant find block (context getblocksabovehash)");
                } else {
                    let mut got: u64 = block_from.header.height;
                    let mut prev: Block = block_from.clone();
                    let mut blks: Vec<String> = vec![];

                    while prev != Default::default() {
                        if (prev == block_from && hash == "0") || prev != block_from {
                            blks.push(prev.encode_compressed());
                        }

                        got += 1;
                        log::trace!("Sent block at height: {}", got);
                        prev = get_block(&chain, got);
                    }

                    if send(
                        serde_json::to_string(&blks).unwrap_or_default(),
                        stream,
                        0x04,
                        true,
                        None
                    ).is_ok() {
                        log::trace!(
                            "Sent all blocks (amount: {}) for chain: {} to peer",
                            got,
                            chain
                        );
                    }
                }
            }

        }
        0x7f => {
            let hash: String = read_msg.message.clone();

            if hash == String::default() {
                log::debug!(
                    "Got malformed globalgetblocksabovehash hash request (invalid body: {})",
                    read_msg.message
                );
            } else {
                let block_from: Block;

                if hash == "0" || hash == "-1"  {
                    log::trace!("Getting blocks above network genesis (globally) ");
                    let got_index = get_data(
                        "globalindex".to_owned(),"1");
                    if got_index != "-1"
                    {
                    block_from = get_block_from_raw(got_index);
                    log::trace!("Block from: {:#?}", block_from);
                    } else {
                        block_from = Block::default();
                    }
                } else {
                    block_from = get_block_from_raw(hash.clone());
                }

                if block_from == Default::default() {
                    log::debug!("Cant find block (context globalgetblocksabovehash)");
                } else {
                    let mut got: u64 = block_from.header.height + 1;
                    let mut prev: Block = block_from.clone();
                    let mut blks: Vec<String> = vec![];

                    loop {
                        if (prev == block_from && hash == "0") || prev != block_from {
                            blks.push(prev.encode_compressed());
                        }

                        got += 1;
                        log::trace!("Sent block at height: {}", got);
                        let got_index = get_data(
                            "globalindex".to_owned(),&got.to_string());
                        if got_index != "-1" {
                            prev = get_block_from_raw(got_index);
                        } else {
                            break;
                        }
                    }

                    if send(
                        serde_json::to_string(&blks).unwrap_or_default(),
                        stream,
                        0x04,
                        true,
                        None
                    ).is_ok() {
                        log::trace!(
                            "Sent all blocks (amount: {}) (global) to peer",
                            got
                        );
                    }
                }
            }

        }
        0x1a => {
            log::debug!("Got handshake from handshook peer, rehandshaking");
            let _ = send("".to_string(), stream, 0x03, true, None);
            return Some("return".to_owned());
        }
        0x8f => {
            log::debug!("Peer=asked for peer list");
            let peerlist_get = avrio_database::get_peerlist();
            if let Ok(peers) = peerlist_get {
                log::trace!("Got peerlist from DB");
                if send(
                    serde_json::to_string(&peers).unwrap_or_default(),
                    stream,
                    0x9f,
                    true,
                    None
                ).is_ok() {
                    log::trace!(
                        "Sent all peers (amount: {})d to peer",
                        peers.len()
                    );
                }
            } else {
                log::warn!("Failed to get peerlist (context=p2p_get_peerlist_msg), error={}; sending blank", peerlist_get.unwrap_err());
                let blank_vec: Vec<String> = vec![];
                if send(
                    serde_json::to_string(&blank_vec).unwrap_or_default(),
                    stream,
                    0x9f,
                    true,
                    None
                ).is_ok() {
                    log::trace!(
                        "Sent blank vec as peerlist to peer"
                    );
                }
            }
        },
        0x9a => {
            log::debug!("Recieved announce peer message, addr={}", read_msg.message);
            let parsed: Result<SocketAddr, _> = read_msg.message.parse();
            if let Ok(socket) = parsed {
                let _ = avrio_database::add_peer(socket);
                // TODO: Check if peer was in peer list and if we are over 25 peer connections, if not then connect to this new peer. Also relay this message to all connected peers
            }
        },
        0xcd => log::error!("Read chain digest response. This means something has not locked properly. Will likley cause failed sync"),
        _ => {
            log::debug!("Got unsupported message type: \"0x{:x}\", please check for updates", read_msg.message_type);
        }

    }
    None
}
