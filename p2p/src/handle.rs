use crate::{
    format::P2pData,
    io::{peek, read, send},
    peer::add_peer,
};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use lazy_static::lazy_static;
use std::net::TcpStream;
use std::sync::Mutex;
use avrio_database::{get_data, open_database};
use avrio_config::config;
extern crate rand_os;
extern crate x25519_dalek;

static MAX_SYNCING_PEERS: u64 = 8;

lazy_static! {
    static ref SYNCING_PEERS: Mutex<(u64, Vec<String>)> = Mutex::new((0, vec![]));
}

fn get_syncing_peers_count() -> Result<u64, Box<dyn std::error::Error>> {
    return Ok(SYNCING_PEERS.lock()?.0);
}

fn set_syncing_peers_count(new: u64) -> Result<(), Box<dyn std::error::Error>> {
    SYNCING_PEERS.lock()?.0 = new;
    return Ok(());
}

fn increment_sync_count() -> Result<(), Box<dyn std::error::Error>> {
    let new = get_syncing_peers_count()? + 1;
    SYNCING_PEERS.lock()?.0 = new;
    return Ok(());
}

fn add_peer_to_sync_list(peer: &SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let peer_no_port = crate::peer::strip_port(peer);
    if !SYNCING_PEERS.lock()?.1.iter().any(|i| i == &peer_no_port) {
        increment_sync_count()?;
        SYNCING_PEERS.lock()?.1.push(peer_no_port);
    } else {
        return Err("Peer already in syncing peers list".into());
    }
    return Ok(());
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
    return Ok(());
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
    return Ok(());
}

pub fn launch_handle_client(
    rx: std::sync::mpsc::Receiver<String>,
    stream: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = stream.try_clone()?;
    let _handler: std::thread::JoinHandle<Result<(), &'static str>> = std::thread::spawn(
        move || loop {
            if let Ok(msg) = rx.try_recv() {
                if msg == "pause" {
                    log::trace!("Pausing stream for peer");
                    loop {
                        if let Ok(msg) = rx.try_recv() {
                            if msg == "run" {
                                log::trace!("Resuming stream for peer");
                                break;
                            }
                        }
                    }
                }
            }
            if let Ok(a) = peek(&mut stream) {
                if let Ok(msg) = rx.try_recv() {
                    if msg == "pause" {
                        log::trace!("Pausing stream for peer");
                        loop {
                            if let Ok(msg) = rx.try_recv() {
                                if msg == "run" {
                                    log::trace!("Resuming stream for peer");
                                    break;
                                }
                            }
                        }
                    }
                }
                if a != 0 {
                    let read_data = read(&mut stream, Some(1000), None);
                    if let Ok(read_msg) = read_data {
                        read_msg.log();
                        match read_msg.message_type {
                            // zero type msg
                            0 => {
                                log::debug!(
                                    "Received a p2p message with type 0. Likeley corrupted"
                                );
                            }
                            // sync req message
                            0x22 => {
                                let used_slots =
                                    get_syncing_peers_count().unwrap_or(MAX_SYNCING_PEERS);
                                let slots_left = MAX_SYNCING_PEERS - used_slots;
                                log::trace!("Recieved sync request from peer, current syncing peers: {}, slots left: {}", used_slots, slots_left);
                                if slots_left > 0 {
                                    if let Ok(_) = add_peer_to_sync_list(
                                        &stream.peer_addr().unwrap_or(SocketAddr::new(
                                            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                            0,
                                        )),
                                    ) {
                                        let _ =
                                            send("syncack".into(), &mut stream, 0x01, true, None);
                                    } else {
                                        let _ =
                                            send("syncdec".into(), &mut stream, 0x01, true, None);
                                    }
                                } else {
                                    let _ = send("syncdec".into(), &mut stream, 0x01, true, None);
                                }
                            }
                            0x23 => {
                                // end syncing
                                let _ = remove_peer_from_sync_list(&stream.peer_addr().unwrap_or(
                                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
                                ));
                            }
                            0x1b | 0x1c => {
                                // send the peer our chain digest
                                log::trace!("Sending chain digest to peer");
                                let chain_digest = avrio_database::get_data(
                                    avrio_config::config().db_path + &"/chaindigest",
                                    "master",
                                );
                                let _ = send(chain_digest, &mut stream, 0xcd, true, None);
                            }
                            0x05 => {
                                // send the peer the block with the hash they specifyed in the message field
                                let _ = crate::helper::send_block_with_hash(
                                    read_msg.message,
                                    &mut stream,
                                );
                            }
                            0x0a => {
                                // the peer just sent us a block,
                                // validate it, save it an enact it
                                log::trace!("Got block from peer");
                                let block: avrio_blockchain::Block =
                                    serde_json::from_str(&read_msg.message).unwrap_or_default();
                                if block.is_default() {
                                    log::trace!("Could not decode block");
                                    let _ = send("dsf".to_owned(), &mut stream, 0x0c, true, None);
                                } else {
                                    if let Err(e) = avrio_blockchain::check_block(block.clone()) {
                                        let curr_invalid_block_count =
                                            crate::peer::get_invalid_block_count(
                                                &stream.peer_addr().unwrap_or(SocketAddr::new(
                                                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                                    0,
                                                )),
                                            )
                                            .unwrap_or_default();
                                        let _ = crate::peer::set_invalid_block_count(
                                            &stream.peer_addr().unwrap_or(SocketAddr::new(
                                                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                                0,
                                            )),
                                            curr_invalid_block_count + 1,
                                        );
                                        log::debug!("Got invalid block from peer. New invalid block count: {}. Invalid because: {:?}", curr_invalid_block_count +1, e);
                                    } else {
                                        if let Err(e) = avrio_blockchain::saveBlock(block.clone()) {
                                            log::debug!("Saving block gave error: {}", e);
                                            let _ = send(
                                                "sbf".to_owned(),
                                                &mut stream,
                                                0x0c,
                                                true,
                                                None,
                                            );
                                        } else {
                                            if let Err(e) =
                                                avrio_blockchain::enact_block(block.clone())
                                            {
                                                log::error!("Enacting block gave error: {}", e);
                                                log::warn!("This could cause undefined behavour. Please consider restarting with --re-enact-from {}", block.header.prev_hash);
                                                log::error!("Please subbmit the following bug report to the developers:");
                                                println!("------ Error Report Begin -----");
                                                println!(
                                                    "Failed to enact block {} due to error: {}",
                                                    block.hash, e
                                                );
                                                println!("Block dump: {:#?}", block);
                                                println!("------ Error Report End -----");
                                                let _ = send(
                                                    "ebf".to_owned(),
                                                    &mut stream,
                                                    0x0c,
                                                    true,
                                                    None,
                                                );
                                                log::error!("");
                                            } else {
                                                log::debug!("Recieved and processed block from peer, sending block ack");
                                                let _ = send(
                                                    "".to_owned(),
                                                    &mut stream,
                                                    0x0b,
                                                    true,
                                                    None,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            0x60 => {
                                log::trace!(
                                    "Peer: {} has requested our chains list",
                                    stream.peer_addr().expect("Could not get addr for peer")
                                );
                    
                                if let Ok(db) = open_database(config().db_path + &"/chainlist".to_owned()) {
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
                    
                                    log::trace!("Our chain list: {:#?}", chains);
                                    let s = serde_json::to_string(&chains).unwrap_or_default();
                    
                                    if s == String::default() {
                                        log::trace!("Failed to ser list");
                                    } else if let Err(e) = send(s, &mut stream, 0x61, true, None) {
                                        log::debug!("Failed to send chain list to peer, gave error: {}", e);

                                    }
                                }
                            }
                            0x45 => {
                                // send block count
                                let bc = get_data(
                                    config().db_path
                                        + &"/chains/".to_owned()
                                        + &read_msg.message
                                        + &"-chainindex".to_owned(),
                                    &"blockcount".to_owned(),
                                );
                                log::trace!("Blockcount={} for chain={}", bc, read_msg.message);

                                if bc == "-1".to_owned() {
                                    let _ = send("0".into(), &mut stream, 0x46, true, None);
                                } else {
                                    let _ = send(bc, &mut stream, 0x46, true, None);
                                }
                    
                            }
                            0x1a => log::debug!("Got handshake from handshook peer, ignoring"),
                            0xcd => log::error!("Read chain digest response. This means something has not locked properly. Will likley cause failed sync"),
                            _ => {
                                log::debug!("Got unsupported message type: \"0x{:x}\", please check for updates", read_msg.message_type);
                                ();
                            }
                        }
                    }
                }
            } else {
                return Err("failed to peek peer");
            }
        },
    );
    return Ok(());
}
