use crate::{
    format::P2pData,
    io::{peek, read, send},
    peer::add_peer,
};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use lazy_static::lazy_static;
use std::net::TcpStream;
use std::sync::Mutex;
extern crate rand_os;
extern crate x25519_dalek;

use avrio_config::config;
use rand_os::OsRng;

use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

static MAX_SYNCING_PEERS: u64 = 8;

lazy_static! {
    static ref SYNCING_PEERS: Mutex<u64> = Mutex::new(0);
}

fn get_syncing_peers_count() -> Result<u64, Box<dyn std::error::Error>> {
    return Ok(*SYNCING_PEERS.lock()?);
}

fn set_syncing_peers_count(new: u64) -> Result<(), Box<dyn std::error::Error>> {
    *SYNCING_PEERS.lock()? = new;
    return Ok(());
}

fn increment_sync_count() -> Result<(), Box<dyn std::error::Error>> {
    let new = get_syncing_peers_count()? + 1;
    *SYNCING_PEERS.lock()? = new;
    return Ok(());
}

fn deincrement_sync_count() -> Result<(), Box<dyn std::error::Error>> {
    let mut new = {
        let spc = get_syncing_peers_count()?;
        if spc == 0 {
            0
        } else {
            spc - 1
        }
    };
    *SYNCING_PEERS.lock()? = new;
    return Ok(());
}

pub fn launch_handle_client(
    rx: std::sync::mpsc::Receiver<String>,
    stream: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = stream.try_clone()?;
    let _handler: std::thread::JoinHandle<Result<(), &'static str>> = std::thread::spawn(
        move || loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Ok(msg) = rx.try_recv() {
                if msg == "pause" {
                    loop {
                        if let Ok(msg) = rx.try_recv() {
                            if msg == "run" {
                                break;
                            }
                        }
                    }
                }
            }
            if let Ok(a) = peek(&mut stream) {
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
                                    let _ = send("syncack".into(), &mut stream, 0x01, true, None);
                                    let _ = deincrement_sync_count();
                                } else {
                                    let _ = send("syncdec".into(), &mut stream, 0x01, true, None);
                                }
                            }
                            0x1b | 0x1c => {
                                log::trace!("Sending chain digest to peer");
                                let chain_digest = avrio_database::getData(
                                    avrio_config::config().db_path + &"/chainsdigest",
                                    "master",
                                );
                                let _ = send(chain_digest, &mut stream, 0xcd, true, None);
                            }
                            0x05 => {
                                let _ = crate::helper::send_block_with_hash(
                                    read_msg.message,
                                    &mut stream,
                                );
                            }
                            0x0a => {
                                let block: avrio_blockchain::Block =
                                    serde_json::from_str(&read_msg.message).unwrap_or_default();
                                if block.is_default() {
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
                            0x1a => log::debug!("Got handshake from handshook peer, ignoring"),
                            _ => {
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

fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}
