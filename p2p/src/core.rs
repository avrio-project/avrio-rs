use crate::{
    io::{read, send},
    peer::{add_peer, get_peers_addr, lock, remove_peer},
};
extern crate rand;
extern crate x25519_dalek;
use crate::peer::in_peers;
use avrio_config::config;
use avrio_core::chunk::BlockChunk;
use std::{collections::HashMap, sync::Mutex, time::Duration};
use std::{
    convert::TryInto,
    net::{Shutdown, SocketAddr},
};
use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;
fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}
use log::trace;
const CACHED_BLOCKCHUNK_SIGNATURES_SIZE: u64 = 5;
lazy_static! {
pub static ref COMMITTEE_INDEX: Mutex<u64> = Mutex::new(0);
pub static ref HANDLE_CHUNK_CALLBACK: Mutex<Option<Box<dyn Fn(BlockChunk) -> Result<(String, String), Box<dyn std::error::Error>> + Send>>> =
    Mutex::new(None);
pub static ref CACHED_BLOCKCHUNK_SIGNATURES: Mutex<Vec<(String, String)>> =
    Mutex::new(vec![]); // A cache of our signatures, uses LIFO structure
pub static ref TOP_CHUNK_SIGNATURES_CACHE: Mutex<HashMap<String, String>> =
    Mutex::new(HashMap::new()); // a cache of all signatures we have seen on our commites top chunk (indexed by the nodes ecdsa key)
pub static ref TOP_CHUNK_HASH: Mutex<String> = Mutex::new(String::default());
pub static ref FORM_SALT_SEED: Option<Box<dyn Fn() -> Result<String, Box<dyn std::error::Error>> + Sync>> = None;
}

pub fn push_to_signature_stack(
    hash: Option<String>,
    node: Option<String>,
    signature: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(node_sig) = signature {
        if let Some(chunk_hash) = hash {
            if let Some(node_publickey) = node {
                if *TOP_CHUNK_HASH.lock()? != chunk_hash {
                    return Err("Hash != top hash".into());
                }
                TOP_CHUNK_SIGNATURES_CACHE
                    .lock()?
                    .insert(node_publickey, node_sig);
                return Ok(());
            } else {
                // this must be our sig, add to the signature stack

                let lock = &mut *CACHED_BLOCKCHUNK_SIGNATURES.lock()?;
                if lock.len() == 5 {
                    lock.remove(0);
                }
                lock.push((chunk_hash, node_sig));
                return Ok(());
            }
        } else {
            return Err("Chunk hash not set".into());
        }
    } else {
        return Err("Signature not set".into());
    }
}
pub fn new_connection(addr: &str) -> Result<std::net::TcpStream, Box<dyn std::error::Error>> {
    if in_peers(&addr.parse::<SocketAddr>()?)? {
        return Err("Already connected".into());
    }
    log::info!("Connecting to {}", addr);
    let mut a = std::net::TcpStream::connect_timeout(&(addr.parse()?), Duration::new(5, 0))?;
    let mut local_cspring = rand::rngs::OsRng;
    let local_sec = EphemeralSecret::new(&mut local_cspring);
    let local_pub = PublicKey::from(&local_sec);
    let handshake = form_handshake(local_pub.as_bytes());
    trace!("Formed handshake, {}", handshake);
    let _ = crate::io::send(
        handshake.clone(),
        &mut a,
        0xa,
        true,
        Some(
            "hand_keyhand_keyhand_keyhand_key"
                .as_bytes()
                .try_into()
                .unwrap(),
        ),
    )?;
    let mut d = crate::io::read(
        &mut a,
        Some(10000),
        Some("hand_keyhand_keyhand_keyhand_key".as_bytes()),
    )?;
    if d.message == "cancel" {
        return Err("canceled by peer".into());
    }
    if d.message_type == 0x03 {
        // we are reconnecting to the peer, but they have not droped our socket yet. Resend everything
        log::info!("Reconnecting to {}", addr);
        drop(a);
        a = std::net::TcpStream::connect(addr)?;
        let _ = crate::io::send(
            handshake,
            &mut a,
            0xa,
            true,
            Some(
                "hand_keyhand_keyhand_keyhand_key"
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            ),
        )?;
        d = crate::io::read(
            &mut a,
            Some(2000),
            Some("hand_keyhand_keyhand_keyhand_key".as_bytes()),
        )?;
        if d.message == "cancel" {
            return Err("canceled by peer".into());
        }
    }
    if d.message_type != 0x1a {
        return Err("wrong first response type".into());
    }
    let d_split = d.message.split('*').collect::<Vec<&str>>();
    if d_split.len() != 5 {
        trace!("d_split: {}, expected 4", d_split.len());
        Err("wrong return len: ".into())
    } else if hex::encode(config().network_id) != d_split[0] {
        Err("wrong network id".into())
    } else if d_split[1] == config().identitiy {
        return Err("tried to connect to peer with the same identity (self)".into());
    } else {
        let addr_s = addr.to_string();
        let ip_s = addr_s.split(':').collect::<Vec<&str>>()[0];
        let addr_s = format!("{}:{}", ip_s, d_split[3]);
        let _ = avrio_database::add_peer(addr_s.parse()?)?;
        let key = local_sec.diffie_hellman(&PublicKey::from(from_slice(&hex::decode(d_split[4])?)));
        let ss = key.as_bytes();
        trace!("KEY={}, LEN={}", hex::encode(ss), ss.len());
        send("".into(), &mut a, 0xa2, true, Some(ss))?;
        let p2_read = read(
            &mut a,
            Some(2000),
            Some("hand_keyhand_keyhand_keyhand_key".as_bytes()),
        );
        if let Ok(data) = p2_read {
            if data.message_type != 0xa3 {
                return Err(format!(
                    "got wrong message type {} from peer, expecting 0xa3",
                    data.message_type
                )
                .into());
            } else if data.message != "ack" {
                Err("peer did not understand our message; key derivation failed".into())
            } else {
                log::info!("Handshook with peer. Adding to peer list and launching handler stream");
                let (tx, rx) = std::sync::mpsc::channel::<String>();
                if let Err(e) = add_peer(a.try_clone()?, true, hex::encode(&ss), &tx) {
                    log::error!(
                        "Failed to handshake with peer, adding peer to peerlist gave error: {}",
                        e
                    );
                    return Err("failed to add peer to peer list".into());
                } else if let Err(e) = crate::handle::launch_handle_client(rx, &mut a, true) {
                    log::error!("Failed to launch peer handler stream, gave error: {}", e);
                }
                Ok(a)
            }
        } else {
            log::error!(
                "Failed to handshake with peer, reading inbound message no 2 gave error: {}",
                p2_read.unwrap_err()
            );
            Err("reading inbound message no 2 gave error".into())
        }
    }
}

pub fn form_handshake(l_pub: &[u8; 32]) -> String {
    return format!(
        "{}*{}*{}*{}*{}",
        hex::encode(config().network_id),
        &config().identitiy,
        &config().node_type,
        &config().p2p_port,
        hex::encode(l_pub)
    );
}

pub fn rec_server(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut p2p_server = crate::server::P2pServer::default();
    p2p_server.set_bind_addr(&address.parse()?)?;
    p2p_server.launch()
}

pub fn close_all() -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Closing all tcp streams");
    for addr in &get_peers_addr()? {
        let _ = close(addr)?;
    }
    Ok(())
}

pub fn close(peer: &std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(mut stream) = lock(peer, 10000) {
        log::info!("Disconnected from peer {}", stream.peer_addr()?,);
        let _ = send("".to_string(), &mut stream, 0xff, true, None);
        std::thread::sleep(Duration::from_micros(1000));
        let _ = remove_peer(stream.peer_addr()?, true);
        let _ = remove_peer(stream.peer_addr()?, false);
        let _ = stream.shutdown(Shutdown::Both);
    }
    Ok(())
}
