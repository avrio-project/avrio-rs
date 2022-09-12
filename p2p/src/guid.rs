use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex},
};

use crate::{
    core::new_connection,
    format::P2pData,
    io::{read as read_from_peer, send},
    peer::{in_peers, lock, unlock_peer},
};
use avrio_crypto::raw_hash;
use lazy_static::lazy_static;
use log::*;
lazy_static! {
    static ref ROUTING_TABLE: Mutex<HashMap<u64, (String, SocketAddr)>> =
        Mutex::new(HashMap::new());
}
pub fn form_table(all_peers: Vec<(String, SocketAddr)>) -> Result<u64, Box<dyn std::error::Error>> {
    info!(
        "Forming routing table from {} peers, estimated connection count: {}",
        all_peers.len(),
        log_2(all_peers.len() as i32)
    );
    // A guid is formed by hashing the peers IP with their commitee ID and fullnode pubkey, this string is then translated to a value
    // You then take the GUID of each member of a commitee and put it in a vector, sorted from lowest GUID to highest
    // the position/index of peer within the vector (eg 0, 1, 2 ) is your intra-commitee GUID
    // TODO: Implement the GUID routing stuff; for now connect to each peer
    // TODO: Calc the GUID of each peer, as well as the GUIDs which should be in our tabel

    let mut routing_table_lock = ROUTING_TABLE.lock()?;
    for (id, addr) in guid_to_intra_committee_id(all_peers.clone()) {
        if !in_peers(&addr)? {
            debug!("Connecting to {}", all_peers[id as usize].0);
            match new_connection(&addr.to_string()) {
                Ok(stream) => {
                    debug!("Opened new connection to {}", stream.peer_addr()?);
                    routing_table_lock.insert(id, (all_peers[id as usize].0.clone(), addr));
                }
                Err(connection_error) => {
                    error!(
                        "Failed to open connection to {}, error={}",
                        all_peers[id as usize].0, connection_error
                    );
                }
            }
        }
    }
    Ok(routing_table_lock.len() as u64)
}

/// # Hash into u64
/// Turns a hash in string form into a u64 (using 8 wise bitshifts)
pub fn hash_to_u64(hash: String) -> u64 {
    let hash_bytes = hash.into_bytes();
    let mut hash_u64: u64 = 0;
    for i in 0..hash_bytes.len() {
        hash_u64 = (hash_u64 << 8) + (hash_bytes[i] as u64);
    }
    hash_u64
}

pub fn calculate_guid(public_key: &String, commitee_id: u64, ip_addr: SocketAddr) -> String {
    raw_hash(&format!(
        "{}{}{}",
        public_key,
        commitee_id.to_string(),
        ip_addr.to_string()
    ))
}

pub fn guid_to_intra_committee_id(all_peers: Vec<(String, SocketAddr)>) -> Vec<(u64, SocketAddr)> {
    let mut return_table = vec![];
    let mut iteration = 0;
    for peer in all_peers {
        return_table.push((iteration, peer.1));
        iteration += 1;
    }
    return_table
}

/// # Send to all
/// Sends a message to every peer in the GUID table
/// if 'read' is true then this function will also lock the peer and read for their response (returning in a ```Result<Vec<P2pMessage>>>```)
/// Otherwise any response will be handled by the handle thread
/// If error_on_fail_read is true then the function will return an error if a peer cannot be read from
pub fn send_to_all(
    message: String,
    message_type: u16,
    read: bool,
    error_on_fail_read: bool,
) -> Result<Vec<P2pData>, Box<dyn std::error::Error>> {
    let mut to_return: Vec<P2pData> = vec![];
    for (id, (guid, addr)) in &*(ROUTING_TABLE.lock()?) {
        debug!(
            "Sending message {} (type={}) to {} (id={})",
            message, message_type, guid, id
        );
        let mut stream = lock(&addr, 10000)?;
        send(message.clone(), &mut stream, message_type, true, None)?;
        if read {
            // read from the peer
            let read_data_res = read_from_peer(&mut stream, Some(10000), None);
            if let Ok(read_data) = read_data_res {
                to_return.push(read_data)
            } else if error_on_fail_read {
                return Err("Failed to read from peer".into());
            }
        }
        unlock_peer(stream)?;
    }
    Ok(to_return)
}

const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

fn log_2(x: i32) -> u32 {
    if x <= 0 {
        return 0;
    }
    num_bits::<i32>() as u32 - x.leading_zeros() - 1
}
