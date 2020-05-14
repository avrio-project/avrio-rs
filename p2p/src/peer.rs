use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

use std::collections::HashMap;
use std::sync::Mutex;

const MAX_INVALID_BLOCKS: u64 = 15;

lazy_static! {
    pub static ref INCOMING: Mutex<Vec<TcpStream>> = Mutex::new(vec![]);
    pub static ref OUTGOING: Mutex<Vec<TcpStream>> = Mutex::new(vec![]);
    pub static ref PEERS: Mutex<HashMap<String, (String, bool, Option<std::sync::mpsc::Sender<String>>, u64)>> =
        Mutex::new(HashMap::new());
}

/// # get_peers
/// Returns a Result enum conating a vector of every connections tcp stream (inbound and outbound)
pub fn get_peers() -> Result<Vec<TcpStream>, Box<dyn Error>> {
    let mut peers: Vec<TcpStream> = vec![];
    let val = INCOMING.lock()?;
    let iter = val.iter();

    for peer in iter {
        peers.push(peer.try_clone()?)
    }
    let val = OUTGOING.lock()?;
    let iter = val.iter();

    for peer in iter {
        peers.push(peer.try_clone()?)
    }

    return Ok(peers);
}

/// # in_peers
/// returns a resut value conatining a bool value.
/// If the peer is in either INCOMING or OUTGOING it will be true
pub fn in_peers(peer: &std::net::SocketAddr) -> Result<bool, Box<dyn Error>> {
    for p in get_peers()? {
        if strip_port(&p.peer_addr()?) == strip_port(peer) {
            return Ok(true);
        }
    }
    return Ok(false);
}

pub fn add_peer(
    peer: TcpStream,
    out: bool,
    key: String,
    tx: &std::sync::mpsc::Sender<String>,
) -> Result<(), Box<dyn Error>> {
    (*PEERS.lock()?).insert(
        strip_port(&peer.peer_addr()?),
        (key, false, Some(tx.clone()), 0),
    );
    if !out {
        let _ = (*INCOMING.lock()?).push(peer);
    } else {
        let _ = (*OUTGOING.lock()?).push(peer);
    }
    return Ok(());
}

pub fn locked(peer: &std::net::SocketAddr) -> Result<bool, Box<dyn Error>> {
    if !in_peers(peer)? {
        return Err("not in peer list".into());
    } else {
        let map = PEERS.lock()?;
        if let Some(x) = map.get(&strip_port(&peer)) {
            return Ok(x.1);
        } else {
            return Err("cant find peer".into());
        }
    }
}

pub fn lock(peer: &SocketAddr, timeout: u64) -> Result<TcpStream, Box<dyn Error>> {
    let begin = std::time::SystemTime::now();
    if !in_peers(peer)? {
        return Err("peer not found".into());
    }
    while locked(peer)? {
        if std::time::SystemTime::now()
            .duration_since(begin)?
            .as_millis() as u64
            >= timeout
            && timeout != 0
        {
            return Err("timed out".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // now the peer is unlocked
    let mut map = PEERS.lock()?;
    if let Some(x) = map.get_mut(&strip_port(&peer)) {
        x.1 = true;
        //tell the handler stream to pause
        if let Some(tx) = x.2.clone() {
            tx.send("pause".to_string())?;
        } else {
            return Err("peer has no handler stream".into());
        }
        for p in get_peers()? {
            if strip_port(
                &p.peer_addr()
                    .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)),
            ) == strip_port(peer)
            {
                return Ok(p);
            }
        }
        return Err("cant find peer".into());
    } else {
        return Err("cant find peer".into());
    }
}

pub fn unlock(peer: TcpStream) -> Result<(), Box<dyn Error>> {
    let peer_add: SocketAddr;
    if let Ok(addr) = peer.peer_addr() {
        peer_add = addr;
    } else {
        return Err("failed to get peer addr".into());
    }
    if !locked(&peer_add)? {
        return Err("peer not locked".into());
    } else {
        let mut map = PEERS.lock()?;
        if let Some(x) = map.get_mut(&strip_port(
            &peer
                .peer_addr()
                .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)),
        )) {
            x.1 = false;
            if let Some(tx) = x.2.clone() {
                tx.send("run".to_string())?;
            } else {
                return Err("peer has no handler stream".into());
            }
        } else {
            return Err("cant find peer".into());
        }
        drop(peer);
    }
    return Ok(());
}
/// # strip_port
/// Takes a SocketAddr and returns the ip address along of a peer, as a string.
/// Eg: 123.45.678:5679 becomes "123.45.678"
pub fn strip_port(peer: &SocketAddr) -> String {
    return peer
        .to_string()
        .split(":")
        .to_owned()
        .collect::<Vec<&str>>()[0]
        .to_owned();
}

pub fn get_invalid_block_count(peer: &SocketAddr) -> Result<u64, Box<dyn std::error::Error>> {
    let map = PEERS.lock()?;
    if let Some(x) = map.get(&strip_port(&peer)) {
        return Ok(x.3);
    } else {
        return Err("cant find peer".into());
    }
}

pub fn set_invalid_block_count(
    peer: &SocketAddr,
    new: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut map = PEERS.lock()?;
    if let Some(x) = map.get_mut(&strip_port(&peer)) {
        x.3 = new;
        return Ok(());
    } else {
        return Err("cant find peer".into());
    }
}
