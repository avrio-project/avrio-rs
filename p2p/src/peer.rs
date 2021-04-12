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

#[deprecated(
    since = "0.0.0",
    note = "Please use the get peer addr function and call lock() on the ones you need"
)]
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

    Ok(peers)
}

/// Returns a result, vector of the SocketAddrs of the peers we are connected to
pub fn get_peers_addr() -> Result<Vec<SocketAddr>, Box<dyn Error>> {
    let mut peers: Vec<SocketAddr> = vec![];
    let val = INCOMING.lock()?;
    let iter = val.iter();

    for peer in iter {
        if let Ok(peer_addr) = peer.peer_addr() {
            peers.push(peer_addr);
        }
    }
    let val = OUTGOING.lock()?;
    let iter = val.iter();
    for peer in iter {
        if let Ok(peer_addr) = peer.peer_addr() {
            peers.push(peer_addr);
        }
    }

    Ok(peers)
}

/// # in_peers
/// returns a resut value conatining a bool value.
/// If the peer is in either INCOMING or OUTGOING it will be true
pub fn in_peers(peer: &std::net::SocketAddr) -> Result<bool, Box<dyn Error>> {
    for p in get_peers_addr()? {
        if strip_port(&p) == strip_port(peer) {
            return Ok(true);
        }
    }
    Ok(false)
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
    Ok(())
}

pub fn remove_peer(peer: SocketAddr, is_incoming: bool) -> Result<(), Box<dyn Error>> {
    (*PEERS.lock()?).remove(&strip_port(&peer));
    if is_incoming {
        let mut new_incoming: Vec<TcpStream> = vec![];
        for incoming in &(*INCOMING.lock()?) {
            if let Ok(trying_peer_addr) = &incoming.peer_addr() {
                if strip_port(trying_peer_addr) != strip_port(&peer) {
                    let stream = incoming.try_clone()?;
                    new_incoming.push(stream);
                }
            } // if we failed to get the addr of the stream, assume it is disconnected and remove (eg dont add it) it as well
        }
        // now set the INCOMING to the new_incoming vec
        *INCOMING.lock()? = new_incoming;
    } else {
        let mut new_outgoing: Vec<TcpStream> = vec![];
        for outgoing in &(*OUTGOING.lock()?) {
            if let Ok(trying_peer_addr) = &outgoing.peer_addr() {
                if strip_port(trying_peer_addr) != strip_port(&peer) {
                    let stream = outgoing.try_clone()?;
                    new_outgoing.push(stream);
                }
            } // if we failed to get the addr of the stream, assume it is disconnected and remove (eg dont add it) it as well
        }
        // now set the OUTGOING to the new_outgoing vec
        *OUTGOING.lock()? = new_outgoing;
    }
    Ok(())
}

pub fn locked(peer: &std::net::SocketAddr) -> Result<bool, Box<dyn Error>> {
    if !in_peers(peer)? {
        Err("not in peer list".into())
    } else {
        let map = PEERS.lock()?;
        if let Some(x) = map.get(&strip_port(&peer)) {
            Ok(x.1)
        } else {
            Err("cant find peer".into())
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
            log::trace!("Telling handler stream for peer {} to pause", peer);
            tx.send("pause".to_string())?;
            //   std::thread::sleep(std::time::Duration::from_millis(1000)); // wait 350ms for the handler thread to see our message and stop. TODO: wait for a response from the thread instead
            //  log::trace!("Waited 350ms, proceeding")
        } else {
            return Err("peer has no handler stream".into());
        }
        for p in get_peers()? {
            if strip_port(
                &p.peer_addr()
                    .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)),
            ) == strip_port(peer)
            {
                std::thread::sleep(std::time::Duration::from_millis(350)); // wait 350ms for the handler thread to see our message and stop. TODO: wait for a response from the thread instead
                log::trace!("Waited 350ms, proceeding");
                return Ok(p);
            }
        }
        Err("cant find peer".into())
    } else {
        Err("cant find peer".into())
    }
}

pub fn unlock_peer(peer: TcpStream) -> Result<(), Box<dyn Error>> {
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
        if let Some(x) =
            map.get_mut(&strip_port(&peer.peer_addr().unwrap_or_else(|_| {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
            })))
        {
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
    Ok(())
}

/// # strip_port
/// Takes a SocketAddr and returns the ip address along of a peer, as a string.
/// Eg: 123.45.678:5679 becomes "123.45.678"
pub fn strip_port(peer: &SocketAddr) -> String {
    return peer
        .to_string()
        .split(':')
        .to_owned()
        .collect::<Vec<&str>>()[0]
        .to_owned();
}

pub fn get_invalid_block_count(peer: &SocketAddr) -> Result<u64, Box<dyn std::error::Error>> {
    let map = PEERS.lock()?;
    if let Some(x) = map.get(&strip_port(&peer)) {
        Ok(x.3)
    } else {
        Err("cant find peer".into())
    }
}

pub fn set_invalid_block_count(
    peer: &SocketAddr,
    new: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut map = PEERS.lock()?;
    if let Some(x) = map.get_mut(&strip_port(&peer)) {
        x.3 = new;
        Ok(())
    } else {
        Err("cant find peer".into())
    }
}
