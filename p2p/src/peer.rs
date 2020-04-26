use tokio::net::TcpStream;
use tokio::prelude::*;
use std::error::Error;



use std::sync::Mutex;

lazy_static! {
    static ref PEERS: Mutex<Vec<TcpStream>> = Mutex::new(vec![]);
}

pub fn get_peers() -> Result<Vec<TcpStream>, Box<dyn Error>> {
    let val = PEERS.lock()?;
    let iter = val.iter();
    let mut peers: Vec<TcpStream> = vec![];
    
    for peer in iter {
        peers.push(peer.try_clone()?)
    }

    return Ok(peers);
}

pub fn in_peers(peer: std::net::SocketAddr) -> Result<bool> {
    for peer in get_peers()? {
        if strip_port(&peer.peer_addr()?) == strip_port(peer) {
            return Ok(true);
        }
    }
    return Ok(false);
}

// TODO: strip port
pub fn strip_port(peer: std::net::SocketAddr) -> String {
    return "".into();
}