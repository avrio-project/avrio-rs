use std::net::TcpStream;
use std::error::Error;



use std::sync::Mutex;

lazy_static! {
    static ref INCOMING: Mutex<Vec<TcpStream>> = Mutex::new(vec![]);
    static ref OUTGOING: Mutex<Vec<TcpStream>> = Mutex::new(vec![]);
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
pub fn in_peers(peer: std::net::SocketAddr) -> Result<bool, Box<dyn Error>> {
    for p in get_peers()? {
        if strip_port(p.peer_addr()?) == strip_port(peer) {
            return Ok(true);
        }
    }
    return Ok(false);
}

// TODO: strip port
/// # strip_port
/// Takes a SocketAddr and returns the ip address along of a peer, as a string.
/// Eg: 123.45.678:5679 becomes "123.45.678"
pub fn strip_port(peer: std::net::SocketAddr) -> String {
    todo!();
}