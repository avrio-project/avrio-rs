// This file handles the assessor node functions

use avrio_p2p::{format::P2pData, io::send};
use std::io::Read;
use std::net::TcpStream;
extern crate serde_json;

pub fn test_prt(peer: &mut TcpStream) -> u64 {
    let _ = send("ping".to_owned(), peer, 0x00, true, None);
    let now = std::time::SystemTime::now();
    let mut buf = [0; 1024];
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
    let _ = peer.try_clone().unwrap().read(&mut buf);
    let time = std::time::SystemTime::now()
        .duration_since(now)
        .unwrap_or_default()
        .as_millis() as u64;
    let msg = String::from_utf8(buf.to_vec()).unwrap_or_else(|_| "utf8 failed".to_string());
    let v: Vec<&str> = msg.split('}').collect();
    let msg_c = v[0].to_string() + &"}".to_string();
    drop(v);
    let deformed: P2pData = serde_json::from_str(&msg_c).unwrap_or_else(|_| P2pData::default());
    if deformed.message != *"pong" {
        100000
    } else {
        time
    }
}
