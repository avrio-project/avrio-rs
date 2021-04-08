use crate::{
    io::{read, send},
    peer::add_peer,
};
extern crate rand;
extern crate x25519_dalek;

use avrio_config::config;

use crate::peer::in_peers;
use std::{convert::TryInto, net::SocketAddr};
use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;
fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}
use log::trace;

pub fn new_connection(addr: &str) -> Result<std::net::TcpStream, Box<dyn std::error::Error>> {
    if in_peers(
        &addr.parse::<SocketAddr>()?
    )? {
        return Err("Already connected".into());
    }
    log::info!("Connecting to {}", addr);
    let mut a = std::net::TcpStream::connect(addr)?;
    let mut local_cspring = rand::rngs::OsRng;
    let local_sec = EphemeralSecret::new(&mut local_cspring);
    let local_pub = PublicKey::from(&local_sec);
    let handshake = form_handshake(local_pub.as_bytes());
    trace!("Formed handshake, {}", handshake);
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
    let d = crate::io::read(
        &mut a,
        Some(2000),
        Some("hand_keyhand_keyhand_keyhand_key".as_bytes()),
    )?;
    if d.message == "cancel" {
        return Err("canceled by peer".into());
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
                } else if let Err(e) = crate::handle::launch_handle_client(rx, &mut a) {
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

pub fn close_all() {}

pub fn close(_peer: std::net::SocketAddr) {}
