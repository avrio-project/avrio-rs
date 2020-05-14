use std::net::{IpAddr, Ipv4Addr, SocketAddr};

extern crate rand_os;
extern crate x25519_dalek;

use avrio_config::config;
use rand_os::OsRng;

use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

use crate::{
    io::{read, send},
    peer::add_peer,
};

pub struct P2pServer {
    state: P2pServerState,
    connections: u64,
    pub ip: String,
    pub port: String,
    pub accept_in: bool,
    tx: Option<std::sync::mpsc::Sender<&'static str>>,
}

impl Default for P2pServer {
    fn default() -> Self {
        Self {
            state: P2pServerState::Uninitialized,
            connections: 0,
            ip: "0.0.0.0".to_string(),
            port: "56789".to_string(),
            accept_in: true,
            tx: None,
        }
    }
}
#[derive(PartialEq, Debug)]
enum P2pServerState {
    AcceptingIncoming,
    DenyNewConnections,
    ShuttingDown,
    Uninitialized,
}
fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

impl P2pServer {
    pub fn new(ip: String, port: String, accept_in: bool) -> P2pServer {
        return P2pServer {
            state: P2pServerState::Uninitialized,
            connections: 0,
            ip,
            port,
            accept_in,
            tx: None,
        };
    }
    fn set_state(&mut self, state: P2pServerState) {
        self.state = state;
    }
    fn increment_connections(&mut self) {
        if self.state != P2pServerState::DenyNewConnections
            && self.state != P2pServerState::Uninitialized
            && self.state != P2pServerState::ShuttingDown
        {
            self.connections += 1;
        }
    }
    fn deincrement_connections(&mut self) {
        if self.state != P2pServerState::DenyNewConnections
            && self.state != P2pServerState::Uninitialized
            && self.state != P2pServerState::ShuttingDown
        {
            self.connections -= 1;
        }
    }
    pub fn set_bind_addr(&mut self, bind: &std::net::SocketAddr) -> Result<(), &'static str> {
        let bind_addr_as_string: String = bind.to_string();
        let bind_addr_split = bind_addr_as_string.split(":").collect::<Vec<&str>>();
        if bind_addr_split.len() <= 1 {
            return Err("resultant string too short when split");
        } else {
            self.ip = bind_addr_split[0].to_string();
            self.port = bind_addr_split[1].to_string();
            return Ok(());
        }
    }
    pub fn launch(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.state == P2pServerState::Uninitialized {
            let bind_res = std::net::TcpListener::bind(format!("{}:{}", self.ip, self.port));
            if let Ok(listener) = bind_res {
                for stream in listener.incoming() {
                    match stream {
                        Ok(mut stream) => {
                            if let Ok(read_msg) =
                                read(&mut stream, Some(1000), Some("hand_key".as_bytes()))
                            {
                                let addr = stream.peer_addr().unwrap_or(SocketAddr::new(
                                    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                    0,
                                ));
                                if let Ok(in_peers) = crate::peer::in_peers(&addr) {
                                    if in_peers == false {
                                        let mut local_cspring = OsRng::new().unwrap();
                                        let local_sec = EphemeralSecret::new(&mut local_cspring);
                                        let local_pub = PublicKey::from(&local_sec);
                                        let d_split =
                                            read_msg.message.split("*").collect::<Vec<&str>>();

                                        if hex::encode(config().network_id) != d_split[0] {
                                            log::debug!("Peer tried to handshake with wrong network id. Expecting: {}, got: {}. Ignoring...", hex::encode(config().network_id), d_split[0]);
                                            // TODO: send shutdown type first!
                                            stream.shutdown(std::net::Shutdown::Both);
                                        } else {
                                            let addr_s = addr.to_string();
                                            let ip_s = addr_s.split(":").collect::<Vec<&str>>()[0];
                                            let addr_s = format!("{}:{}", ip_s, d_split[3]);
                                            let mut save_res: Result<(), &'static str> = Ok(());
                                            let _ = avrio_database::add_peer(addr_s.parse().unwrap_or(SocketAddr::new(
                                            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                            0,
                                        ))).unwrap_or_else(|e| {
                                            log::error!("Saving peer gave error: {}, dropping connection", e);
                                            // TODO: send shutdown type first!
                                            stream.shutdown(std::net::Shutdown::Both);
                                            save_res = Err("Saving peer gave error");
                                        });
                                            if let Err(e) = save_res {
                                                return Err(e.into());
                                            }
                                            let key = local_sec.diffie_hellman(&PublicKey::from(
                                                from_slice(
                                                    &hex::decode(d_split[4]).unwrap_or_default(),
                                                ),
                                            ));
                                            let handshake =
                                                crate::core::form_handshake(local_pub.as_bytes());
                                            let _ = crate::io::send(
                                                handshake,
                                                &mut stream,
                                                0x1a,
                                                true,
                                                Some("hand_key".as_bytes()),
                                            )
                                            .unwrap_or_default();
                                            if let Ok(d) = crate::io::read(
                                                &mut stream,
                                                Some(100000),
                                                Some(key.as_bytes()),
                                            ) {
                                                if d.message_type != 0xa2 {
                                                    return Err(
                                                        "wrong seccond response type".into()
                                                    );
                                                } else {
                                                    // We understood that key - we can send ack (accept)
                                                    let _ = send(
                                                        "ack".to_string(),
                                                        &mut stream,
                                                        0xa3,
                                                        true,
                                                        Some("hand_res".as_bytes()),
                                                    );
                                                    // now we add peer to peers list
                                                    log::info!(
                                                        "New incoming connection to peer: {}",
                                                        stream.peer_addr().unwrap()
                                                    );

                                                    let _ = avrio_database::add_peer(
                                                        stream.peer_addr().unwrap(),
                                                    );

                                                    if let Err(e) = avrio_database::add_peer(
                                                        stream.peer_addr().unwrap(),
                                                    ) {
                                                        log::error!(
                                                        "Failed to add peer: {} to peer list, gave error: {}",
                                                        stream.peer_addr().unwrap(),
                                                        e
                                                    );

                                                        drop(listener);

                                                        return Err(
                                                            "failed to add peer to peerlist".into(),
                                                        );
                                                    } else {
                                                        std::thread::spawn(move || {
                                                            // connection succeeded
                                                            let (tx, rx) =
                                                                std::sync::mpsc::channel();
                                                            let _ = add_peer(
                                                                stream.try_clone().unwrap(),
                                                                false,
                                                                hex::encode(key.as_bytes()),
                                                                &tx,
                                                            );
                                                            let _ =
                                                                crate::handle::launch_handle_client(
                                                                    rx,
                                                                    &mut stream
                                                                        .try_clone()
                                                                        .unwrap(),
                                                                );
                                                        });
                                                    }
                                                }
                                            } else {
                                                // WE did not understand that key - send rej (reject)
                                                let _ = send(
                                                    "rej".to_string(),
                                                    &mut stream,
                                                    0xa3,
                                                    true,
                                                    Some("hand_res".as_bytes()),
                                                );
                                            }
                                        }
                                    } else {
                                        log::debug!("Got handshake from handshook peer, ignoring");
                                    }
                                }
                            }
                        }

                        Err(e) => {
                            log::warn!(
                                "Handling peer connection to peer resulted in  error: {}",
                                e
                            );
                            /* connection failed */
                        }
                    };
                }
            }
        } else {
            return Err("allready running".into());
        }
        return Ok(());
    }
    pub fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        return Ok(());
    }
}
