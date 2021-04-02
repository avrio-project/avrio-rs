#![feature(allocator_api)]
use avrio_blockchain::Block;
use lazy_static::*;
use log::*;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

lazy_static! {
    static ref CONNECTIONS: Mutex<Vec<(TcpStream, Vec<String>)>> = Mutex::new(vec![]);
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
struct Announcement {
    m_type: String,
    content: String,
}

pub fn block_announce(blk: Block) -> Result<(), Box<dyn std::error::Error>> {
    let connections = &mut CONNECTIONS.lock().unwrap();
    for (stream, subscriptions) in connections.iter_mut() {
        if subscriptions.contains(&"block".to_string()) {
            if let Err(e) = stream.write(
                serde_json::to_string(&Announcement {
                    m_type: "block".to_string(),
                    content: serde_json::to_string(&blk).unwrap_or_default(),
                })
                .unwrap_or_default()
                .as_bytes(),
            ) {
                trace!(
                    "Failed to announce block={} to peer, got error={}",
                    blk.hash,
                    e,
                );
            }
        }
    }
    Ok(())
}

pub fn username_announce(username: String) -> Result<(), Box<dyn std::error::Error>> {
    let connections = &mut CONNECTIONS.lock().unwrap();
    for (stream, subscriptions) in connections.iter_mut() {
        if subscriptions.contains(&"username".to_string()) {
            if let Err(e) = stream.write(
                serde_json::to_string(&Announcement {
                    m_type: "username".to_string(),
                    content: username.clone(),
                })
                .unwrap_or_default()
                .as_bytes(),
            ) {
                trace!(
                    "Failed to announce username={} to peer, got error={}",
                    username,
                    e,
                );
            }
        }
    }
    Ok(())
}

pub fn peer_announce(peer: String) -> Result<(), Box<dyn std::error::Error>> {
    let connections = &mut CONNECTIONS.lock().unwrap();
    for (stream, subscriptions) in connections.iter_mut() {
        if subscriptions.contains(&"peer".to_string()) {
            if let Err(e) = stream.write(
                serde_json::to_string(&Announcement {
                    m_type: "peer".to_string(),
                    content: peer.clone(),
                })
                .unwrap_or_default()
                .as_bytes(),
            ) {
                trace!(
                    "Failed to announce new peer with addr={} to peer, got error={}",
                    peer,
                    e,
                );
            }
        }
    }
    Ok(())
}

pub fn launch(port: u64) {
    info!("Launching RPC server on TCP port: {}", port);
    let bind_res = std::net::TcpListener::bind(format!("127.0.0.1:{}", port));
    if let Ok(listener) = bind_res {
        log::info!("RPC Server bound to 127.0.0.1:{}", port);
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    log::trace!("New incoming stream");
                    let mut hi_buffer = [0; 128];
                    if let Ok(_) = stream.read(&mut hi_buffer) {
                        // turn the buf into a string
                        let hi_string = String::from_utf8(hi_buffer.to_vec()).unwrap_or_default();
                        if hi_string == "init" {
                            let services_list = [
                                "block".to_string(),
                                "chain".to_string(),
                                "username".to_string(),
                                "peer".to_string(),
                            ]; // TODO: move to config
                            let services_list_ser =
                                serde_json::to_string(&services_list).unwrap_or_default();
                            if let Ok(_) = stream.write(services_list_ser.as_bytes()) {
                                let mut register_buffer = [0; 128];
                                if let Ok(_) = stream.read(&mut register_buffer) {
                                    let register_string =
                                        String::from_utf8(register_buffer.to_vec())
                                            .unwrap_or_default();
                                    let mut registered_services: Vec<String> = vec![];
                                    if register_string == "*" {
                                        registered_services = services_list.to_vec();
                                    } else {
                                        let register_services_vec: Vec<String> =
                                            serde_json::from_str(&register_string)
                                                .unwrap_or_default();
                                        for serv in register_services_vec {
                                            if services_list.contains(&serv) {
                                                registered_services.push(serv);
                                            }
                                        }
                                    }
                                    if registered_services.len() == 0 {
                                        let _ = stream.write(b"end");
                                        return;
                                    } else {
                                        // add the peer to the LAZY static
                                        if let Ok(mut connections_lock) = CONNECTIONS.lock() {
                                            let connections_vec = &mut (*connections_lock);
                                            connections_vec.push((stream, registered_services));
                                            let mut new_connections_vec: Vec<(
                                                TcpStream,
                                                Vec<String>,
                                            )> = vec![];
                                            for (stream, registered_services) in connections_vec {
                                                if let Ok(new_stream) = stream.try_clone() {
                                                    new_connections_vec.push((
                                                        new_stream,
                                                        registered_services.clone(),
                                                    ));
                                                }
                                            }
                                            *connections_lock = new_connections_vec;
                                            // TODO: Now create a new thread that trys to read from the stream every x seccodns to ahdnel api requests
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }
}
