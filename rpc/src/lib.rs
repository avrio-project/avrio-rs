use avrio_core::block::{Block, BlockType};
use lazy_static::*;
use log::*;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;

lazy_static! {
    static ref CONNECTIONS: Mutex<Vec<(TcpStream, Vec<String>)>> = Mutex::new(vec![]);
    pub static ref LOCAL_CALLBACKS: Mutex<Vec<Caller<'static>>> = Mutex::new(vec![]);
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Announcement {
    pub m_type: String,
    pub content: String,
}
unsafe impl Send for Announcement {}
pub struct Caller<'callback> {
    pub callback: Box<dyn FnMut(Announcement) + Send + 'callback>,
}

impl Caller<'_> {
    pub fn call(&mut self, ann: Announcement) {
        (self.callback)(ann)
    }
}
pub fn block_announce(blk: Block) -> Result<(), Box<dyn std::error::Error>> {
    if blk.block_type == BlockType::Send {
        info!(
            "New block! Hash={}, Sender={}, Type=Send",
            blk.hash, blk.header.chain_key
        );
    } else {
        info!(
            "New block! Hash={}, Sender={}, Type=Recieve, Send block hash={}",
            blk.hash,
            blk.header.chain_key,
            blk.send_block
                .as_ref()
                .unwrap_or(&"(Error unwrapping)".to_string())
        );
    }
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
    let mut local_callbacks = LOCAL_CALLBACKS.lock().unwrap();
    for callback in local_callbacks.iter_mut() {
        callback.call(Announcement {
            m_type: "block".to_string(),
            content: serde_json::to_string(&blk).unwrap_or_default(),
        });
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

pub fn launch_client(
    server_ip: String,
    server_port: u64,
    services: Vec<String>,
    mut caller: Caller<'static>,
) -> Result<(), Box<dyn Error>> {
    info!(
        "Launching RPC server client, connecting to server on port={}",
        server_port
    );
    if let Ok(mut stream) = TcpStream::connect(format!("{}:{}", server_ip, server_port)) {
        if let Ok(_) = stream.write(b"init") {
            debug!("Sent init message to server");
            let mut buf = [0u8; 1024];
            if services.is_empty() {
                // use all services we can discard the read bytes
                if let Ok(_) = stream.read(&mut buf) {
                    drop(buf);
                    if let Ok(_) = stream.write(b"*") {
                        debug!("Sent services register command (*=all)");
                        info!("Connected to RPC server at 127.0.0.1:{}", server_port);
                        let _loop_thread_handle = std::thread::spawn(move || loop {
                            let mut buf = [0u8; 2048];
                            if let Ok(size_of_msg) = stream.peek(&mut buf) {
                                debug!("Peeked {} bytes into buffer, reading", size_of_msg);
                                let mut new_buf = vec![0u8; size_of_msg];
                                if let Ok(read_bytes) = stream.read(&mut new_buf) {
                                    if read_bytes == 0 {
                                        // TODO: Ping the client and if they don't respond then disconect the stream like so
                                        debug!("Read 0 bytes, assuming peer disconect");
                                        return;
                                    }
                                    trace!(
                                        "Read bytes into buffer (read={}, expected={}, parity={})",
                                        read_bytes,
                                        size_of_msg,
                                        read_bytes == size_of_msg
                                    );
                                    if let Ok(message_string) = String::from_utf8(new_buf) {
                                        if let Ok(announcement) =
                                            serde_json::from_str::<Announcement>(&message_string)
                                        {
                                            debug!("Recieved new announcement from server, announcement={:#?}", announcement);
                                            caller.call(announcement);
                                            trace!(
                                                "Called the caller's callback with announcement"
                                            );
                                        }
                                    }
                                }
                            }
                        });
                        info!("Spawned RPC listener thread");
                        return Ok(());
                    } else {
                        error!("Failed to write * register to stream");
                        return Err("Failed to write * register to stream".into());
                    }
                } else {
                    error!("Failed to read avilable services into void ");
                    return Err("could not read available services into void".into());
                }
            } else if let Ok(read_bytes) = stream.read(&mut buf) {
                let buf_trimmed = buf[0..read_bytes].to_vec();
                let services_list_string = String::from_utf8(buf_trimmed).unwrap_or_default();
                let services_list: Vec<String> =
                    serde_json::from_str(&services_list_string).unwrap_or_default();
                let mut to_register: Vec<String> = vec![];
                for service in services_list.clone() {
                    if services.contains(&service) {
                        to_register.push(service);
                    }
                }
                if to_register.is_empty() {
                    error!(
                        "Server had no overlapping services: server={:#?}, us={:#?}",
                        services_list, services
                    );
                } else {
                    info!(
                        "Connected to RPC server at 127.0.0.1:{}, registered_services={:#?}",
                        server_port, services_list
                    );
                    let _loop_thread_handle = std::thread::spawn(move || loop {
                        let mut buf = [0u8; 2048];
                        if let Ok(size_of_msg) = stream.peek(&mut buf) {
                            debug!("Peeked {} bytes into buffer, reading", size_of_msg);
                            let mut new_buf = vec![0u8; size_of_msg];
                            if let Ok(read_bytes) = stream.read(&mut new_buf) {
                                trace!(
                                    "Read bytes into buffer (read={}, expected={}, parity={})",
                                    read_bytes,
                                    size_of_msg,
                                    read_bytes == size_of_msg
                                );
                                if let Ok(message_string) = String::from_utf8(new_buf) {
                                    if let Ok(announcement) =
                                        serde_json::from_str::<Announcement>(&message_string)
                                    {
                                        debug!("Recieved new announcement from server, announcement={:#?}", announcement);
                                        caller.call(announcement);
                                        trace!("Called the caller's callback with announcement");
                                    }
                                }
                            }
                        }
                    });
                    info!("Spawned RPC listener thread");
                    return Ok(());
                }
            }
        } else {
            error!("Failed to write init msg");
            return Err("Failed to write init msg".into());
        }
    } else {
        error!("Failed to connect to server");
        return Err("Failed to connect to server".into());
    }
    return Err("reached end of function".into());
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
                    let mut hi_buffer = [0u8; 128];
                    if let Ok(read_bytes) = stream.read(&mut hi_buffer) {
                        // turn the buf into a string
                        let hi_string = String::from_utf8(hi_buffer[0..read_bytes].to_vec())
                            .unwrap_or_default();
                        if hi_string == "init" {
                            let services_list = ["block".to_string()]; // TODO: move to config
                            let services_list_ser =
                                serde_json::to_string(&services_list).unwrap_or_default();
                            if let Ok(_) = stream.write(services_list_ser.as_bytes()) {
                                let mut register_buffer = [0u8; 128];
                                if let Ok(read_bytes) = stream.read(&mut register_buffer) {
                                    let register_string =
                                        String::from_utf8(register_buffer[0..read_bytes].to_vec())
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
