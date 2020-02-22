#[macro_use]
extern crate log;
#[macro_use]
use serde::{Deserialize, Serialize};
#[macro_use]
extern crate unwrap;
extern crate avrio_config;
use std::io::{Read, Write};
use std::process;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::str;
use std::thread;
extern crate hex;
use std::error::Error;
extern crate simple_logger;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct P2pdata {
    pub message_bytes: usize, // The length in bytes of message
    pub message_type: u16,    // The type of data
    pub message: String,      // The serialized data
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Peer {
    pub id: String,
    pub socket: SocketAddr, // socket (ip, port) of a peer
    pub info: PeerTracker,  // stats about recived and sent bytes from this peer
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Tracker {
    pub sent_bytes: u32,
    pub received_bytes: u32,
    pub peers: u32,
    pub uptime: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PeerTracker {
    pub sent_bytes: u32,
    pub recieved_bytes: u32,
}
fn handle_client(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    loop {
        let mut data = [0 as u8; 200];
        match stream.read(&mut data) {
            Ok(_) => {
                match deformMsg(&String::from_utf8(data.to_vec()).unwrap()) {
                    Some(a) => {
                        /* we just recieved a handshake, now we send ours
                        This is in the following format
                        network id, our peer id, our node type;
                        */
                        let msg = hex::encode(config().network_id)
                            + "*"
                            + &config().identitiy
                            + "*"
                            + &config().node_type.to_string();
                        info!("Our handshake: {}", msg);
                        let _ = stream.write_all(formMsg(msg.to_owned(), 0x1a).as_bytes()); // send our handshake
                        
                    }
                    _ =>  {}
                }
            }
            Err(_) => {
                debug!(
                    "Terminating connection with {}",
                    stream.peer_addr().unwrap()
                );
                stream.shutdown(Shutdown::Both).unwrap();
                return Err("undefined".into());
            }
        } {}
    }
    return Ok(());
}
fn rec_server() -> u8 {
    let listener = TcpListener::bind("0.0.0.0:56789").unwrap();
    // accept connections and process them, spawning a new thread for each one
    info!("P2P Server Launched on 0.0.0.0:{}", 56789);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("New incoming connection to peer: {}", stream.peer_addr().unwrap());

                thread::spawn(move || {
                    // connection succeeded
                    let _ = handle_client(stream);
                });
            }
            Err(e) => {
                warn!("handling peer connection to peer resulted in  error: {}", e);
                /* connection failed */
            }
        }
    }
    // close the socket server
    drop(listener);
    return 1;
}
fn new_connection(socket: SocketAddr) -> Result<Peer, Box<dyn Error>> {
    // This Fucntion handles all the details of conecting to a peer, geting id and constructing a Peer struct
    let mut stream = TcpStream::connect(socket)?;
    let self_config = config();
    /*Once we have established a connection over TCP we now send vital data as a hanshake,
    This is in the following format
    network id,our peer id, our node type;
    The recipitent then verifyes this then they send the same hand shake back to us;
    */
    let msg = hex::encode(self_config.network_id)
        + "*"
        + &self_config.identitiy
        + "*"
        + &self_config.node_type.to_string();
    let _ = stream.write(formMsg(msg, 0x1a).as_bytes()); // send our handshake
    let mut buffer_n = [0; 200];
    //error!("{:?}", buffer_n.len());
    let read = stream.read(&mut buffer_n);
    match read {
        Ok(0) => {
            error!("Got No Data, retrying");
            let read_retry = stream.read(&mut buffer_n);
            match read_retry {
                Ok(0) => {
                    warn!("Got No Data on retry.");
                    return Err("no data read".into());
                }
                Ok(_) => {
                    info!("Retry worked");
                }
                _ => warn!("Failed"),
            }
        }
        _ => {}
    }
    trace!("stream read = {:?}", read);
    debug!(
        "recived handshake, as string {}",
        String::from_utf8(buffer_n.to_vec()).unwrap()
    );
    let pid: String;
    match deformMsg(&String::from_utf8(buffer_n.to_vec())?) {
        Some(x) => {
            pid = x;
        }
        None => {
            warn!("Got no Id from peer");
            return Err("Got no id".into());
        }
    };
    sendData("hello".to_string(), &mut stream,  0x01);
    let mut info = PeerTracker {
        sent_bytes: 200,
        recieved_bytes: 200,
    };
    return Ok(Peer {
        id: pid,
        socket,
        info,
    });
}

fn process_message(s: String) {
    info!("Message:{}", s);
}

fn process_block(s: String) {
    info!("Block {}", s);
}

fn process_transaction(s: String) {
    info!("Transaction {}", s);
}

fn process_registration(s: String) {
    info!("Certificate {}", s);
}

fn process_handshake(s: String) -> Result<String, String> {
    trace!("Handshake: {}", s);
    let id: String;
    let network_id_hex = hex::encode(config().network_id);
    let network_id_hex_len = network_id_hex.len();
    if s.len() < network_id_hex_len {
        warn!(
            "Bad handshake recived from peer (too short. Len: {}, Should be: {}), handshake: {}",
            s.len(),
            network_id_hex_len,
            s
        );
        //return Err("Handshake too short".to_string());
    }
    let peer_network_id_hex: &String = &s[0..network_id_hex.len()].to_string();
    if network_id_hex != peer_network_id_hex.to_owned() {
        debug!("Recived erroness network id {}", peer_network_id_hex);
        return Err(String::from("Incorrect network id"));
    } else {
        let val = s[peer_network_id_hex.len() + 1..s.len()].to_string();
        drop(s);
        let v: Vec<&str> = val.split("*").collect();
        id = v[0].to_string();
    }
    info!("Handshook with peer, gave id {}", id);
    return Ok(id);
}

pub enum p2p_errors {
    None,
    TimeOut,
    InvalidSocket,
    Other,
}

fn sendData(data: String, peer: &mut TcpStream, msg_type: u16) { // This function takes some data as a string and places it into a struct before sending to the peer
    let data_s: String = formMsg(data, msg_type);
    let sent = peer.write_all(data_s.as_bytes());

}

fn formMsg(data_s: String, data_type: u16) -> String {
    let data_len = data_s.len();
    let msg: P2pdata = P2pdata {
        message_bytes: data_len,
        message_type: data_type,
        message: data_s,
    };
    return serde_json::to_string(&msg).unwrap();
}

fn deformMsg(msg: &String) -> Option<String> {
    // deforms message and excutes appropriate function to handle resultant data
    let v: Vec<&str> = msg.split("}").collect();
    let msg_c = v[0].to_string() + &"}".to_string();
    trace!("recive: {}", msg_c);
    drop(v);
    let mut msg_d: P2pdata = serde_json::from_str(&msg_c).unwrap_or_else(|e| {
        debug!(
            "Bad Packets recieved from peer, packets: {}. Parsing this gave error: {}",
            msg, e
        );
        return P2pdata::default();
    });
    match msg_d.message_bytes {
        0 => return Some("none".to_string()),
        _ => (),
    }
    match msg_d.message_type {
        0x01 => {
            process_message(msg_d.message);
            return None;
        },
        0x0a => {
            process_block(msg_d.message);
            return None;
        }
        0x0b => {
            process_transaction(msg_d.message);
            return None;
        }
        0x0c => {
            process_registration(msg_d.message);
            return None;
        }
        0x1a => {
            return Some(process_handshake(msg_d.message).unwrap());
        }
        _ => {
            warn!("Bad Messge type from peer. Message type {}. (If you are getting, lots of these check for updates)", msg_d.message_type.to_string());
            return None;
        }
    }
}
