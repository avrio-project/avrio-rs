#[macro_use]
extern crate log;
#[macro_use]
extern crate unwrap;
extern crate avrio_config;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, SocketAddr};
use std::thread;
use std::str;
extern crate hex;
use serde::{Deserialize, Serialize};
use avrio_config::config;
use std::error::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct P2pdata {
    pub message_bytes: usize, // The length in bytes of message
    pub message_type: u16, // The type of data
    pub message: String,   // The serialized data
}


pub struct Peer {
    pub id: String,
    pub socket: SocketAddr,     // socket (ip, port) of a peer
    pub info: PeerTracker, // stats about recived and sent bytes from this peer
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tracker {
    pub sent_bytes: u32,
    pub received_bytes: u32,
    pub peers: u32,
    pub uptime: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerTracker {
    pub sent_bytes: u32,
    pub recieved_bytes: u32,
}
fn handle_client(mut stream: TcpStream) {
    let mut data = [0 as u8; 128]; 
    while match stream.read(&mut data) {
        Ok(_) => {
            deformMsg(&String::from_utf8(data.to_vec()).unwrap());
            true
        }
        Err(_) => {
            debug!(
                "Terminating connection with {}",
                stream.peer_addr().unwrap()
            );
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}

fn rec_server() -> u8 {
    let _self_config = config();
    let listener = TcpListener::bind("127.0.0.1:56789").unwrap();
    // accept connections and process them, spawning a new thread for each one
    info!(
        "P2P Server Launched on 127.0.0.1:{}",
        56789
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!(
                    "New incoming connection: {}",
                    stream.peer_addr().unwrap()
                );

                thread::spawn(move || {
                    // connection succeeded
                    handle_client(stream)
                });
            }
            Err(e) => {
                warn!(
                    "handling peer connection to peer resulted in  error: {:?}",
                    e
                );
                /* connection failed */
            }
        }
    }
    // close the socket server
    drop(listener);
    return 1;
}
fn new_connection(socket: SocketAddr) -> Result<Peer,Box<dyn Error>> {
    // This Fucntion handles all the details of conecting to a peer, geting id and constructing a Peer struct
    let mut stream = TcpStream::connect(socket)?;
    let self_config = config();
    /*Once we have established a connection over TCP we now send vital data as a hanshake,
    This is in the following format
    network id,our peer id, our node type;
    The recipitent then verifyes this then they send the same hand shake back to us;
    */
    let msg = hex::encode(self_config.network_id)
        + ","
        + &self_config.identitiy
        + ","
        + &self_config.node_type.to_string();
    let _ = stream.write(formMsg(msg,0x1a).as_bytes()); // send our handshake
    let mut buffer = [0, 128];
    let _ = stream.read(&mut buffer);
    let pid: String = process_handshake(String::from_utf8(buffer.to_vec()).unwrap())?;
    let mut info = PeerTracker {
        sent_bytes: 128,
        recieved_bytes: 128,
    };
    return Ok(Peer {
        id: pid,
        socket,
        info,
    });
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
    let id: String;
    let network_id_hex = hex::encode(config().network_id);
    let peer_network_id_hex: &String = &s[0..network_id_hex.len()].to_string();
    if network_id_hex != peer_network_id_hex.to_owned() {
        return Err(String::from("Incorrect network id"));
    } else {
        let val = s[peer_network_id_hex.len()+1..s.len()].to_string();
        drop(s);
        let v: Vec<&str> = val.split(",").collect();
        id = v[0].to_string();
    }
    return Ok(id);
}


pub enum p2p_errors {
  None,
  TimeOut,
  InvalidSocket,
  Other,
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

fn deformMsg(msg: &String) { // deforms message and excutes appropriate function to handle resultant data
    let mut msg_d:P2pdata = serde_json::from_str(msg).unwrap();
    match msg_d.message_type {
        0x0a => process_block(msg_d.message),
        0x0b => process_transaction(msg_d.message),
        0x0c => process_registration(msg_d.message),
        0x1a => {match process_handshake(msg_d.message) {
            _ => (),
        }},
        _ => warn!("Bad Messge type from peer. Message type {:?}. (If you ae getting, lots of these check for updates)", msg_d.message_type),
    }
}

