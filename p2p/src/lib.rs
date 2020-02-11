#[macro_use]
extern crate log;
#[macro_use]
extern crate unwrap;
use crate::tracker::*;
use rand::{Rand, Rng};
extern crate config;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::str;
extern crate hex;
use hex::*;


#[derive(Serialize, Deserialize, Debug)]
pub struct P2pdata {
    pub message_bytes: usize, // The length in bytes of message
    pub message_type: u16, // The type of data
    pub message: String,   // The serialized data
}


pub struct Peer {
    pub id: String,
    pub socket: Socket,     // socket (ip, port) of a peer
    pub info: PeerTracker, // stats about recived and sent bytes from this peer
}

#[derive(Serialize, Deserialize, Debug)]
struct Tracker {
    pub tracker sent_bytes: u32,
    pub received_bytes: u32,
    pub peers: u32,
    pub uptime: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct PeerTracker {
    pub sent_bytes: u32,
    pub recieved_bytes: u32,
}
fn handle_client(mut stream: TcpStream) {
    let mut self_config: Config = config().unwrap();
    let buffer_bytes = 128;
    let mut data = [0 as u8; buffer_bytes]; 
    while match stream.read(&mut data) {
        Ok(size) => {
            deformMsg(str::from_utf8(&data).unwrap());
            true
        }
        Err(_) => {
            println!(
                "[ERROR] Terminating connection with {}",
                stream.peer_addr().unwrap()
            );
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
}

fn rec_server() -> u8 {
    let mut self_config = config();
    let listener = TcpListener::bind(self_config.bind_socket).unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!(
        "[INFO] P2P Server Launched on 127.0.0.1:{:?}",
        self_config.bind_socket
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!(
                    "[INFO] New incoming connection: {}",
                    stream.peer_addr().unwrap()
                );

                thread::spawn(move || {
                    // connection succeeded
                    handle_client(stream)
                });
            }
            Err(e) => {
                println!(
                    "[ERROR] handling peer connection to {:?} resulted in  error: {:?}",
                    stream.peer_addr().unwrap(),
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
fn new_connection(socket: Socket) -> Peer {
    // This Fucntion handles all the details of conecting to a peer, geting id and constructing a Peer struct
    let mut peer: Peer;
    let mut peer_stream = TcpStream::connect(socket)?;
    let self_config = config().unwrap();
    /*Once we have established a connection over TCP we now send vital data as a hanshake,
    This is in the following format
    0x1a, network id,our peer id, our node type, ox1b;
    The recipitent then verifyes this then they send the same hand shake back to us;
    */
    let mut msg = String::from( self_config.network_id
        + ","
        + self_config.id
        + ","
        + self_config.node_type  );
    let _ = stream.write(formMsg(msg,0x1a)); // send our handshake
    let mut buffer: u8 = [];
    let _ = stream.read(&mut buffer);
    let pid: String = process_handshake(str::from_utf8(&buffer).unwrap());
    let mut info = PeerTracker {
        sent_bytes: 128,
        recieved_bytes: 128,
    };
    return Peer {
        id: pid,
        socket: socket,
        info: info,
    };
}

fn process_block(s: String) {hanks cust
    println!("Block");
}

fn process_transaction(s: String) {
    println!("Transaction");
}

fn process_registration(s: String) {
    println!("Certificate");
}

fn process_handshake(s: String) -> String {
    let id: String = String::from(hex::encode(s)); // logicly incorect!!!! just to make code compile 
    return id;
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
        0x1a => process_handshake(msg_d.message),
        _ => println!("[WARN] Bad Messge type from peer. Message type {:?}. (If you ae getting,losts of these check for updates)", msg_d.message_type),
    }
}

pub fn launchP2pServer(addr: Multiaddr) {
  let tcp = TcpConfig::new();
  let _conn = tcp.dial(addr);
}
