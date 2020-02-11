use tokio::net::TcpListener;
use tokio::prelude::*;
use futures::stream::StreamExt;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct P2pdata {
    message_bytes: usize, // The length in bytes of message
    message_type: u16, // The type of data
    message: String,   // The serialized data
}

fn process_block(s: String) {
    println!("Block");
}

fn process_transaction(s: String) {
    println!("Transaction");
}

fn process_registration(s: String) {
    println!("Certificate");
}

fn process_handshake(s: String) {
    println!("handshake");
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

pub fn launchP2pServer(addr: &String, port: &String) {
  let address = String::from(addr.to_owned() + ":" + port);
// todo
}
