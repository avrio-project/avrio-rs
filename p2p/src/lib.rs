use tokio::net::TcpListener;
use tokio::prelude::*;
use futures::stream::StreamExt;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct P2pdata {
    message_bytes: u64, // The length in bytes of message
    message_type: byte, // The type of data
    message: String,   // The serialized data
}

pub enum p2p_errors {
  None,
  TimeOut,
  InvalidSocket,
  Other,
}

function formMsg(data_s: String, data_type: byte) -> String {
    let mut msg: P2pdata = {
        message_bytes: data_s.len(),
        message_type: data_type,
        message: data_s,
    };
    return serde_json::to_string(&msg).unwrap();
}

function deformMsg(&msg: String) -> u8 { // deforms message and excutes appropriate function to handle resultant data
    let mut msg_d:P2pdata = serde_json::from_string(msg).unwrap();
    match msg_d.message_type {
        "0x0a" => process_block(msg_d.message) => return 1, // block
        "0x0b" => process_transaction(msg_d.message) => return 2,
        "0x0c" => process_registration(msg_d.message) => return 3,
        "0x1a" => process_handshake(msg_d.message) => return 4,
        _ => println!("[WARN] Bad Messge type from peer. Message type {:?}. (If you ae getting,losts of these check for updates)", msg_d.message_type) => return 0,
    }
}

function handleConn(&sock: UdpSocket) {
  let (mut reader, mut writer) = sock.split(); 
  let data = reader.blah(); // todo
  deformMsg(&data);
}

pub function launchP2pServer(addr: &String, port: &16) {
  let address = String::from(addr + ":" + port);
  let mut listener = TcpListener::bind(address).await.unwrap();
  let server = async move {
        let mut incoming = listener.incoming();
        while let Some(socket_res) = incoming.next().await {
            match socket_res {
                Ok(socket) => {
                    println!("[INFO] Accepted connection from {:?}", socket.peer_addr());
                    // Now handle the message they send to us
                    handleConn(socket);
                }
                Err(err) => {
                    // Handle error by printing to STDOUT.
                    println!("[WARN] Error accepting peer {:?}, threw error = {:?}",socket.peer_addr(), err);
                }
            }
        }
    };
    thread::Builder::new().name("p2pServer".to_string()).spawn( move || {
      server.await;
    }
}
