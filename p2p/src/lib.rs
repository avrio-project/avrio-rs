use tokio::net::TcpListener;
use tokio::prelude::*;
use futures::stream::StreamExt;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct P2pdata {
    message_bytes: u64, // The length in bytes of this message
    message: String,   // The serialized data
}

pub enum p2p_errors {
  None,
  TimeOut,
  InvalidMultiAdrr,
  Other
}
function formMsg(data_s: String, network_id: Vec<byte>) -> Vec<bytes> {
    let mut msg: Vec<bytes>;
    for byte_ in network_id {
        msg.push(byte);
    }
    for byte_ in data_s.as_bytes() {
        msg.push(byte_);
    }
    msg.push(0x00);
    return msg;
}
function handleConn(sock: UdpSocket) {
  let (mut reader, mut writer) = sock.split(); 
  let data = reader.blah(); // todo
  match data[0..4] {
    "0x0a" => let mut block: Block, // block
    "0x0b" => let mut txn: Transaction,
    "0x0c" => let mut certificate: Certificate,
  }
}
/* msg format
network id
msg type (eg 0x1b = block)
serilised P2pdata
0x00 (null)
*/
pub function launchP2pServer(addr: &String, port: &16) {
  let address = String::from(addr + ":" + port);
  let mut listener = TcpListener::bind(address).await.unwrap();
  let server = async move {
        let mut incoming = listener.incoming();
        while let Some(socket_res) = incoming.next().await {
            match socket_res {
                Ok(socket) => {
                    println!("[INFO] Accepted connection from {:?}", socket.peer_addr());
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
