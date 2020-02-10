use tokio::net::TcpListener;
use tokio::prelude::*;
use futures::stream::StreamExt;

pub enum p2p_errors {
  None,
  TimeOut,
  InvalidMultiAdrr,
  Other
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
                    let (mut reader, mut writer) = sock.split();
                    handleConn(reader, writer);
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
