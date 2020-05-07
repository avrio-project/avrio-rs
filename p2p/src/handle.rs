use crate::{
    format::P2pData,
    io::{read, send},
    peer::add_peer,
};

pub fn launch_handle_client(rx: std::sync::mpsc::Receiver<String>) -> Result<(), Box<dyn std::error::Error>> {
    let handler = std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            if let Ok(msg) = rx.try_recv() {
                if msg == "pause" {
                    loop{
                        if let Ok(msg) = rx.try_recv() {
                            if msg == "run" {
                                break;
                            }
                        }
                    }
                }
            } 
        }
    });
    return Ok(());
}