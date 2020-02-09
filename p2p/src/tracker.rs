use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Tracker {
    sent_bytes: u32,
    received_bytes: u32,
    peers: u32,
    uptime: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct PeerTracker {
    sent_bytes: u32,
    recieved_bytes: u32,
}
