#[derive(Serialize, Deserialize, Debug)]
struct Tracker {
    sent_bytes: u32,
    received_bytes: u32,
    peers: u32,
    uptime: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct peer_tracker {
    sent_bytes: u32,
    sent_bytes: u32,
}
