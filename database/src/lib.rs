use rocksdb::{DBRawIterator, DB};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
#[macro_use]
extern crate log;
extern crate avrio_config;
use avrio_config::config;
#[derive(Debug, Serialize, Deserialize)]
struct PeerlistSave {
    peers: Vec<String>,
}
pub fn openDb(path: String) -> Result<rocksdb::DB, ()> {
    if let Ok(database) = DB::open_default(&path.to_owned()) {
        return Ok(database);
    } else {
        return Err(());
    }
}
pub fn getIter<'a>(db: &'a rocksdb::DB) -> DBRawIterator<'a> {
    return db.raw_iterator();
}
pub fn saveData(serialized: String, path: String, key: String) -> u8 {
    // used to save data without having to create 1000's of functions (eg saveblock, savepeerlist, ect)
    let db = DB::open_default(&path.to_owned()).unwrap_or_else(|e| {
        error!(
            "Failed to open database at path {}, gave error {:?}",
            path, e
        );
        process::exit(0);
    });
    db.put(key, serialized);
    return 1;
}

pub fn get_peerlist() -> std::result::Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let s = getData(
        config().db_path + &"/peers".to_string(),
        &"white".to_string(),
    );
    if s == "-1".to_owned() {
        return Err("peerlist not found".into());
    } else {
        let peerlist: PeerlistSave = serde_json::from_str(&s)?;
        let mut as_socket_addr: Vec<SocketAddr> = vec![];
        for peer in peerlist.peers {
            as_socket_addr.push(peer.parse()?);
        }
        return Ok(as_socket_addr);
    }
}

pub fn add_peer(peer: SocketAddr) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut current_peer_list = get_peerlist()?;
    current_peer_list.push(peer);
    return save_peerlist(&current_peer_list);
}

pub fn save_peerlist(
    _list: &Vec<SocketAddr>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut as_string: Vec<String> = vec![];
    for peer in _list {
        as_string.push(peer.to_string());
    }
    let s = serde_json::to_string(&as_string)?;
    saveData(
        s,
        config().db_path + &"/peers".to_string(),
        "white".to_string(),
    );
    return Ok(());
}

pub fn getData(path: String, key: &String) -> String {
    let db = DB::open_default(path).unwrap();
    let data: String;
    match db.get(key) {
        Ok(Some(value)) => data = String::from_utf8(value).unwrap_or("".to_owned()),
        Ok(None) => data = "-1".to_owned(),
        Err(_e) => data = "0".to_owned(),
    }
    return data;
}

pub fn getDataDb(db: &DB, key: &String) -> String {
    let data: String;
    match db.get(key) {
        Ok(Some(value)) => data = String::from_utf8(value).unwrap_or("".to_owned()),
        Ok(None) => data = "-1".to_owned(),
        Err(_e) => data = "0".to_owned(),
    }
    return data;
}
