use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
extern crate avrio_config;
use std::process;
#[macro_use]
extern crate log;
#[derive(Debug, Serialize, Deserialize)]
struct PeerlistSave {
    peers: Vec<String>,
}
pub fn saveData(serialized: String, path: String, key: String) -> u8 {
    // used to save data without having to create 1000's of functions (eg saveblock, savepeerlist, ect)
    let db = DB::open_default(&path.to_owned()).unwrap_or_else(|e| { 
        error!("Failed to open database at path {}, gave error {:?}", path, e);
        process::exit(0);
    });
    db.put(key, serialized);
    return 1;
}

pub fn savePeerlist(list: &Vec<Vec<u8>>, path: String) {
    let peerlist_s: String;
    let ips: Vec<String>;
    let mut ip_curr: String = "".to_string();
    let mut ip_prv: String;
    let mut pl: PeerlistSave = PeerlistSave {
        peers: vec![]
    };
    for ip in list {
        for ip_seg in ip {
            ip_prv = ip_curr.clone();
            ip_curr = ip_prv + &".".to_owned() + &ip_seg.to_string();
        }
        pl.peers.push(String::from(&ip_curr));
    }
    let pl_s: String = serde_json::to_string(&pl).unwrap_or_else(|e| { warn!("Failed to compact peerlist to string. Gave error: {}", e); return "".to_string()});
    saveData(pl_s, path, "peerlist".to_string());
}

pub fn getData(path: String, key: String) -> String {
    let db = DB::open_default(path).unwrap();
    let mut data: String;
    match db.get(key) {
        Ok(Some(value)) => data = value.to_utf8().unwrap().to_string(),
        Ok(None) => data = "-1".to_owned(),
        Err(e) => data = "0".to_owned(),
    }
    return data;
}

