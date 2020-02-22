use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
extern crate config;
extern crate log;

fn saveData(serialized: String, path: String, key: String) -> u8 {
    // used to save data without having to create 1000's of functions (eg saveblock, savepeerlist, ect)
    let db = DB::open_default(path).unwrap_or_else(|e| { 
        fatal!("Failed to open database at path {}, gave error {:?}", path, e);
    });
    db.put(key, serialized);
    return 1;
}

fn savePeerlist(list: &Vec<Vec<u8>>, path) {
    let peerlist_s: String;
    let ips: Vec<String>;
    let ip_curr: String;
    for ip in list {
        for ip_seg in ip {
            ip_curr = &ip_curr + ".".to_owned() + &String::from(ip_seg);
        }
        ips.push(String:from(ip_curr));
    }
    saveData(ips, path, "peerlist");
}

fn getData(path: String, key: String) -> String {
    let db = DB::open_default(path).unwrap();
    let mut data: String;
    match db.get(key) {
        Ok(Some(value)) => data = value,
        Ok(None) => data = "-1".to_owned(),
        Err(e) => data = "0".to_owned(),
    }
    return data;
}

