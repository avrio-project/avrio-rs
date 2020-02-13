use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
extern crate config;
extern crate core;

fn saveData(serialized: String, path: String, key: String) -> u8 {
    // used to save data without having to create 1000's of functions (eg saveblock, savepeerlist, ect)
    let db = DB::open_default(path).unwrap();
    db.put(key, serialized);
    return 1;
}

fn savePeerlist(list: &Vec<Vec<u8>>, path) {
    let peerlist_s: String;
    let ips: Vec<String>;
    let ip_curr: String;
    for ip in list {
        for ip_seg in ip {
            ip_curr = &ip_curr + "." + String::from(ip_seg);
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
        Ok(None) => data = "-1",
        Err(e) => data = "0",
    }
    return data.to_string();
}

fn setAccount(acc: Account) -> u8 {
    let path = config.path + "/db/accountdb";
    let serialized = serde_json::to_string(&acc).unwrap();
    saveData(serialized, path, acc.public_key);
    return 1;
}

fn getAccount(public_key: String) -> Account {
    let path = config.path + "/bd/accountdb";
    let mut data = getData(path, public_key);
    let db = DB::open_default(path).unwrap();
    if state != "1" {
        return nullAcc;
    } else {
        let acc = serde_json::from_str(&data).unwrap();
    }
    return acc;
}
