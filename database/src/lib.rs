use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
extern crate config;
extern crate core
use core::{TxStore, Account};
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

fn setAccount(acc: Account) -> u8 {
    let path = config().db_path + "/db/accountdb";
    let serialized: String;
    serialized = serde_json::to_string(&acc).unwrap_or_else(|e| {
        error!("Unable To Serilise Account, gave error {}, retrying", e);
        serialized = serde_json::to_string(&acc).unwrap_or_else(|et| { 
                fatal!("Retry Failed with error: {}" et);
                panic!();
        });
    });
    saveData(serialized, path, acc.public_key);
    return 1;
}

fn getAccount(public_key: String) -> Result<Account, u8> {
    let path = config().db_path + "/bd/accountdb".to_owned();
    let mut data = getData(path, public_key);
    if data != "1" {
        return Err(1);
    } else {
        let acc: Account;
        acc = serde_json::from_str(&data).unwrap_or_else(|e| { 
            error!("Failed to Parse Account {:?}, gave error {:?}, Retrying...", &data, e);
            serde_json::from_str(&data).unwrap_or_else(|et| { 
                fatal!("Retry failed with error {:?}", et);
                panic!();
            });
        });
    }
    return Ok(acc);
}
