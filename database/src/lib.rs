
use rocksdb::{DBRawIterator, Error, Options, DB};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr};
use std::process;
#[macro_use]
extern crate log;
extern crate avrio_config;
use avrio_config::config;
extern crate num_cpus;

#[derive(Debug, Serialize, Deserialize)]
struct PeerlistSave {
    peers: Vec<String>,
}

pub fn openDb(path: String) -> Result<rocksdb::DB, Error> {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.set_skip_stats_update_on_db_open(false);
    opts.increase_parallelism(((1 / 2) * num_cpus::get()) as i32);
    return DB::open(&opts, path);
}
pub fn getIter<'a>(db: &'a rocksdb::DB) -> DBRawIterator<'a> {
    return db.raw_iterator();
}

pub fn saveData(serialized: String, path: String, key: String) -> u8 {
    // used to save data without having to create 1000's of functions (eg saveblock, savepeerlist, ect)
    let db = openDb(path).unwrap_or_else(|e| {
        error!("Failed to open database, gave error {:?}", e);
        process::exit(0);
    });
    if let Err(e) = db.put(key.clone(), serialized.clone()) {
        error!("Failed to save data to db, gave error: {}", e);
        return 0;
    } else {
        trace!(
            "set data to db: {}, key: {}, value, {}",
            db.path().display(),
            key,
            serialized
        );
        return 1;
    }
}

pub fn get_peerlist() -> std::result::Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let peers_db = openDb(config().db_path + &"/peers".to_string()).unwrap();
    let s = getDataDb(&peers_db, &"white");
    drop(peers_db);
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
    let mut current_peer_list = get_peerlist().unwrap_or_default();
    current_peer_list.push(peer);
    let set: std::collections::HashSet<_> = current_peer_list.drain(..).collect(); // dedup
    current_peer_list.extend(set.into_iter());
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

pub fn getData(path: String, key: &str) -> String {
    let db = openDb(path.clone()).unwrap_or_else(|e| {
        error!("Failed to open database, gave error {:?}", e);
        process::exit(0);
    });
    let data: String;
    match db.get(key) {
        Ok(Some(value)) => {
            data = String::from_utf8(value).unwrap_or("".to_owned());
            trace!("got data from db: {}, data: {}", path, data);
        }
        Ok(None) => {
            data = "-1".to_owned();
            trace!("got data from db: {}, data: None", path);
        }
        Err(e) => {
            data = "0".to_owned();
            error!("Error {} getting data from db", e);
        }
    }
    return data;
}

pub fn getDataDb(db: &DB, key: &str) -> String {
    let data: String;
    match db.get(key) {
        Ok(Some(value)) => {
            data = String::from_utf8(value).unwrap_or("".to_owned());
            trace!(
                "got data (db) from db: {}, data: {}",
                db.path().display(),
                data
            );
        }
        Ok(None) => {
            data = "-1".to_owned();
            trace!("got data (db) from db: {}, data: None", db.path().display());
        }
        Err(e) => {
            data = "0".to_owned();
            error!("Error {} getting data (db) from db", e);
        }
    }
    return data;
}

pub fn setDataDb(value: &String, db: &DB, key: &str) -> u8 {
    if let Err(e) = db.put(key, value) {
        error!(
            "Failed to save data (db) to db: {}, gave error: {}",
            db.path().display(),
            e
        );
        return 0;
    } else {
        trace!(
            "set data (db) to db: {}, key: {}, value, {}",
            db.path().display(),
            key,
            value
        );
        return 1;
    }
}
