use rocksdb::{DBRawIterator, DB};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
#[macro_use]
extern crate log;
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
/// Gets the saved peerlist
// TODO: getPeerList
pub fn getPeerList() -> std::result::Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    return Ok(vec![SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        12345,
    )]);
}
// TODO: Save the vec of SocketAddrs to peerlist db
pub fn savePeerlist(list: &Vec<SocketAddr>, path: String) {}

pub fn getData(path: String, key: &String) -> String {
    let db = DB::open_default(path).unwrap();
    let mut data: String;
    match db.get(key) {
        Ok(Some(value)) => data = String::from_utf8(value).unwrap_or("".to_owned()),
        Ok(None) => data = "-1".to_owned(),
        Err(_e) => data = "0".to_owned(),
    }
    return data;
}
