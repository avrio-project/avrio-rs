#![feature(once_cell)]
extern crate avrio_config;
extern crate num_cpus;
use std::collections::HashMap;
use std::sync::{
    mpsc::{Receiver, Sender},
    Mutex, MutexGuard,
};

#[macro_use]
extern crate log;
use avrio_config::config;
use serde::{Deserialize, Serialize};
use sled::{open, Db as SledDb, Iter};
use std::lazy::SyncLazy;
use std::mem::size_of_val;
use std::net::SocketAddr;

// SledDb's operations are threadsafe and (mostly) non-blocking, this means we do not need a mutex! (yay)
static DATABASE_LOCK: SyncLazy<SledDb> =
    SyncLazy::new(|| open(config().db_path + "/database").unwrap());

#[derive(Debug, Serialize, Deserialize)]
struct PeerlistSave {
    peers: Vec<String>,
}

/// # Close DB
/// Closes the open mater DB, flushing all pending changes to disk
/// Returns Result((), Error)
pub fn close_db() -> Result<(), Box<dyn std::error::Error>> {
    trace!("Got lock on db lock cache, closing");
    let mut count = 0;
    let bytes_flushed = DATABASE_LOCK.flush()?;
    debug!("Closed Master DB, flushed {} bytes", bytes_flushed);

    return Ok(());
}

/// # Trees
/// Returns the list of trees that are a member of the master DB
/// Returns Result<Vec<String>, Error>
/// If the master DB is not open, an error will be returned
pub fn trees() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let open_trees = DATABASE_LOCK.tree_names();
    let mut trees: Vec<String> = vec![];
    for tree_ivec in open_trees {
        let tree_bytes = tree_ivec.to_vec();
        match String::from_utf8(tree_bytes) {
            Ok(tree_name) => trees.push(tree_name),
            Err(e) => error!("Failed to decode tree name from bytes, gave error={}", e),
        }
    }
    return Ok(trees);
}

/// # Open Tree
/// Opens a tree on the main db
/// Returns Result<Tree, std::error::Error>
pub fn open_tree(tree_name: String) -> Result<sled::Tree, Box<dyn std::error::Error>> {
    // open this DB and add to the cache
    if let Ok(tree) = DATABASE_LOCK.open_tree(tree_name.clone()) {
        debug!("Opened DB tree {}", tree_name);
        return Ok(tree);
    } else {
        error!("Failed to open db tree: {}", tree_name);
        return Err("Failed to open db tree".into());
    }
}
/// # Iter Database
/// Iterates over the key values of a given tree and constructs a hashmap of the key-values
/// Returns Result<Hashmap<String, String>, Error>
pub fn iter_database(
    tree_name: String,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let tree = open_tree(tree_name.clone())?;
    let mut return_database: HashMap<String, String> = HashMap::new();

    let iter = tree.iter();
    for item in iter {
        match item {
            Ok((key_bytes, value_bytes)) => {
                let key = String::from_utf8(key_bytes.to_vec())?;
                let value = String::from_utf8(value_bytes.to_vec())?;
                return_database.insert(key, value);
            }
            Err(e) => {
                error!("Error reading database: {}", e);
            }
        }
    }

    trace!(
        "Read all {} values from tree {}",
        return_database.len(),
        tree_name
    );
    Ok(return_database)
}

pub fn save_data(serialized: &str, tree_name: &str, key: String) -> u8 {
    trace!("SD: {} : {} -> {}", key, serialized, tree_name);
    match open_tree(tree_name.to_string()) {
        Ok(tree) => {
            //  we have this database cached, read from it
            // safe to get the value
            // write to our local copy of the lazy_static
            if let Err(e) =
                tree.insert(key.to_string().as_bytes(), serialized.to_owned().as_bytes())
            {
                error!("Failed to write to database, error={}", e);
                return 0;
            }
            trace!(
                "Set data (new lock), tree={}, key={}, serialized={}",
                tree_name,
                key,
                serialized
            );
            1
        }
        Err(e) => {
            error!(
                "Failed to open tree (tree_name={}) for writing, error={}",
                tree_name, e
            );
            0
        }
    }
}

pub fn get_peerlist() -> std::result::Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let s = get_data("peers".to_string(), &"white");

    if s == *"-1" {
        Err("peerlist not found".into())
    } else {
        let peerlist: PeerlistSave = serde_json::from_str(&s)?;
        let mut as_socket_addr: Vec<SocketAddr> = vec![];

        for peer in peerlist.peers {
            as_socket_addr.push(peer.parse()?);
        }

        Ok(as_socket_addr)
    }
}

pub fn add_peer(peer: SocketAddr) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut current_peer_list = get_peerlist().unwrap_or_default();
    current_peer_list.push(peer);

    let deduplicated_peerlist: std::collections::HashSet<_> = current_peer_list.drain(..).collect(); // deduplicate peer list
    current_peer_list.extend(deduplicated_peerlist.into_iter());

    save_peerlist(&current_peer_list)
}

pub fn save_peerlist(list: &[SocketAddr]) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut as_string: PeerlistSave = PeerlistSave { peers: vec![] };

    for peer in list {
        as_string.peers.push(peer.to_string());
    }

    let s = serde_json::to_string(&as_string)?;

    save_data(
        &s,
        "peers",
        "white".to_string(),
    );

    Ok(())
}

pub fn get_data(tree_name: String, key: &str) -> String {
    trace!("GD: {} from tree {}", key, tree_name);
    let data: String;
    match open_tree(tree_name.to_string()) {
        Ok(tree) => match tree.get(key.to_string().as_bytes()) {
            Ok(read_bytes) => match read_bytes {
                Some(unwrapped_bytes) => {
                    trace!("Some bytes (len={})", unwrapped_bytes.len());
                    let bytes_vec = unwrapped_bytes.to_vec();
                    match String::from_utf8(bytes_vec) {
                        Ok(data_) => data = data_,
                        Err(e) => {
                            error!("Failed to decode bytes, gave error={}", e);
                            data = String::from("-3")
                        }
                    }
                }
                None => {
                    trace!("No bytes");
                    data = String::from("-1");
                }
            },
            Err(e) => {
                error!("Error reading bytes, error={}", e);
                data = String::from("-2");
            }
        },
        Err(e) => {
            error!(
                "Failed to open tree (tree_name={}) for reading, error={}",
                tree_name, e
            );
            data = String::from("-4");
        }
    }
    data
}
