extern crate avrio_config;
extern crate num_cpus;
use std::collections::HashMap;
use std::sync::{
    mpsc::{Receiver, Sender},
    Mutex, MutexGuard,
};
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

//use rocksdb::{DBRawIterator, IteratorMode, Options, DB};
use serde::{Deserialize, Serialize};
use std::mem::size_of_val;
use std::net::SocketAddr;

// sled imports
use sled::{open, Db as SledDb, Iter};

use avrio_config::config;
// Complex types to satisfy most of clippy's nagging
type DatabaseLocks = HashMap<String, SledDb>;
type DatabaseLocksMutex = Mutex<DatabaseLocks>;

lazy_static! {
    static ref DATABASE_LOCKS: DatabaseLocksMutex = Mutex::new(HashMap::new());
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerlistSave {
    peers: Vec<String>,
}

pub fn cache_database(
    path: String,
    database_cache_lock: &mut DatabaseLocks,
) -> Result<bool, Box<dyn std::error::Error>> {
    // check this DB is not already cached

    return if database_cache_lock.contains_key(&path) {
        Ok(false) // this db is already cached
    } else {
        // open this DB and add to the cache
        let db_lock = sled::open(config().db_path + &path)?;
        // add to the db lock to the hashmap
        database_cache_lock.insert(path, db_lock);
        Ok(true)
    };
}

pub fn open_database(path: String) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let db: SledDb;
    //  gain a lock on the DATABASES lazy_sataic

    if let Ok(mut database_cache_lock) = DATABASE_LOCKS.lock() {
        if database_cache_lock.contains_key(&path) {
            //  we have this database cached, read from it
            trace!("Open database: Database cached (path={})", path);
            db = database_cache_lock.get(&path).unwrap().clone();
        } else {
            // we need to read from disc
            cache_database(path.clone(), &mut *database_cache_lock)?;
            db = database_cache_lock.get(&path).unwrap().clone();
        }
    } else {
        return Err("Failed to get a lock on DATABASE CACHE".into());
    }

    let mut return_database: HashMap<String, String> = HashMap::new();

    let export = db.export();
    for (_, _, collection_iter) in export {
        trace!(
            "OD: collection_iter={:?}",
            collection_iter.collect::<Vec<Vec<Vec<u8>>>>()
        );
        /*for mut kv in collection_iter {
            let v = kv.pop().expect("failed to get value from tree export");
            let k = kv.pop().expect("failed to get key from tree export");
            return_database
                .insert(String::from_utf8(k)?, String::from_utf8(v)?)
                .expect("failed to insert value during tree import");
        }*/
    }

    trace!("Read all {} values from db {}", return_database.len(), path);
    Ok(return_database)
}

pub fn init_cache(max_size: usize) -> Result<(), Box<dyn std::error::Error>> {
    // max_size is the max memory to use for caching, in bytes. Eg 1000000000 = 1gb (TODO, limmit mem used to this)
    // gain a lock on the DATABASES global varible to prevent people reading from it before we have assiged to it
    let mut db_lock = DATABASE_LOCKS.lock()?;
    trace!("Gained lock on lazy static");
    // TODO move this to config
    let to_cache_paths = /* (config().db_path + )*/ vec!["/chains/masterchainindex", "/chaindigest", "/peers"];
    log::info!(
        "Starting database cache, max size (bytes)={}, number_cachable_dbs={}",
        max_size,
        to_cache_paths.len()
    );
    let mut database_lock_hashmap: HashMap<String, SledDb> = HashMap::new();
    for raw_path in to_cache_paths {
        let final_path = config().db_path + raw_path;
        log::debug!("Caching db, path={}", final_path);
        // (re)open the db
        let db_new = open(final_path.clone())?;
        // now we add the on-disk DB lock to DATABASEFILES
        database_lock_hashmap.insert(final_path.clone(), db_new);
    }
    let percent_usage: f64 = ((size_of_val(&database_lock_hashmap)) / max_size) as f64;
    debug!(
        "Cached all DB's, total used mem={}, set_max={} ({}%)",
        size_of_val(&database_lock_hashmap),
        max_size,
        percent_usage
    );

    // now set the DATABASE_FILES lazy static
    trace!("Adding on-disk database locks to lazy_static");
    *db_lock = database_lock_hashmap;
    trace!("Added on-disk database locks to memory");

    Ok(())
}

pub fn save_data(serialized: &str, path: &str, key: String) -> u8 {
    trace!("SD: {} : {} -> {}", key, serialized, path);
    //  gain a lock on the DATABASES lazy_sataic
    return if let Ok(mut database_lock) = DATABASE_LOCKS.lock() {
        // it does; now check if the databases hashmap contains our path (eg is this db cached)
        if database_lock.contains_key(path) {
            //  we have this database cached, read from it
            // safe to get the value
            let db = database_lock[path].clone();
            // write to our local copy of the lazy_static
            if let Err(e) = db.insert(key.to_string().as_bytes(), serialized.to_owned().as_bytes())
            {
                error!("Failed to write to database, error={}", e);
                return 0;
            }

            trace!(
                "Set data (cached lock), path={}, key={}, serialized={}",
                path,
                key,
                serialized
            );
            1
        } else {
            match cache_database(path.to_string(), &mut *database_lock) {
                Ok(_) => {
                    //  we have this database cached, read from it
                    // safe to get the value
                    let db = database_lock[path].clone();
                    // write to our local copy of the lazy_static
                    if let Err(e) =
                        db.insert(key.to_string().as_bytes(), serialized.to_owned().as_bytes())
                    {
                        error!("Failed to write to database, error={}", e);
                        return 01;
                    }
                    trace!(
                        "Set data (new lock), path={}, key={}, serialized={}",
                        path,
                        key,
                        serialized
                    );
                    1
                }
                Err(e) => {
                    error!("Failed to cache database, error={}", e);
                    0
                }
            }
        }
    } else {
        error!("Failed to get a lock on DATABASE CACHE");
        0
    };
}

pub fn get_peerlist() -> std::result::Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let s = get_data(config().db_path + &"/peers".to_string(), &"white");

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
        &(config().db_path + &"/peers".to_string()),
        "white".to_string(),
    );

    Ok(())
}

pub fn get_data(path: String, key: &str) -> String {
    let data: String;
    //  gain a lock on the DATABASES lazy_sataic
    if let Ok(mut database_lock) = DATABASE_LOCKS.lock() {
        // it does; now check if the databases hashmap contains our path (eg is this db cached)
        if database_lock.contains_key(&path) {
            //  we have this database cached, read from it
            // safe to get the value
            let db = database_lock[&path].clone();
            // write to our local copy of the lazy_static
            match db.get(key.to_string().as_bytes()) {
                Ok(read_bytes) => match read_bytes {
                    Some(unwrapped_bytes) => {
                        trace!("Some bytes (len={})", unwrapped_bytes.len());
                        let bytes_vec = unwrapped_bytes.to_vec();
                        match String::from_utf8(bytes_vec) {
                            Ok(data_) => data = data_,
                            Err(e) => {
                                error!(
                                    "Failed to decode bytes, gave error={}",
                                    e
                                );
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
            }
            trace!(
                "Read from DB cache, path={}, key={}, data={}",
                path,
                key,
                data
            );
        } else {
            match cache_database(path.to_string(), &mut *database_lock) {
                Ok(_) => {
                    //  we have this database cached, read from it
                    // safe to get the value
                    let db = database_lock[&path].clone();
                    // read from our local copy of the lazy_static
                    match db.get(key.to_string().as_bytes()) {
                        Ok(read_bytes) => match read_bytes {
                            Some(unwrapped_bytes) => {
                                trace!("Some bytes (len={})", unwrapped_bytes.len());
                                let bytes_vec = unwrapped_bytes.to_vec();
                                match String::from_utf8(bytes_vec) {
                                    Ok(data_) => data = data_,
                                    Err(e) => {
                                        error!(
                                            "Failed to decode bytes, gave error={}",
                                             e
                                        );
                                        data = String::from("-3");
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
                    }
                    trace!(
                        "Read from new DB cache, path={}, key={}, data={}",
                        path,
                        key,
                        data
                    );
                }
                Err(e) => {
                    error!("Failed to cache database, error={}", e);
                    return "-1".into();
                }
            }
        }
    } else {
        error!("Failed to get a lock on DATABASE CACHE");
        return "-1".into();
    }
    data
}

