extern crate avrio_config;
extern crate num_cpus;
use std::collections::HashMap;
use std::sync::{
    mpsc::{Receiver, Sender}, Mutex,
};
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

use rocksdb::{DBRawIterator, Options, DB};
use serde::{Deserialize, Serialize};
use std::mem::size_of_val;
use std::net::SocketAddr;


use avrio_config::config;
// a lazy static muxtex (essentially a 'global' variable)
// The first hashmap is wrapped in Option (either None, or Some) for startup saftey
// It is indexed by hashes of paths of db. eg to get the db at path "~/leocornelius/some_db"
// You hash "~/leocornelius/some_db" and get the value from the hashmap
// This returns a tuple (HashMap, u16), the u16 acts a modified tag. If tha value is != 0 the database is marked as 'dirty'
// and a flush to disk operation is queued, the HashMap is the database itself, to get a value simply look up the corrosponding key in this hashmap
// NOTE: this is dev docs, for writing avrio_db functions, to get data from the databases please use the get_data and save_data wrappers
lazy_static! {
    static ref DATABASES: Mutex<Option<HashMap<String, (HashMap<String, (String, u16)>, u16)>>> =
        Mutex::new(None);
}
lazy_static! {
    static ref FLUSH_STREAM_HANDLER: Mutex<Option<std::sync::mpsc::Sender<String>>> =
        Mutex::new(None);
}
#[derive(Debug, Serialize, Deserialize)]
struct PeerlistSave {
    peers: Vec<String>,
}
pub fn close_flush_stream() {
    info!("Shutting down dirty page flusher stream");
    if let Some(sender) = FLUSH_STREAM_HANDLER.lock().unwrap().clone() {
        sender.send("stop".to_string());
    }
}

pub fn open_database(path: String) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    //  gain a lock on the DATABASES lazy_sataic
    if let Ok(database_lock) = DATABASES.lock() {
        // check if it contains a Some(x) value
        if let Some(databases) = database_lock.clone() {
            // it does; now check if the databases hashmap contains our path (eg is this db cached)
            if databases.contains_key(&path) {
                //  we have this database cached, read from it
                let mut return_databases: HashMap<String, String> = HashMap::new();
                for (key, (val, _)) in databases[&path].0.clone() {
                    return_databases.insert(key, val);
                }
                return Ok(return_databases);
            }
        }
    }
    // we need to read from disc
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.set_skip_stats_update_on_db_open(false);
    opts.increase_parallelism(((1 / 2) * num_cpus::get()) as i32);
    let mut return_databases: HashMap<String, String> = HashMap::new();
    let db = DB::open(&opts, path)?;
    let iter = db.raw_iterator();
    while iter.valid() {
        return_databases.insert(
            String::from_utf8(iter.key().unwrap_or_default().to_vec())?,
            String::from_utf8(iter.value().unwrap_or_default().to_vec())?,
        );
    }
    return Ok(return_databases);
}

pub fn get_iterator<'a>(db: &'a rocksdb::DB) -> DBRawIterator<'a> {
    return db.raw_iterator();
}
pub fn init_cache(
    max_size: usize,
) -> Result<(Sender<String>, std::thread::JoinHandle<()>), Box<dyn std::error::Error>> {
    // max_size is the max memory to use for caching, in bytes. Eg 1000000000 = 1gb (TODO, limmit mem used to this)
    // gain a lock on the DATABASES global varible to prevent people reading from it before we have assiged to it
    let mut db_lock = DATABASES.lock()?;
    trace!("Gained lock on lazy static");
    // TODO move this to config
    let to_cache_paths = /* (config().db_path + )*/ vec![""];
    log::info!(
        "Starting database cache, max size (bytes)={}, number_cachable_dbs={}",
        max_size,
        to_cache_paths.len()
    );
    let mut databases_hashmap: HashMap<String, (HashMap<String, (String, u16)>, u16)> =
        HashMap::new();
    for path in to_cache_paths {
        let final_path = config().db_path + path;
        log::debug!("Caching db, path={}", final_path,);
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_skip_stats_update_on_db_open(false);
        opts.increase_parallelism(((1 / 2) * num_cpus::get()) as i32);
        let db = DB::open(&opts, path)?;
        let db_iter = db.raw_iterator();
        let mut values_hashmap: HashMap<String, (String, u16)> = HashMap::new();
        while db_iter.valid() {
            if let Some(key_bytes) = db_iter.key() {
                if let Ok(key) = String::from_utf8(Vec::from(key_bytes)) {
                    let hashed_key = avrio_crypto::raw_lyra(&key);
                    // now get the value
                    if let Some(value_bytes) = db_iter.value() {
                        if let Ok(value) = String::from_utf8(Vec::from(value_bytes)) {
                            trace!("(DB={}) Got key={} for value={}", path, key, value);
                            // now put that into a hashmap
                            values_hashmap.insert(hashed_key, (value, 0));
                        }
                    }
                }
            }
        }
        // get size of values_hashmap HashMap
        let size_of_local = size_of_val(&values_hashmap);
        // we have gone through every key value pair and added it to values_hashmap, now add the values_hashmap HashMap to the databases_hashmap HashMap
        databases_hashmap.insert(final_path.to_owned(), (values_hashmap, 0));
        let size_of_total = size_of_val(&databases_hashmap);
        debug!(
            "Cached db with path={}, db_hashmap_size={} bytes, databases_hashmap_size={} bytes",
            final_path, size_of_local, size_of_total
        );
        if max_size != 0 {
            debug!(
                "Used {}% of allocated cache memory ({}/{} bytes)",
                max_size / size_of_total,
                size_of_local,
                size_of_total
            );
        }
    }
    debug!(
        "Cached all DB's, total used mem={}, set_max={} ({}%)",
        size_of_val(&databases_hashmap),
        max_size,
        size_of_val(&databases_hashmap) / max_size
    );
    // now we need to set the DATABASES global var to this
    trace!("Allocating to databases");
    *db_lock = Some(databases_hashmap);
    trace!("Set db global varible to the database_hashmap finished");
    // all done, launch the dirty data flush thread
    let (send, recv) = std::sync::mpsc::channel();
    let flush_handler = std::thread::spawn(move || {
        let _ = flush_dirty_to_disk(recv).expect("Flush dirty page function returned an error");
    });
    *FLUSH_STREAM_HANDLER.lock().unwrap() = Some(send.clone()); // set global var
    return Ok((send, flush_handler));
}

fn flush_dirty_to_disk(rec: Receiver<String>) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Starting dirty flush loop");
    loop {
        let mut to_break = false;
        if let Ok(mesg) = rec.try_recv() {
            if mesg == "stop" {
                to_break = true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(5000)); // check every 5 secconds for dirty entries
        let db_lock = DATABASES.lock()?; // get a lock
        if let Some(mut db_lock_val) = db_lock.clone() {
            for (path, db_tuple) in db_lock_val.clone() {
                let dirty = db_tuple.1 != 0;
                trace!(
                    /*target="dirty flush loop", */
                    "path={}, dirty={}",
                    path,
                    dirty
                );
                if dirty {
                    // TODO: save data to disk
                    // we need to read from disc
                    let mut opts = Options::default();
                    opts.create_if_missing(true);
                    opts.set_skip_stats_update_on_db_open(false);
                    opts.increase_parallelism(((1 / 2) * num_cpus::get()) as i32);
                    let db = DB::open(&opts, &path)?;
                    for (key, value) in db_tuple.0 {
                        if value.1 != 0 {
                            if let Err(e) = db.put(key.clone(), value.0.clone()) {
                                error!("Failed to save data to db, gave error: {}", e);
                            } else {
                                trace!(
                                    "flushed data to db: {}, key: {}, value, {}",
                                    db.path().display(),
                                    key,
                                    value.0
                                );
                                // set per-value dirty flag to 0 (clean)
                                //     let mut reset_bit_buffer = db_lock_val[&path].0.clone();
                                let mut reset_bit = db_lock_val.get_mut(&key).unwrap();
                                reset_bit.1 = 0;
                                *db_lock_val.get_mut(&path).unwrap() = reset_bit.clone();
                                *db_lock_val.get_mut(&path).unwrap() =
                                    (db_lock_val[&path].0.clone(), db_lock_val[&path].1);
                            }
                        }
                    }
                    // set per-database dirty flag to 0 (clean)
                    *db_lock_val.get_mut(&path).unwrap() = (db_lock_val[&path].0.clone(), 0);
                }
            }
        }
        if to_break {
            break;
        }
    }
    return Ok(());
}

pub fn save_data(serialized: &String, path: &String, key: String) -> u8 {
    //  gain a lock on the DATABASES lazy_sataic
    if let Ok(mut database_lock) = DATABASES.lock() {
        // check if it contains a Some(x) value
        if let Some(databases) = database_lock.clone() {
            // it does; now check if the databases hashmap contains our path (eg is this db cached)
            let hashed_path = avrio_crypto::raw_lyra(&path);
            if databases.contains_key(&hashed_path) {
                //  we have this database cached, read from it
                // safe to get the value
                let mut db = databases[&hashed_path].clone().0;
                // write to our local copy of the lazy_static
                db.insert(
                    avrio_crypto::raw_lyra(&key.to_string()),
                    (serialized.to_owned(), 1),
                );
                // now update the global lazy_static
                *database_lock = Some(databases);
                return 1;
            }
        }
    }
    // used to save data without having to create 1000's of functions (eg saveblock, savepeerlist, ect)
    // we need to read from disc
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.set_skip_stats_update_on_db_open(false);
    opts.increase_parallelism(((1 / 2) * num_cpus::get()) as i32);
    let db = DB::open(&opts, path).unwrap();
    /*    let db = open_database(path).unwrap_or_else(|e| {
        error!("Failed to open database, gave error {:?}", e);
        process::exit(0);
    });*/

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
    let peers_db = open_database(config().db_path + &"/peers".to_string()).unwrap();
    let s = get_data_from_database(&peers_db, &"white");

    drop(peers_db);

    if s == "-1".to_owned() {
        return Err("peerlist not found".into());
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

    let deduplicated_peerlist: std::collections::HashSet<_> = current_peer_list.drain(..).collect(); // dedup
    current_peer_list.extend(deduplicated_peerlist.into_iter());

    save_peerlist(&current_peer_list)
}

pub fn save_peerlist(
    _list: &Vec<SocketAddr>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut as_string: Vec<String> = vec![];

    for peer in _list {
        as_string.push(peer.to_string());
    }

    let s = serde_json::to_string(&as_string)?;

    save_data(
        &s,
        &(config().db_path + &"/peers".to_string()),
        "white".to_string(),
    );

    Ok(())
}

pub fn get_data(dbpath: String, key: &str) -> String {
    //  gain a lock on the DATABASES lazy_sataic
    if let Ok(database_lock) = DATABASES.lock() {
        // check if it contains a Some(x) value
        if let Some(databases) = database_lock.clone() {
            // it does; now check if the databases hashmap contains our path (eg is this db cached)
            if databases.contains_key(&dbpath) {
                //  we have this database cached, read from it
                // safe to get the value
                let db = databases[&dbpath].clone().0;
                // does the database cache have this value?
                let hashed_key = avrio_crypto::raw_lyra(&key.to_string());
                if db.contains_key(&hashed_key) {
                    //  we have this database cached, read from it
                    // safe to get the value
                    return db[&hashed_key].clone().0; // return the first element of the tuple (the string value)
                } // we dont have this key-value pair cached we continue with reading from disk to be sure we are not missing data that has not been cached
            }
        }
    }
    // er did not have:
    // 1) the database cached
    // or 2) the key cached
    // therfore we read from disk to be sure we dont have this value
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.set_skip_stats_update_on_db_open(false);
    opts.increase_parallelism(((1 / 2) * num_cpus::get()) as i32);
    let db = DB::open(&opts, &dbpath).unwrap();

    let data: String;

    match db.get(key) {
        Ok(Some(value)) => {
            data = String::from_utf8(value).unwrap_or("".to_owned());

            trace!("got data from db: {}, data: {}, key {}", dbpath, data, key);
        }

        Ok(None) => {
            data = "-1".to_owned();

            trace!("got data from db: {}, data: None, key: {}", dbpath, key);
        }

        Err(e) => {
            data = "0".to_owned();

            error!("Error {} getting data from db", e);
        }
    }

    data
}

pub fn get_data_from_database(db: &HashMap<String, String>, key: &str) -> String {
    let data: String;

    match db.contains_key(key) {
        true => {
            data = db[key].to_owned();

            trace!("got data (db) from db: hashmap, data: {}", data);
        }
        false => {
            data = "-1".to_owned();

            trace!("got data (db) from db: hashmap, data: None");
        }
    }

    return data;
}
