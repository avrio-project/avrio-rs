extern crate avrio_config;
extern crate num_cpus;
use std::collections::HashMap;
use std::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

use rocksdb::{DBRawIterator, IteratorMode, Options, DB};
use serde::{Deserialize, Serialize};
use std::mem::size_of_val;
use std::net::SocketAddr;

use avrio_config::config;
static CACHE_VALUES: bool = false; // should we use a memtable to store database values in memory (NO, this is not yet working)
                                   // a lazy static muxtex (essentially a 'global' variable)
                                   // The first hashmap is wrapped in Option (either None, or Some) for startup saftey
                                   // It is indexed by hashes of paths of db. eg to get the db at path "~/leocornelius/some_db"
                                   // You hash "~/leocornelius/some_db" and get the value from the hashmap
                                   // This returns a tuple (HashMap, u16), the u16 acts a modified tag. If tha value is != 0 the database is marked as 'dirty'
                                   // and a flush to disk operation is queued, the HashMap is the database itself, to get a value simply look up the corrosponding key in this hashmap
                                   // NOTE: this is dev docs, for writing avrio_db functions, to get data from the databases please use the get_data and save_data wrappers

// Complex types to satisfy most of clippy's nagging
type Databases = Mutex<Option<HashMap<String, (HashMap<String, (String, u16)>, u16)>>>;
type FlushStreamHandler = Mutex<Option<std::sync::mpsc::Sender<String>>>;
type DatabaseFiles = Mutex<HashMap<String, rocksdb::DB>>;
type DatabaseHashmap = HashMap<String, (HashMap<String, (String, u16)>, u16)>;
type DatabaseLock<'a> =
    std::sync::MutexGuard<'a, Option<HashMap<String, (HashMap<String, (String, u16)>, u16)>>>;

lazy_static! {
    static ref DATABASES: Databases = Mutex::new(None);
    static ref FLUSH_STREAM_HANDLER: FlushStreamHandler = Mutex::new(None);
    static ref DATABASEFILES: DatabaseFiles = Mutex::new(HashMap::new());
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerlistSave {
    peers: Vec<String>,
}
pub fn close_flush_stream() {
    info!("Shutting down dirty page flusher stream");
    if let Some(sender) = FLUSH_STREAM_HANDLER.lock().unwrap().clone() {
        if let Err(e) = sender.send("stop".to_string()) {
            error!(
                "CRITICAL: failed to send stop message to dirty data flush stream. Got error={}",
                e
            );
        } else {
            info!("Safley shut down dirty data flush stream!");
        }
    } else {
        error!("Called close_flsuh_stream() but failed to get access to FLUSH_STRAM_HANDLER");
    }
}

pub fn open_database(path: String) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    //  gain a lock on the DATABASES lazy_sataic
    if CACHE_VALUES {
        if let Ok(database_lock) = DATABASES.lock() {
            // check if it contains a Some(x) value
            if let Some(databases) = database_lock.clone() {
                // it does; now check if the databases hashmap contains our path (eg is this db cached)
                if databases.contains_key(&path) {
                    //  we have this database cached, read from it
                    trace!("Open database: Database cached (path={})", path);
                    let mut return_databases: HashMap<String, String> = HashMap::new();
                    for (key, (val, _)) in databases[&path].0.clone() {
                        trace!("OD: key={}, val={}", key, val);
                        return_databases.insert(key, val);
                    }
                    return Ok(return_databases);
                }
            }
        }
    }
    // we need to write to disc
    let mut db_file_lock = DATABASEFILES.lock().unwrap();
    let db_deref: DB;
    let db: &DB;
    match db_file_lock.keys().len() {
        0 => {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.set_skip_stats_update_on_db_open(false);
            opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
            db_deref = DB::open(&opts, path).unwrap();
            db = &db_deref;
        }
        _ => {
            let db_hashmap = &mut *db_file_lock;
            if db_hashmap.contains_key(&path) {
                trace!("OD: db lock cached in hashmap");
                db = &db_hashmap[&path];
            } else {
                trace!("OD: db lock not cached in hashmap");
                let mut opts = Options::default();
                opts.create_if_missing(true);
                opts.set_skip_stats_update_on_db_open(false);
                opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
                db_deref = DB::open(&opts, &path).unwrap();
                db = &db_deref;
                let cloned_path = path.clone();
                trace!("Open database, reloading cache");
                let _ = reload_cache(vec![cloned_path], &mut db_file_lock, &mut DATABASES.lock()?);
                trace!("Finished reloading cache, continuing");
            }
        }
    };
    let mut return_databases: HashMap<String, String> = HashMap::new();
    let iter = db.iterator(IteratorMode::Start); // Always iterates forward
    for (key, value) in iter {
        trace!(
            "OD: saw {}, {}",
            String::from_utf8(key.to_vec())?,
            String::from_utf8(value.to_vec())?,
        );
        return_databases.insert(
            String::from_utf8(key.to_vec())?,
            String::from_utf8(value.to_vec())?,
        );
    }
    Ok(return_databases)
}

pub fn get_iterator(db: &rocksdb::DB) -> DBRawIterator {
    db.raw_iterator()
}

fn reload_cache(
    db_paths: Vec<String>,
    db_file_lock: &mut std::sync::MutexGuard<HashMap<String, rocksdb::DB>>,
    db_lock: &mut DatabaseLock,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!("Reloading cache for DBs: {:?}", db_paths);
    let mut new_db_hashmap: HashMap<String, rocksdb::DB> = HashMap::new();
    let mut additions = 0;
    let mut unchanged = 0;
    let mut databases_hashmap: DatabaseHashmap = HashMap::new();
    for path in db_paths {
        // iterate over all the new paths to add
        trace!("Recaching {}", path);
        let db: DB;
        match db_file_lock.keys().len() {
            0 => {
                // the existing hashmap is empty, open the db from disk
                let mut opts = Options::default();
                opts.create_if_missing(true);
                opts.set_skip_stats_update_on_db_open(false);
                opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
                db = DB::open(&opts, &path)?;
                additions += 1;
            }
            _ => {
                // db file locks hashmap is not empty
                let db_hashmap = &mut *db_file_lock;
                if db_hashmap.contains_key(&path) {
                    // the db files lock hashmap contains the database we are looking for, call remove on it to gain ownership of it
                    db = db_hashmap.remove(&path).unwrap();
                    unchanged += 1;
                } else {
                    // open the db file, we dont have it already
                    let mut opts = Options::default();
                    opts.create_if_missing(true);
                    opts.set_skip_stats_update_on_db_open(false);
                    opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
                    db = DB::open(&opts, &path)?;
                    additions += 1;
                }
            }
        };
        if CACHE_VALUES {
            // now we use the opened db to load all values into values_hashmap
            let mut values_hashmap: HashMap<String, (String, u16)> = HashMap::new();

            {
                let db_iter = db.raw_iterator();
                while db_iter.valid() {
                    if let Some(key_bytes) = db_iter.key() {
                        if let Ok(key) = String::from_utf8(Vec::from(key_bytes)) {
                            // now get the value
                            if let Some(value_bytes) = db_iter.value() {
                                if let Ok(value) = String::from_utf8(Vec::from(value_bytes)) {
                                    trace!("(DB={}) Got key={} for value={}", path, key, value);
                                    // now put that into a hashmap
                                    values_hashmap.insert(key, (value, 0));
                                }
                            }
                        }
                    }
                }
            }
            // we now add values_hashmap to databases_hashmap

            databases_hashmap.insert(path.to_owned(), (values_hashmap, 0));
        }
        // now add the db object into the db locks hashmap
        new_db_hashmap.insert(path, db); //  add DB lock file to new_db_hashmap
    }
    // now we iterate over all the keys left over in the DATABASES lazy static, in other owrds we move the existing DBs into the new hashmap
    let mut keys: Vec<String> = vec![];
    {
        // open a closure to drop the immutable borrow of db_file_lock created by the keys() function
        // now we iterate over all the other open DBs
        let local_keys = db_file_lock.keys().clone();
        for key in local_keys {
            // iterate over the vec of keys
            keys.push(key.to_string());
        }
    }
    for key in keys {
        if db_file_lock.contains_key(&key) {
            // thi should always be true, it checks if the key is contained in the db locks hashmap. If this ever returns false; its a bug
            trace!("Moving DB lock file (key={}) to new hashmap", key);
            let moved_db = db_file_lock.remove(&key).unwrap(); // get the DB object by key
            unchanged += 1; // for logging purposes
            new_db_hashmap.insert(key, moved_db); // insert it into the new ahshmap
        } else {
            error!(
                "Unexpected error. Key listed in hm.keys() is not contained, key={}. THIS IS A BUG, please open a bug report at github",
                key
            );
        }
    }
    let new_size = std::mem::size_of_val(&new_db_hashmap); // get the current size of the db_locks hashmap
                                                           // now we need to set the lazy_static to new_hashmap
    *(*db_file_lock) = new_db_hashmap;
    debug!(
        "Updated db_file_lock to new db hashmap, additions_count={}, unchanged_count={}, new_lock_cache_size={}",
        additions, unchanged, new_size
    );
    if CACHE_VALUES {
        trace!(
            "Cached new valuess into global hashmap, new_values_cache_size={}",
            std::mem::size_of_val(&databases_hashmap)
        );
        *(*db_lock) = Some(databases_hashmap);
        trace!("Set db global varible to the database_hashmap");
    }
    Ok(())
}
pub fn init_cache(
    max_size: usize,
) -> Result<(Sender<String>, std::thread::JoinHandle<()>), Box<dyn std::error::Error>> {
    // max_size is the max memory to use for caching, in bytes. Eg 1000000000 = 1gb (TODO, limmit mem used to this)
    // gain a lock on the DATABASES global varible to prevent people reading from it before we have assiged to it
    let mut db_lock = DATABASES.lock()?;
    trace!("Gained lock on lazy static");
    // TODO move this to config
    let to_cache_paths = /* (config().db_path + )*/ vec!["/chains/masterchainindex", "/chaindigest", "/peers"];
    log::info!(
        "Starting database cache, max size (bytes)={}, number_cachable_dbs={}",
        max_size,
        to_cache_paths.len()
    );
    let mut databases_hashmap: DatabaseHashmap = HashMap::new();
    let mut database_lock_hashmap: HashMap<String, rocksdb::DB> = HashMap::new();
    for raw_path in to_cache_paths {
        let final_path = config().db_path + raw_path;
        log::debug!("Caching db, path={}", final_path);
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_skip_stats_update_on_db_open(false);
        opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
        let mut values_hashmap: HashMap<String, (String, u16)> = HashMap::new();
        if CACHE_VALUES {
            let db = DB::open(&opts, final_path.to_owned())?;
            let db_iter = db.raw_iterator();
            while db_iter.valid() {
                if let Some(key_bytes) = db_iter.key() {
                    if let Ok(key) = String::from_utf8(Vec::from(key_bytes)) {
                        // now get the value
                        if let Some(value_bytes) = db_iter.value() {
                            if let Ok(value) = String::from_utf8(Vec::from(value_bytes)) {
                                trace!("(DB={}) Got key={} for value={}", final_path, key, value);
                                // now put that into a hashmap
                                values_hashmap.insert(key, (value, 0));
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
                    size_of_total / max_size,
                    size_of_local,
                    size_of_total
                );
            }
        }
        // (re)open the db
        let db_new = DB::open(&opts, final_path.to_owned())?;
        // now we add the on-disk DB lock to DATABASEFILES
        database_lock_hashmap.insert(final_path.to_string(), db_new);
    }
    let percent_usage: f64 =
        ((size_of_val(&databases_hashmap) + size_of_val(&database_lock_hashmap)) / max_size) as f64;
    debug!(
        "Cached all DB's, total used mem={}, set_max={} ({}%)",
        size_of_val(&databases_hashmap) + size_of_val(&database_lock_hashmap),
        max_size,
        percent_usage
    );
    // now we need to set the DATABASES global var to this
    trace!("Allocating to databases");
    *db_lock = Some(databases_hashmap);
    trace!("Set db global varible to the database_hashmap");
    // now set the DATABASE_FILES lazy static
    trace!("Adding on-disk database locks to lazy_static");
    let mut db_file_lock = DATABASEFILES.lock()?;
    *db_file_lock = database_lock_hashmap;
    trace!("Added on-disk database locks to memory");

    // all done, launch the dirty data flush thread
    let (send, recv) = std::sync::mpsc::channel();
    let flush_handler = std::thread::spawn(move || {
        if CACHE_VALUES {
            debug!(
                "Rrunning flush_dirty_data_to_disk, CACHE_VALUES={}",
                CACHE_VALUES
            );
            let _ = flush_dirty_to_disk(recv).expect("Flush dirty page function returned an error");
        } else {
            debug!(
                "Not running flush_dirty_data_to_disk, CACHE_VALUES={}",
                CACHE_VALUES
            );
        }
    });
    *FLUSH_STREAM_HANDLER.lock().unwrap() = Some(send.clone()); // set global var
    Ok((send, flush_handler))
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
        {
            let mut db_lock = DATABASES.lock()?; // get a lock
            if let Some(mut db_lock_val) = db_lock.clone() {
                for (path, db_tuple) in db_lock_val.clone() {
                    if db_tuple.1 != 0 {
                        trace!(
                            /*target="dirty flush loop", */
                            "path={}, dirty=true",
                            path,
                        );
                        // we need to write to disc
                        let mut db_file_lock = DATABASEFILES.lock()?;
                        let db_deref: DB;
                        let db: &DB;
                        match db_file_lock.keys().len() {
                            0 => {
                                let mut opts = Options::default();
                                opts.create_if_missing(true);
                                opts.set_skip_stats_update_on_db_open(false);
                                opts.increase_parallelism(
                                    ((1.0 / 3.0) * num_cpus::get() as f64) as i32,
                                );
                                db_deref = DB::open(&opts, &path)?;
                                db = &db_deref;
                            }
                            _ => {
                                let db_hashmap = &mut *db_file_lock;
                                if db_hashmap.contains_key(&path) {
                                    db = &db_hashmap[&path];
                                } else {
                                    let mut opts = Options::default();
                                    opts.create_if_missing(true);
                                    opts.set_skip_stats_update_on_db_open(false);
                                    opts.increase_parallelism(
                                        ((1.0 / 3.0) * num_cpus::get() as f64) as i32,
                                    );
                                    db_deref = DB::open(&opts, &path)?;
                                    db = &db_deref;
                                    let cloned_path = path.clone();
                                    trace!("Dirty dataflush stream, reloading cache");
                                    let _ = reload_cache(
                                        vec![cloned_path],
                                        &mut db_file_lock,
                                        &mut db_lock,
                                    );
                                    trace!("Finished reloading cache, continuing");
                                }
                            }
                        };
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
                    } else {
                        trace!(
                            /*target="dirty flush loop", */
                            "path={}, dirty=false",
                            path,
                        );
                    }
                }
            }
            if to_break {
                break;
            }
        }
    }
    Ok(())
}

pub fn save_data(serialized: &str, path: &str, key: String) -> u8 {
    if CACHE_VALUES {
        //  gain a lock on the DATABASES lazy_sataic
        if let Ok(mut database_lock) = DATABASES.lock() {
            // check if it contains a Some(x) value
            if let Some(databases) = database_lock.clone() {
                // it does; now check if the databases hashmap contains our path (eg is this db cached)
                if databases.contains_key(path) {
                    //  we have this database cached, read from it
                    // safe to get the value
                    let mut db = databases[path].clone().0;
                    // write to our local copy of the lazy_static
                    db.insert(key.to_string(), (serialized.to_owned(), 1));
                    trace!(
                        "Updated DB cache, path={}, key={}, serialized={}",
                        path,
                        key,
                        serialized
                    );
                    // now update the global lazy_static
                    *database_lock = Some(databases);
                    return 1;
                }
            }
        }
    }
    // used to save data without having to create 1000's of functions (eg saveblock, savepeerlist, ect)
    // we need to write to disc
    let mut db_file_lock = DATABASEFILES.lock().unwrap();
    let db_deref: DB;
    let db: &DB;
    match db_file_lock.keys().len() {
        0 => {
            debug!("db_file_lock contains no keys");
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.set_skip_stats_update_on_db_open(false);
            opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
            db_deref = DB::open(&opts, path).unwrap();
            db = &db_deref;
        }
        _ => {
            trace!("db_file_lock contains keys");
            let db_hashmap = &mut *db_file_lock;
            if db_hashmap.contains_key(path) {
                db = &db_hashmap[path];
            } else {
                let mut opts = Options::default();
                opts.create_if_missing(true);
                opts.set_skip_stats_update_on_db_open(false);
                opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
                db_deref = DB::open(&opts, &path).unwrap();
                db = &db_deref;
                let cloned_path = path.to_string();
                let try_lock = DATABASES.lock();
                if let Ok(mut db_lock) = try_lock {
                    trace!("Save data, reloading cache");
                    let _ = reload_cache(vec![cloned_path], &mut db_file_lock, &mut db_lock);
                    trace!("Finished reloading cache, continuing");
                } else {
                    error!("Save data, failed to gain lock on DATABASES mutex; skipping recache, error={}", try_lock.unwrap_err());
                }
            }
        }
    };

    if let Err(e) = db.put(key.clone(), serialized.to_string()) {
        error!("Failed to save data to db, gave error: {}", e);

        0
    } else {
        trace!(
            "set data to db: {}, key: {}, value, {}",
            db.path().display(),
            key,
            serialized
        );

        1
    }
}

pub fn get_peerlist() -> std::result::Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let peers_db = open_database(config().db_path + &"/peers".to_string()).unwrap();
    let s = get_data_from_database(&peers_db, &"white");

    drop(peers_db);

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
    let mut as_string: Vec<String> = vec![];

    for peer in list {
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
    if CACHE_VALUES {
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
                    if db.contains_key(key) {
                        //  we have this database cached, read from it
                        // safe to get the value
                        let val = db[key].clone().0;
                        trace!(
                            "Got data from DB cache, path={}, key={}, value={}",
                            dbpath,
                            key,
                            val
                        );
                        return val;
                        // return the first element of the tuple (the string value)
                    } // we dont have this key-value pair cached we continue with reading from disk to be sure we are not missing data that has not been cached
                }
            }
        }
    }
    // either did not have:
    // 1) the database cached
    // or 2) the key cached
    // therefore we read from disk to be sure we dont have this value there instead
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.set_skip_stats_update_on_db_open(false);
    opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
    let data: String;
    // we need to write to disc
    let mut db_file_lock = DATABASEFILES.lock().unwrap();
    let db_deref: DB;
    let db: &DB;
    match db_file_lock.keys().len() {
        0 => {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.set_skip_stats_update_on_db_open(false);
            opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
            db_deref = DB::open(&opts, &dbpath).unwrap();
            db = &db_deref;
        }
        _ => {
            let db_hashmap = &mut *db_file_lock;
            if db_hashmap.contains_key(&dbpath) {
                db = &db_hashmap[&dbpath];
            } else {
                let mut opts = Options::default();
                opts.create_if_missing(true);
                opts.set_skip_stats_update_on_db_open(false);
                opts.increase_parallelism(((1.0 / 3.0) * num_cpus::get() as f64) as i32);
                db_deref = DB::open(&opts, &dbpath).unwrap();
                db = &db_deref;
                let cloned_path = dbpath.clone();
                let try_lock = DATABASES.lock();
                if let Ok(mut db_lock) = try_lock {
                    trace!("Get data, reloading cache");
                    let _ = reload_cache(vec![cloned_path], &mut db_file_lock, &mut db_lock);
                    trace!("Finished reloading cache, continuing");
                } else {
                    error!("Get data, failed to gain lock on DATABASES mutex; skipping recache, error={}", try_lock.unwrap_err());
                }
            }
        }
    };
    match db.get(key) {
        Ok(Some(value)) => {
            data = String::from_utf8(value).unwrap_or_else(|_| "".to_owned());

            trace!("got data from db={}, data={}, key={}", dbpath, data, key);
        }

        Ok(None) => {
            data = "-1".to_owned();

            trace!("got data from db={}, data=None, key={}", dbpath, key);
        }

        Err(e) => {
            data = "0".to_owned();
            error!("Error {} getting data from db", e);
        }
    }
    data
}

pub fn get_data_from_database(db: &HashMap<String, String>, key: &str) -> String {
    // TODO: legacy function, move evrything to stop using it
    let data: String;

    match db.contains_key(key) {
        true => {
            data = db[key].to_owned();

            trace!("got data from db hashmap, data: {}, key={}", data, key);
        }
        false => {
            data = "-1".to_owned();

            trace!("got data from db hashmap, data: None, key={}", key);
        }
    }

    data
}
