use std::sync::Mutex;
extern crate avrio_blockchain;
use avrio_blockchain::Block;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::SystemTime;
extern crate avrio_config;
use avrio_config::config;
use std::fs::File;
use std::io::prelude::*;

/// The time a block can be in the mempool before being removed
const MEMPOOL_ENTRY_EXPIREY_TIME: u64 = (3 * 60) * 1000; // 3hr

/// Time (in ms) beetween mempool "purges" (Removing blocks that have been in the mempool for over MEMPOOL_ENTRY_EXPIREY_TIME ms)
const PURGE_EVERY: u64 = 6000000; // 10 mins

#[derive(Debug, PartialEq, Clone)]
enum MempoolState {
    Initialized,
    Uninitialized,
    ShuttingDown,
}

#[derive(Serialize, Deserialize, Debug)]
struct Mempool {
    blocks: HashMap<String, (Block, SystemTime)>,
    #[serde(skip)]
    init: MempoolState,
    #[serde(skip)]
    purge_handle: Option<JoinHandle<()>>,
    #[serde(skip)]
    purge_stream: Option<mpsc::Sender<String>>,
}

lazy_static! {
    pub static ref MEMPOOL: Mutex<HashMap<String, (Block, SystemTime)>> =
        Mutex::new(HashMap::new());
}

impl Default for Mempool {
    fn default() -> Mempool {
        return Mempool {
            blocks: HashMap::new(),
            init: MempoolState::Uninitialized,
            purge_handle: None,
            purge_stream: None,
        };
    }
}

impl Default for MempoolState {
    fn default() -> MempoolState {
        return MempoolState::Uninitialized;
    }
}

impl Mempool {
    pub fn new(blocks: Vec<Block>) -> Self {
        let mut mem: Mempool = Mempool {
            blocks: HashMap::new(),
            init: MempoolState::Uninitialized,
            purge_handle: None,
            purge_stream: None,
        };
        for block in blocks {
            mem.blocks
                .insert(block.hash.clone(), (block.clone(), SystemTime::now()));
        }
        return mem;
    }
    pub fn load(&self) -> Result<(), Box<dyn std::error::Error>> {
        *MEMPOOL.lock()? = self.blocks.clone();
        return Ok(());
    }
    pub fn save(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.blocks = MEMPOOL.lock()?.clone();
        return Ok(());
    }
    pub fn purge_worker(
        &mut self,
        rx: mpsc::Receiver<String>,
    ) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
        let self_clone = Mempool {
            blocks: self.blocks,
            init: MempoolState::Initialized,
            purge_handle: None,
            purge_stream: None,
        };
        return Ok(std::thread::spawn(move || {
            self_clone.load();
            let mut start = SystemTime::now();
            loop {
                if let Ok(msg) = rx.try_recv() {
                    if msg == "shutdown" {
                        return ();
                    }
                } else {
                    if SystemTime::now().duration_since(start).unwrap_or_default().as_millis() as u64 >= PURGE_EVERY {
                        start = SystemTime::now();
                        if let Err(e) = self_clone.purge() {
                            error!("Failed to purge mempool, gave error: {}", e);
                            return ();
                        }
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        }));
    }
    pub fn into_string() -> Result<String, Box<dyn std::error::Error>> {
        let mut mem: Mempool = Mempool::new(vec![]);
        mem.save()?;
        if let Ok(s) = serde_json::to_string(&mem) {
            return Ok(s);
        } else {
            return Err("failed to turn mempool into string".into());
        }
    }

    pub fn from_string(s: &String) -> Result<(), Box<dyn std::error::Error>> {
        let mem: Mempool = serde_json::from_str(s)?;
        mem.load()?;
        return Ok(());
    }
    pub fn get_mempool(&self) -> Result<Vec<Block>, Box<dyn std::error::Error>> {
        if self.init != MempoolState::Initialized {
            return Err("mempool not initalised".into());
        }
        let map = MEMPOOL.lock()?;
        let mut res: Vec<Block> = vec![];
        for val in map.values() {
            res.push(val.0.clone());
        }
        return Ok(res);
    }

    pub fn add_block(&mut self, blk: &Block) -> Result<(), Box<dyn std::error::Error>> {
        if self.init != MempoolState::Initialized {
            return Err("mempool not initalised".into());
        }
        let mut map = MEMPOOL.lock()?;
        if map.contains_key(&blk.hash) {
            return Err("block already in mempool".into());
        } else {
            map.insert(blk.hash.clone(), (blk.clone(), SystemTime::now()));
            if !self.blocks.contains_key(&blk.hash) {
                self.blocks
                    .insert(blk.hash.clone(), (blk.clone(), SystemTime::now()));
            }
            return Ok(());
        }
    }

    pub fn remove_block(&mut self, hash: &String) -> Result<(), Box<dyn std::error::Error>> {
        if self.init != MempoolState::Initialized {
            return Err("mempool not initalised".into());
        }
        let mut map = MEMPOOL.lock()?;
        if let Some(_) = map.remove(hash) {
            if let Some(_) = self.blocks.remove(hash) {
                return Ok(());
            } else {
                return Err("cant find block in self".into());
            }
        } else {
            return Err("cant find block in mempool".into());
        }
    }

    pub fn purge(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.init != MempoolState::Initialized {
            return Err("mempool not initalised".into());
        }
        let now = SystemTime::now();
        let mut map = MEMPOOL.lock()?;
        let mut to_remove: Vec<String> = vec![];
        for (k, v) in map.iter_mut() {
            if now.duration_since(v.1)?.as_millis() as u64 >= MEMPOOL_ENTRY_EXPIREY_TIME {
                to_remove.push(k.clone());
            }
        }
        for key in to_remove {
            map.remove(&key);
            self.blocks.remove(&key);
        }
        return Ok(());
    }

    pub fn shutdown(self) -> Result<(), Box<(dyn std::error::Error)>> {
        if self.init != MempoolState::Initialized {
            return Err("mempool not initalised".into());
        } else {
            info!("Shutting down mempool");
            *MEMPOOL.lock()? = HashMap::new();
            info!("Cleared mempool, sending shutdown to purge thread");
            if let Some(tx) = self.purge_stream.clone() {
                tx.send("shutdown".to_owned())?;
                info!("Shutdown purge stream");
                info!("Flushing mempool to disk");
                self.save_to_disk(&format!("{}/mempool", config().db_path))?;
                info!("Saved mempool to disk");
                info!("Unalloticating self");
                drop(self);
            } else {
                error!("No purge stream transmiter in mempool, aborting");
                return Err("no purge stream transmitter".into());
            }
        }
        return Ok(());
    }

    pub fn save_to_disk(&self, path: &String) -> Result<(), Box<dyn std::error::Error>> {
        let s = serde_json::to_string(&self)?;
        let mut file = File::create(path)?;
        file.write_all(&s.as_bytes())?;
        drop(file);
        return Ok(());
    }

    pub fn load_from_disk(&mut self, path: &String) -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(mut file) = File::open(path) {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            return Ok(serde_json::from_str(&contents)?);
        } else {
            return Err("cant open mempool file".into());
        }
    }
}
