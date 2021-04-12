use std::{net::SocketAddr, sync::Mutex};
extern crate avrio_blockchain;
use avrio_blockchain::{Block, BlockType};
use log::{error, info, trace};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::SystemTime;
extern crate avrio_config;
use avrio_config::config;
use std::borrow::Cow;
use std::fs::File;
use std::io::prelude::*;

/// The time a block can be in the mempool before being removed
const MEMPOOL_ENTRY_EXPIREY_TIME: u64 = (3 * 60) * 1000; // 3hr

/// Time (in ms) beetween mempool "purges" (Removing blocks that have been in the mempool for over MEMPOOL_ENTRY_EXPIREY_TIME ms) & enact now valid blocks
const PURGE_EVERY: u64 = 5000; // 5 secconds

#[derive(Debug, PartialEq, Clone)]
enum MempoolState {
    Initialized,
    Uninitialized,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Mempool {
    blocks: HashMap<String, (Block, SystemTime)>,
    #[serde(skip)]
    init: MempoolState,
    #[serde(skip)]
    purge_handle: Option<JoinHandle<()>>,
    #[serde(skip)]
    purge_stream: Option<mpsc::Sender<String>>,
}
pub struct Caller {
    pub callback: Box<dyn Fn(SocketAddr, Block) + Send>,
    pub rec_from: SocketAddr,
}

impl Caller {
    pub fn call(&self, blk: Block) {
        (self.callback)(self.rec_from, blk)
    }
}

lazy_static! {
    pub static ref MEMPOOL: Mutex<HashMap<String, (Block, SystemTime, Option<Caller>)>> =
        Mutex::new(HashMap::new());
}

impl Default for Mempool {
    fn default() -> Mempool {
        Mempool {
            blocks: HashMap::new(),
            init: MempoolState::Uninitialized,
            purge_handle: None,
            purge_stream: None,
        }
    }
}

impl Default for MempoolState {
    fn default() -> MempoolState {
        MempoolState::Uninitialized
    }
}

pub fn add_block(blk: &Block, callback: Caller) -> Result<(), Box<dyn std::error::Error>> {
    let mut map = MEMPOOL.lock()?;
    if map.contains_key(&blk.hash) {
        Err("block already in mempool".into())
    } else {
        if !map.contains_key(&blk.hash) {
            map.insert(
                blk.hash.clone(),
                (blk.clone(), SystemTime::now(), Some(callback)),
            );
        }
        Ok(())
    }
}

pub fn remove_block(hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut map = MEMPOOL.lock()?;
    if map.remove(hash).is_some() {
        Ok(())
    } else {
        Err("cant find block in mempool".into())
    }
}

pub fn get_block(hash: &str) -> Result<Block, Box<dyn std::error::Error>> {
    let map = MEMPOOL.lock()?;
    for (b, _, _) in map.values() {
        if b.hash == hash {
            return Ok(b.clone());
        }
    }
    Err("cant find block in mempool".into())
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
        mem
    }
    pub fn load(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut to_set: HashMap<String, (Block, SystemTime, Option<Caller>)> = HashMap::new();
        for (key, (block, time)) in self.blocks.clone().iter() {
            to_set.insert(key.clone(), (block.clone(), time.clone(), None));
        }
        *MEMPOOL.lock()? = to_set;
        Ok(())
    }
    pub fn save(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        for (key, (block, time, _)) in MEMPOOL.lock()?.iter() {
            self.blocks
                .insert(key.clone(), (block.clone(), time.clone()));
        }
        Ok(())
    }
    pub fn purge_worker(
        &mut self,
        rx: mpsc::Receiver<String>,
    ) -> Result<JoinHandle<()>, Box<dyn std::error::Error>> {
        let mut self_clone = Mempool {
            blocks: self.blocks.clone(),
            init: MempoolState::Initialized,
            purge_handle: None,
            purge_stream: None,
        };
        Ok(std::thread::spawn(move || {
            self_clone.load().unwrap();
            let mut start = SystemTime::now();
            loop {
                if let Ok(msg) = rx.try_recv() {
                    if msg == "shutdown" {
                        return;
                    }
                } else if SystemTime::now()
                    .duration_since(start)
                    .unwrap_or_default()
                    .as_millis() as u64
                    >= PURGE_EVERY
                {
                    start = SystemTime::now();
                    if let Err(e) = self_clone.purge() {
                        error!("Failed to purge mempool, gave error: {}", e);
                        return;
                    }
                } else {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }))
    }

    pub fn into_string() -> Result<String, Box<dyn std::error::Error>> {
        let mut mem: Mempool = Mempool::new(vec![]);
        mem.save()?;
        if let Ok(s) = serde_json::to_string(&mem) {
            Ok(s)
        } else {
            Err("failed to turn mempool into string".into())
        }
    }

    pub fn from_string(s: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mem: Mempool = serde_json::from_str(s)?;
        mem.load()?;
        Ok(())
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
        Ok(res)
    }

    pub fn add_block(
        &mut self,
        blk: &Block,
        caller: Caller,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.init != MempoolState::Initialized {
            return Err("mempool not initalised".into());
        }
        let mut map = MEMPOOL.lock()?;
        if map.contains_key(&blk.hash) {
            Err("block already in mempool".into())
        } else {
            map.insert(
                blk.hash.clone(),
                (blk.clone(), SystemTime::now(), Some(caller)),
            );
            if !self.blocks.contains_key(&blk.hash) {
                self.blocks
                    .insert(blk.hash.clone(), (blk.clone(), SystemTime::now()));
            }
            Ok(())
        }
    }

    pub fn remove_block(&mut self, hash: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.init != MempoolState::Initialized {
            return Err("mempool not initalised".into());
        }
        let mut map = MEMPOOL.lock()?;
        if map.remove(hash).is_some() {
            if self.blocks.remove(hash).is_some() {
                Ok(())
            } else {
                Err("cant find block in self".into())
            }
        } else {
            Err("cant find block in mempool".into())
        }
    }

    pub fn purge(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.init != MempoolState::Initialized {
            return Err("mempool not initalised".into());
        }
        let now = SystemTime::now();
        let mut map = MEMPOOL.lock()?;
        let mut to_remove: Vec<(String, String)> = vec![];
        let mut blocks_to_check: HashMap<String, ()> = HashMap::new(); // Contains the list of hashes of send blocks that now have at least one corrosponding recieve block
        for (k, v) in map.iter() {
            if v.0.block_type == BlockType::Recieve {
                if !blocks_to_check.contains_key(v.0.send_block.as_ref().unwrap()) {
                    // add this block and to the hashmap of send block hashes that can be enacted
                    blocks_to_check.insert(v.0.send_block.as_ref().unwrap().to_owned(), ());
                    blocks_to_check.insert(v.0.hash.to_owned(), ());
                }
            }
            if now.duration_since(v.1)?.as_millis() as u64 >= MEMPOOL_ENTRY_EXPIREY_TIME {
                to_remove.push((k.clone(), "timed out".to_owned()));
            }
        }
        for (k, _) in blocks_to_check.iter() {
            if map.contains_key(k) {
                let block = map[k].0.clone();
                let check_result = avrio_blockchain::check_block(block.clone());
                if check_result.is_ok() {
                    let e_res = avrio_blockchain::save_block(block.clone());
                    if e_res.is_ok() {
                        if let Err(enact_res) = avrio_blockchain::enact_block(block.clone()) {
                            error!(
                                "Failed to enact saved & valid block from mempool. Gave error: {}",
                                enact_res
                            );
                        }
                    } else {
                        error!(
                            "Failed to save validated block from mempool. Gave error: {}",
                            e_res.unwrap_err()
                        );
                    }
                    to_remove.push((k.clone(), "enacted".to_owned()));
                    if let Some(callback) = &map[k].2 {
                        callback.call(block);
                    }
                } else {
                    log::debug!(
                        "Block {} in block_to_check invalid, reason={:?}",
                        k,
                        check_result.unwrap_err()
                    );
                }
            }
        }
        let set: std::collections::HashSet<_> = to_remove.drain(..).collect(); // dedup
        to_remove.extend(set.into_iter());
        for (key, r) in to_remove {
            trace!("Removing block: {} from mempool. Reason: {}", key, r);
            map.remove(&key);
            self.blocks.remove(&key);
        }
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), Box<(dyn std::error::Error)>> {
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
        Ok(())
    }

    pub fn save_to_disk(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let s = serde_json::to_string(&self)?;
        let mut file = File::create(path)?;
        file.write_all(&s.as_bytes())?;
        drop(file);
        Ok(())
    }

    pub fn load_from_disk(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Ok(mut file) = File::open(path) {
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            Ok(serde_json::from_str(&contents)?)
        } else {
            Err("cant open mempool file".into())
        }
    }

    pub fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.init != MempoolState::Uninitialized {
            Err("Already initalised".into())
        } else {
            let (tx, rx) = std::sync::mpsc::channel();
            self.purge_stream = Some(tx);
            self.purge_handle = Some(self.purge_worker(rx)?);
            self.init = MempoolState::Initialized;
            Ok(())
        }
    }
}
