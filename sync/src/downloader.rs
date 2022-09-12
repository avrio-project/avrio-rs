use crate::{
    types::{SyncDataType, SyncError, SyncProgress},
    Actor, Command,
};

use avrio_crypto::raw_hash;
use avrio_p2p::{
    format::P2pData,
    io::{read, send},
};
use std::{
    collections::HashMap,
    net::TcpStream,
    sync::{mpsc, Arc},
    thread::JoinHandle,
};
#[derive(Debug, Clone)]
pub enum DownloadType {
    Block,
    BlockChunk,
    Transaction,
    ShardMetadata,
    ShardTip,
    StateDigest,
    ShardList,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DownloadGoal {
    download_id: String,
    backwash: DownloadBackwash,
}

impl DownloadGoal {
    pub fn execute(&self, backash_tx: &mpsc::Sender<DownloadBackwash>) {
        let _ = backash_tx.send(self.backwash.clone());
    }
}

impl DownloadType {
    pub fn to_string(&self) -> String {
        match &self {
            DownloadType::Block => String::from("Block"),
            DownloadType::BlockChunk => String::from("BlockChunk"),
            DownloadType::Transaction => String::from("Transaction"),
            DownloadType::ShardMetadata => String::from("ShardMetadata"),
            DownloadType::ShardTip => String::from("ShardTip"),
            DownloadType::StateDigest => String::from("StateDigest"),
            DownloadType::ShardList => String::from("ShardList"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Download {
    resorce: String, // eg block hash
    resorce_type: DownloadType,
    priority: u8,
}

impl Download {
    pub fn id(&self) -> String {
        raw_hash(&format!(
            "{}{}",
            self.resorce,
            self.resorce_type.to_string()
        ))[0..16]
            .to_string()
    }
}

#[derive(Debug, Clone)]
pub enum DownloadCommand {
    Add(Download),
    AddMulti(Vec<Download>),
    Remove(Download),
    Get(String),
    GetAll,
    ReportProgress,
    Clear,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DownloadBackwash {
    Data(Option<(String, String)>),
    Progress(SyncProgress),
    Error(SyncError),
    None,
}

impl Command for DownloadCommand {}
impl Command for DownloadBackwash {}

pub struct DownloadManager {
    downloads: Vec<Download>,
    completed_downloads: Vec<Download>,
    cache: HashMap<String, String>,
    rx: mpsc::Receiver<DownloadCommand>,
    backwash_tx: mpsc::Sender<DownloadBackwash>,
    goals: Vec<DownloadGoal>,
    peer: TcpStream,
    backup_peers: Vec<TcpStream>,
}

pub struct DownloadManagerMeta {
    pub tx: mpsc::Sender<DownloadCommand>,
    pub backwash_rx: mpsc::Receiver<DownloadBackwash>,
    pub join_handle: JoinHandle<()>,
}

impl Download {
    pub fn new(resorce: String, resorce_type: DownloadType, priority: u8) -> Download {
        Download {
            resorce,
            resorce_type,
            priority,
        }
    }
}

impl DownloadManager {
    pub fn worker(peer: TcpStream, backup_peers: Vec<TcpStream>) -> DownloadManagerMeta {
        let (tx, rx) = mpsc::channel();
        let (backwash_tx, backwash_rx) = mpsc::channel();
        let mut manager = DownloadManager {
            rx,
            backwash_tx,
            downloads: vec![],
            goals: vec![],
            cache: HashMap::new(),
            completed_downloads: vec![],
            peer,
            backup_peers,
        };
        let join_handle = std::thread::spawn(move || {
            loop {
                // check for incoming commands
                let new_commands = manager.rx.try_iter().collect::<Vec<DownloadCommand>>();
                for command in new_commands {
                    log::trace!("Command {:?} received", command);
                    match command {
                        DownloadCommand::Add(download) => {
                            manager.downloads.push(download);
                        }

                        DownloadCommand::AddMulti(download) => {
                            manager.downloads.extend(download);
                        }
                        DownloadCommand::Remove(download) => {
                            manager.downloads.retain(|d| d.id() != download.id());
                        }
                        DownloadCommand::Get(id) => match manager.cache.get(&id) {
                            Some(data) => manager
                                .backwash_tx
                                .send(DownloadBackwash::Data(Some((id.clone(), data.clone()))))
                                .unwrap(),
                            None => manager
                                .backwash_tx
                                .send(DownloadBackwash::Data(None))
                                .unwrap(),
                        },
                        DownloadCommand::GetAll => {
                            for cache_data in &manager.cache {
                                manager
                                    .backwash_tx
                                    .send(DownloadBackwash::Data(Some((
                                        cache_data.0.clone(),
                                        cache_data.1.clone(),
                                    ))))
                                    .unwrap()
                            }
                            manager.cache.clear();
                        }
                        DownloadCommand::ReportProgress => {
                            manager
                                .backwash_tx
                                .send(DownloadBackwash::Progress(SyncProgress::InProgress(
                                    manager.downloads.len() as u64,
                                    manager.cache.keys().len() as u64,
                                )))
                                .unwrap();
                        }

                        DownloadCommand::Clear => {
                            manager.cache.clear();
                            manager.downloads.clear();
                        }
                        DownloadCommand::Shutdown => {
                            break;
                        }
                    }
                }
                if !manager.downloads.is_empty() {
                    // sort the downloads list via their priority
                    manager
                        .downloads
                        .sort_by(|a, b| a.priority.cmp(&b.priority));
                    let mut completed_downloads = manager.completed_downloads.clone();
                    let mut cache = manager.cache.clone();
                    let mut goals = manager.goals.clone();
                    let backwash_tx_clone = manager.backwash_tx.clone();
                    let mut peer = manager.peer.try_clone().unwrap();
                    manager.downloads.retain(|download| {
                        let downloaded: bool = match download.resorce_type {
                            DownloadType::Block => {
                                if cache.contains_key(&download.resorce) {
                                    completed_downloads.push(download.clone());
                                    return false;
                                } else {
                                    // send a peer a message asking for the block
                                    if let Err(p2p_error) = send(
                                        download.resorce.clone(),
                                        &mut peer,
                                        0x05,
                                        true,
                                        None,
                                    ) {
                                        log::error!(
                                            "Asking peer for block: {}, gave error: {}",
                                            download.resorce,
                                            p2p_error
                                        );
                                        let _ = send(
                                            "".to_string(),
                                            &mut peer,
                                            0x23,
                                            true,
                                            None,
                                        );
                                        backwash_tx_clone
                                            .send(DownloadBackwash::Error(SyncError::P2pSendError(
                                                download.resorce.clone(),
                                                SyncDataType::Block,
                                                Arc::new(
                                                    Err::<
                                                        (),
                                                        Box<dyn std::error::Error + Send + Sync>,
                                                    >(
                                                        format!("{}", p2p_error).into()
                                                    )
                                                    .unwrap_err(),
                                                ),
                                            )))
                                            .unwrap();
                                        true
                                    } else {
                                        let mut no_read: bool = true;
                                        let mut buf = [0; 2048];
                                        while no_read {
                                            if let Ok(a) = peer.peek(&mut buf) {
                                                if a == 0 {
                                                } else {
                                                    no_read = false;
                                                }
                                            }
                                        }

                                        // There are now bytes waiting in the stream
                                        let deformed: P2pData = read(&mut peer, Some(1000), None)
                                            .unwrap_or_else(|p2p_read_error| {
                                                log::error!(
                                                    "Failed to read p2pdata: {}",
                                                    p2p_read_error
                                                );
                                                backwash_tx_clone
                                                    .send(DownloadBackwash::Error(
                                                        SyncError::P2pReadError(
                                                            download.resorce.clone(),
                                                            SyncDataType::Block,
                                                            Arc::new(
                                                                Err::<
                                                                    (),
                                                                    Box<
                                                                        dyn std::error::Error
                                                                            + Send
                                                                            + Sync,
                                                                    >,
                                                                >(
                                                                    format!("{}", p2p_read_error)
                                                                        .into(),
                                                                )
                                                                .unwrap_err(),
                                                            ),
                                                        ),
                                                    ))
                                                    .unwrap();
                                                P2pData::default()
                                            });

                                        log::trace!("got block: {:#?}", deformed);

                                        if deformed.message_type == 0x04 {
                                            let block_encoded: String = deformed.message;

                                            // add this block to the cache
                                            cache.insert(
                                                download.resorce.clone(),
                                                block_encoded,
                                            );
                                            false
                                        } else {
                                            true
                                        }
                                    }
                                }
                            }
                            DownloadType::BlockChunk => {
                                if cache.contains_key(&download.resorce) {
                                    completed_downloads.push(download.clone());
                                    false
                                    // TODO: main function to download block chunks
                                } else {
                                    true
                                }
                            }
                            DownloadType::Transaction => {
                                if cache.contains_key(&download.resorce) {
                                    completed_downloads.push(download.clone());
                                    false
                                } else {
                                    // TODO: main function to download transaction
                                    true
                                }
                            }
                            DownloadType::ShardMetadata => {
                                if cache.contains_key(&download.resorce) {
                                    completed_downloads.push(download.clone());
                                    false
                                } else {
                                    // TODO: main function to download shardMetadata
                                    true
                                }
                            }
                            DownloadType::ShardTip => {
                                if cache.contains_key(&download.resorce) {
                                    completed_downloads.push(download.clone());
                                    false
                                } else {
                                    // TODO: main function to download shardMetadata
                                    true
                                }
                            }
                            DownloadType::StateDigest => {
                                if cache.contains_key(&download.resorce) {
                                    completed_downloads.push(download.clone());
                                    false
                                } else {
                                    // TODO: main function to download shardMetadata
                                    true
                                }
                            }
                            DownloadType::ShardList => {
                                if cache.contains_key(&download.resorce) {
                                    completed_downloads.push(download.clone());
                                    false
                                } else {
                                    // TODO: main function to download shardMetadata
                                    true
                                }
                            }
                        };
                        if downloaded {
                            goals.retain(|goal| {
                                if goal.download_id == download.id() {
                                    goal.execute(&backwash_tx_clone);
                                    return false;
                                }
                                true
                            });
                        }
                        downloaded
                    });
                    manager.completed_downloads = completed_downloads;
                    manager.cache = cache;
                } else {
                    // if there are no downloads, sleep for a second
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        });
        DownloadManagerMeta {
            join_handle,
            tx,
            backwash_rx,
        }
    }
}

impl Actor<DownloadCommand, DownloadBackwash> for DownloadManagerMeta {
    fn send_task(&self, task: DownloadCommand) -> Result<(), mpsc::SendError<DownloadCommand>> {
        self.tx.send(task)
    }

    fn shutdown(self) -> Result<(), mpsc::SendError<DownloadCommand>> {
        self.tx.send(DownloadCommand::Shutdown)
    }

    fn recieve_backwash(&self) -> Result<DownloadBackwash, mpsc::RecvError> {
        self.backwash_rx.recv()
    }

    fn get_tasks(&self) -> Result<Vec<DownloadCommand>, mpsc::RecvError> {
        unimplemented!()
    }

    fn join(self) -> std::thread::Result<()> {
        self.join_handle.join()
    }
}

impl DownloadManagerMeta {
    pub fn get_progress(&self) -> Result<SyncProgress, mpsc::RecvError> {
        self.send_task(DownloadCommand::ReportProgress).unwrap();
        let out;
        loop {
            let out_: Option<Result<SyncProgress, mpsc::RecvError>> = match self.backwash_rx.recv()
            {
                Ok(t) => match t {
                    DownloadBackwash::Progress(p) => Some(Ok(p)),
                    _ => {
                        self.process_backwash(t);
                        None
                    }
                },
                Err(_) => Some(Err(mpsc::RecvError)),
            };
            if let Some(out_) = out_ {
                out = out_;
                break;
            }
        }
        out
    }

    pub fn process_backwash(&self, backwash: DownloadBackwash) {
        match backwash {
            // TODO
            DownloadBackwash::Data(Some((_id, _data))) => {
                //self.cache.insert(id, data);
            }
            DownloadBackwash::Data(None) => {}
            DownloadBackwash::Progress(_progress) => {
                //self.tx.send(DownloadCommand::ReportProgress(progress))?;
            }
            DownloadBackwash::None => todo!(),
            DownloadBackwash::Error(_e) => todo!(),
        }
    }
}
