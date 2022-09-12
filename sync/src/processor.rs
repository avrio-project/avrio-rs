use avrio_core::{block::Block, chunk::BlockChunk, validate::Verifiable};
use log::*;
use std::{sync::mpsc, thread::JoinHandle};

use crate::{
    downloader::{Download, DownloadCommand, DownloadType},
    shard::{ShardMetadata, ShardTip},
    Actor, Command,
};

pub enum ProcessorCommand {
    Valid(ProcessorType),
    Invalid(ProcessorType),
    Shutdown,
}

pub enum ProcessingError {
    Save(Box<dyn std::error::Error + Send + Sync>),
    Enact(Box<dyn std::error::Error + Send + Sync>),
}

pub enum ProcessorBackwash {
    Tasks(Vec<ProcessorCommand>),
    Error((String, ProcessorType, ProcessingError)),
    Download(DownloadCommand),
    None,
}

impl Command for ProcessorCommand {}
impl Command for ProcessorBackwash {}

pub enum ProcessorType {
    PBlock(Block),
    PChunk(BlockChunk),
    PShardMetadata(ShardMetadata),
    PShardTip(ShardTip),
    PStateDigest(String),
    PShardList(Vec<String>),
}

pub struct ProcessorManagerMeta {
    pub tx: mpsc::Sender<ProcessorCommand>,
    pub backwash_rx: mpsc::Receiver<ProcessorBackwash>,
    pub join_handle: JoinHandle<()>,
}

pub struct ProcessorManager {
    pub rx: mpsc::Receiver<ProcessorCommand>,
    pub tasks: Vec<ProcessorCommand>,
    pub backwash_tx: mpsc::Sender<ProcessorBackwash>,
}

impl ProcessorManager {
    pub fn worker() -> ProcessorManagerMeta {
        let (tx, rx) = mpsc::channel();
        let (backwash_tx, backwash_rx) = mpsc::channel();
        let mut manager = ProcessorManager {
            rx,
            backwash_tx,
            tasks: vec![],
        };
        let join_handle = std::thread::spawn(move || {
            // get incoming commands
            manager
                .tasks
                .extend(manager.rx.try_iter().collect::<Vec<ProcessorCommand>>());
            let backwash_tx = manager.backwash_tx.clone();
            manager.tasks.retain(|task| match task {
                ProcessorCommand::Valid(Ctype) => {
                    match Ctype {
                        ProcessorType::PBlock(_block) => {
                            true
                            // TODO
                        }
                        ProcessorType::PChunk(chunk) => {
                            
                                trace!("Processing chunk {}", chunk.hash);
                                
                                if let Err(save_error) = chunk.save() {
                                    error!("Failed to save chunk {}, error={}", chunk.hash, save_error);
                                    backwash_tx.send(ProcessorBackwash::Error((chunk.hash.clone(), ProcessorType::PChunk(chunk.to_owned()), ProcessingError::Save(Err::<(), Box<dyn std::error::Error + Send + Sync>>(format!("{}",save_error).into()).unwrap_err() )))).unwrap();
                                    return false;
                                }
                                trace!("Saved chunk {} to disk, enacting chunk", chunk.hash);
                                let mut enact_try: u8 = 0;
                                const ENACT_RETRY_LIMMIT: u8 = 5;
                                const WAIT_BETWEEN_RETRY: u64 = 100;
                                loop {
                                    if let Err(enact_error) = chunk.enact() {
                                        error!(
                                            "Failed to enact saved chunk, error={}, try number={}/{}",
                                            enact_error, enact_try, ENACT_RETRY_LIMMIT
                                        );
                                        enact_try += 1;
                                        if enact_try >= ENACT_RETRY_LIMMIT {
                                            error!("tried {} times to enact chunk {}, aborting (reached ENACT_RETRY_LIMMIT)", ENACT_RETRY_LIMMIT, chunk.hash);
                                            backwash_tx.send(ProcessorBackwash::Error((chunk.hash.clone(), ProcessorType::PChunk(chunk.to_owned()), ProcessingError::Enact(Err::<(), Box<dyn std::error::Error + Send + Sync>>(format!("{}",enact_error).into()).unwrap_err() )))).unwrap();
                                            break;
                                        }
                                        std::thread::sleep(std::time::Duration::from_millis(WAIT_BETWEEN_RETRY));
                                    }
                                    trace!("Finished processing chunk {}", chunk.hash);
                                    let mut downloads_to_add = vec![];
                                    for block in &chunk.blocks {
                                        downloads_to_add.push(Download::new(
                                            block.clone(),
                                            DownloadType::Block,
                                            0,
                                        ));
                                    }
                                    backwash_tx.send(ProcessorBackwash::Download(DownloadCommand::AddMulti(downloads_to_add))).unwrap();
                                    break
                                }
                                return false;
                            
                        }
                        ProcessorType::PShardMetadata(_shard_metadata) => {
                            true
                        }
                        ProcessorType::PShardTip(_shard_tip) => {
                            true
                        }
                        ProcessorType::PStateDigest(_state_digest) => {
                            true
                        }
                        ProcessorType::PShardList(_shard_list) => {
                            true
                        }
                    }
                },
                ProcessorCommand::Invalid(_Ctype) => true,
                ProcessorCommand::Shutdown => false,
            });
        });
        ProcessorManagerMeta {
            tx,
            backwash_rx,
            join_handle,
        }
    }
}

impl Actor<ProcessorCommand, ProcessorBackwash> for ProcessorManagerMeta {
    fn send_task(&self, task: ProcessorCommand) -> Result<(), mpsc::SendError<ProcessorCommand>> {
        self.tx.send(task)
    }

    fn shutdown(self) -> Result<(), mpsc::SendError<ProcessorCommand>> {
        self.tx.send(ProcessorCommand::Shutdown)
    }

    fn recieve_backwash(&self) -> Result<ProcessorBackwash, mpsc::RecvError> {
        self.backwash_rx.recv()
    }

    fn get_tasks(&self) -> Result<Vec<ProcessorCommand>, mpsc::RecvError> {
        let backwash = self.recieve_backwash()?;
        match backwash {
            ProcessorBackwash::Tasks(tasks) => Ok(tasks),
            _ => Err(mpsc::RecvError),
        }
    }

    fn join(self) -> std::thread::Result<()> {
        self.join_handle.join()
    }
}
