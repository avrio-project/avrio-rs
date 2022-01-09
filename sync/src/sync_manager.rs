use std::{sync::mpsc, thread::JoinHandle};

use crate::{
    downloader::{DownloadCommand, DownloadManager, DownloadManagerMeta, Download, DownloadType},
    processor::{ProcessorCommand, ProcessorManager, ProcessorManagerMeta},
    types::{SyncDownloadTask, SyncError, SyncProgress, SyncState, SyncTask},
    verifier::{VerifierCommand, VerifierManager, VerifierManagerMeta},
    Actor, Command,
};

pub struct SyncManager {
    /// The current sync state
    pub state: SyncState,
    /// The current sync task
    pub task: Option<SyncTask>,
    /// The current sync error
    pub error: Option<SyncError>,
    pub download_manager: DownloadManagerMeta,
    pub processor: ProcessorManagerMeta,
    pub verifier: VerifierManagerMeta,
    pub rx: mpsc::Receiver<SyncCommand>,
    pub backwash_tx: mpsc::Sender<SyncBackwash>,
}

pub enum SyncCommand {
    Start,
    GetProgress,
    Shutdown,
}

pub enum SyncBackwash {
    Progress(SyncProgress),
    Error(SyncError),
    None,
}

pub struct SyncManagerMeta {
    pub tx: mpsc::Sender<SyncCommand>,
    pub backwash_rx: mpsc::Receiver<SyncBackwash>,
    pub join_handle: JoinHandle<()>,
}

impl Command for SyncCommand {}
impl Command for SyncBackwash {}

impl Actor<SyncCommand, SyncBackwash> for SyncManagerMeta {
    fn send_task(&self, task: SyncCommand) -> Result<(), mpsc::SendError<SyncCommand>> {
        self.tx.send(task)
    }

    fn shutdown(self) -> Result<(), mpsc::SendError<SyncCommand>> {
        self.tx.send(SyncCommand::Shutdown)
    }

    fn recieve_backwash(&self) -> Result<SyncBackwash, mpsc::RecvError> {
        self.backwash_rx.recv()
    }

    fn get_tasks(&self) -> Result<Vec<SyncCommand>, mpsc::RecvError> {
        unimplemented!()
    }

    fn join(self) -> std::thread::Result<()> {
        self.join_handle.join()
    }
}

impl SyncManager {
    pub fn worker() -> SyncManagerMeta {
        let (tx, rx) = mpsc::channel();
        let (backwash_tx, backwash_rx) = mpsc::channel();
        let mut manager = SyncManager {
            state: SyncState::Idle,
            task: None,
            error: None,
            download_manager: DownloadManager::worker(),
            processor: ProcessorManager::worker(),
            verifier: VerifierManager::worker(),
            rx,
            backwash_tx,
        };
        let join_handle = std::thread::spawn(move || {
            let commands = manager.rx.iter().collect::<Vec<SyncCommand>>();
            for command in commands {
                match command {
                    SyncCommand::Start => {
                        manager.state = SyncState::Syncing(
                            SyncTask::Download(SyncDownloadTask::StateDigest),
                            SyncProgress::Starting,
                        );
                        manager.task = Some(SyncTask::Download(SyncDownloadTask::StateDigest));
                        manager
                            .download_manager
                            .send_task(DownloadCommand::Add(Download::new(
                                String::default(),
                                DownloadType::StateDigest,
                                0,
                            )))
                            .unwrap();
                    }
                    SyncCommand::GetProgress => {
                        let progress = manager.download_manager.get_progress().unwrap();
                        manager
                            .backwash_tx
                            .send(SyncBackwash::Progress(progress))
                            .unwrap();
                    }
                    SyncCommand::Shutdown => {
                        manager.download_manager.shutdown().unwrap();
                        manager.processor.shutdown().unwrap();
                        manager.verifier.shutdown().unwrap();
                        manager.backwash_tx.send(SyncBackwash::None).unwrap();
                        return;
                    }
                };
            }
        });
        SyncManagerMeta {
            tx,
            backwash_rx,
            join_handle,
        }
    }
}
