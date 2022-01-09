use std::sync::mpsc;

use avrio_core::{block::Block, chunk::BlockChunk};

use crate::{
    processor::ProcessorCommand,
    shard::{ShardMetadata, ShardTip},
    Actor, Command,
};

pub enum VerifierCommand {
    /// Verify the state digest
    VerifyStateDigest(String),
    /// Verify the shard list
    VerifyShardList(Vec<String>),
    /// Verify the shard metadata
    VerifyShardMetadata(ShardMetadata),
    /// Verify the shard tip
    VerifyShardTip(ShardTip),
    /// Verify the chunk
    VerifyChunk(BlockChunk),
    /// Verify the block
    VerifyBlock(Block),
    // Clear queue
    ClearQueue,
    // Shutdown
    Shutdown,
}

pub enum VerifierBackWash {
    Tasks(Vec<VerifierCommand>),
    Process(ProcessorCommand),
    None,
}

pub struct VerifierManager {
    pub rx: mpsc::Receiver<VerifierCommand>,
    pub tasks: Vec<VerifierCommand>,
    pub backwash_tx: mpsc::Sender<VerifierBackWash>,
}

impl Command for VerifierCommand {}
impl Command for VerifierBackWash {}

impl VerifierManager {
    pub fn worker() -> VerifierManagerMeta {
        let (tx, rx) = mpsc::channel();
        let (backwash_tx, backwash_rx) = mpsc::channel();
        let manager = VerifierManager {
            rx,
            tasks: vec![],
            backwash_tx,
        };
        let join_handle = std::thread::spawn(move || {
            // TODO
        });
        VerifierManagerMeta {
            tx,
            backwash_rx,
            join_handle,
        }
    }
}

pub struct VerifierManagerMeta {
    pub tx: mpsc::Sender<VerifierCommand>, // Used to send commands to the verifier
    pub backwash_rx: mpsc::Receiver<VerifierBackWash>, // Used to recieve "backwash" commands: commands sent from the verifier to the parent
    pub join_handle: std::thread::JoinHandle<()>,      // The thread handle
}

impl Actor<VerifierCommand, VerifierBackWash> for VerifierManagerMeta {
    fn send_task(&self, task: VerifierCommand) -> Result<(), mpsc::SendError<VerifierCommand>> {
        self.tx.send(task)
    }

    fn shutdown(self) -> Result<(), mpsc::SendError<VerifierCommand>> {
        self.send_task(VerifierCommand::Shutdown)
    }

    fn recieve_backwash(&self) -> Result<VerifierBackWash, mpsc::RecvError> {
        self.backwash_rx.recv()
    }

    fn get_tasks(&self) -> Result<Vec<VerifierCommand>, mpsc::RecvError> {
        let backwash = self.recieve_backwash()?;
        match backwash {
            VerifierBackWash::Tasks(tasks) => Ok(tasks),
            _ => Err(mpsc::RecvError),
        }
    }

    fn join(self) -> std::thread::Result<()> {
        self.join_handle.join()
    }
}
