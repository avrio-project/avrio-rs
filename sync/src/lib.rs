#![feature(trait_alias)]
use std::sync::mpsc;

pub mod downloader;
pub mod processor;
mod shard;
pub mod sync_manager;
pub mod types;
pub(crate) mod verifier;

pub trait SyncListener {
    /// # On Sync State Change
    /// Called when the sync state changes.
    fn on_sync_state_changed(&self, sync_state: types::SyncState);
    /// # On Sync Error
    /// Called when an error occurs.
    fn on_sync_error(&self, error: types::SyncError);
    /// # On Sync Change
    /// Called when the sync task changes.
    fn on_sync_task_change(&self, task: types::SyncTask);
}

pub trait Command {}

/// # Actor
/// Any <Something>ManagerMeta should implement this trait.
/// This trait is used to send commands to the manager.
/// S: the type of the send command (e.g. DownloadCommand)
/// B: the type of the backwash command (e.g. DownloadBackwash)
pub trait Actor<S: Command, B: Command> {
    fn send_task(&self, task: S) -> Result<(), mpsc::SendError<S>>;

    fn shutdown(self) -> Result<(), mpsc::SendError<S>>;

    fn recieve_backwash(&self) -> Result<B, mpsc::RecvError>;

    fn get_tasks(&self) -> Result<Vec<S>, mpsc::RecvError>;

    fn join(self) -> std::thread::Result<()>;
}
