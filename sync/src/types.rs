use std::error::Error as StdErrorU;
trait StdError = StdErrorU + Send + Sync;

#[derive(Debug)]
pub enum SyncState {
    Idle,                            // Nothing happening
    Syncing(SyncTask, SyncProgress), // Syncing some data
    Error(SyncError),                // Some error happened, and we cannot continue
}
#[derive(Eq, PartialEq, Debug)]
pub enum SyncTask {
    WaitForPeers,               // Block until we have enough peers to sync
    Download(SyncDownloadTask), // Download some data from peers
    Process(SyncProcessTask),   // Process some downloaded data
    VerifySync,                 // Check we are synced
}

#[derive(Eq, PartialEq, Debug)]
pub enum SyncDownloadTask {
    StateDigest,
    ShardList,
    ShardMetadata, // Downloading metadata about the shard (eg top chunk, digest etc)
    ShardTip,      // Downloading the tip of a shard for fast startup
    Chunks,        // Downloading chunks for a shard
    Blocks,        // Downloading blocks for a downloaded chunk
}
#[derive(Eq, PartialEq, Debug)]
pub enum SyncProcessTask {
    StateDigest,
    ShardList,
    ShardMetadata, // processing metadata about the shard (eg top chunk, digest etc)
    ShardTip,      // processing the tip of a shard for fast startup
    Chunks,        // processing chunks for a shard
    Blocks,        // processing blocks for a downloaded chunk
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum SyncDataType {
    StateDigest,
    ShardList,
    ShardMetadata,
    ShardTip,
    Chunk,
    Block,
}
#[derive(Debug, Clone)]
pub enum SyncError {
    UnexpectedMessageType(u8, u8), // Unexpected message type (tuple 0: expected, 1: got)
    FailedToParseData(String, SyncDataType, std::sync::Arc<Box<dyn StdError>>), // Failed to parse recieved data (tuple 0: Data, 1: datra type (eg block), 2: the error recieved)
    NoCommonChain, // Unable to rectify chain with peer
    FailedToSave(String, SyncDataType, std::sync::Arc<Box<dyn StdError>>), // Failed to save data (tuple 0: identifer,1: the data type (eg block), 2: the error recieved)
    FailedToEnact(String, SyncDataType, std::sync::Arc<Box<dyn StdError>>), // Failed to enact data (tuple 0: identifer,1: the data type (eg block), 2: the error recieved)
    SyncAlreadyStarted,
    P2pReadError(String, SyncDataType, std::sync::Arc<Box<dyn StdError>>),
    P2pSendError(String, SyncDataType, std::sync::Arc<Box<dyn StdError>>),

}

impl PartialEq for SyncError {
    fn eq(&self, other: &Self) -> bool {
        use SyncError::*;
        match (self, other) {
            (SyncAlreadyStarted, SyncAlreadyStarted) => true,
            (NoCommonChain, NoCommonChain) => true,
            (FailedToEnact(a_m, a_t, _), FailedToEnact(b_m, b_t, _)) => {
                (a_m == b_m) && (a_t == b_t)
            }
            (FailedToSave(a_m, a_t, _), FailedToSave(b_m, b_t, _)) => (a_m == b_m) && (a_t == b_t),
            (FailedToParseData(a_m, a_t, _), FailedToParseData(b_m, b_t, _)) => {
                (a_m == b_m) && (a_t == b_t)
            }
            (P2pReadError(a_m, a_t, _), P2pReadError(b_m, b_t, _)) => {
                (a_m == b_m) && (a_t == b_t)
            }
            (P2pSendError(a_m, a_t, _), P2pSendError(b_m, b_t, _)) => {
                (a_m == b_m) && (a_t == b_t)
            }
            (UnexpectedMessageType(a_1, a_2), UnexpectedMessageType(b_1, b_2)) => {
                (a_1 == b_1) && (a_2 == b_2)
            }

            _ => false,
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum SyncProgress {
    Starting,             // Starting sync
    InProgress(u64, u64), // 0: current, 1: total
    Finished(u64),        // Finished sync, with the time taken to finish
}
