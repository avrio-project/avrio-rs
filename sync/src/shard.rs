use avrio_core::{account::Account, chunk::BlockChunk};

pub struct ShardMetadata {
    pub shard_id: u64,
    pub shard_digest: String,
    pub shard_chunk_tip: String,
    pub shard_round: u64,
}

pub struct ShardTip {
    pub shard_id: u64,
    pub round: u64,
    pub tip_chunk: BlockChunk,
    pub accounts: Vec<Account>,
}
