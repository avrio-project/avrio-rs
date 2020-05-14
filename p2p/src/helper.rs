use crate::{io::send, peer::get_peers};
use avrio_blockchain::Block;

use bson;
use log::*;
use std::error::Error;
use std::net::TcpStream;

pub fn get_peerlist_from_peer(
    _peer: &mut TcpStream,
) -> Result<Vec<std::net::SocketAddr>, Box<dyn Error>> {
    return Ok(vec![]);
}

pub fn sync() -> Result<(), Box<dyn Error>> {
    return Ok(());
}

pub fn sync_needed() -> Result<bool, Box<dyn Error>> {
    return Ok(true);
}

/// # Prop_block
/// Sends a block to all connected peers.
/// # Returns
/// a result enum conatining the error encountered or a u64 of the number of peers we sent to and got a block ack response from
/// Once proof of node is in place it will send it only to the relevant comitee.
pub fn prop_block(blk: &Block) -> Result<u64, Box<dyn std::error::Error>> {
    let mut i: u64 = 0;
    for peer in get_peers()?.iter_mut() {
        debug!("Sending block to peer: {:?}", peer);
        if let Ok(_) = send_block_struct(blk, peer) {
            i += 1;
        }
    }

    return Ok(i);
}

pub fn send_block_struct(block: &Block, peer: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    if block.hash == Block::default().hash {
        return Err("tried to send default block".into());
    } else {
        let block_ser: String = bson::to_bson(block)?.to_string();

        if let Err(e) = send(block_ser, peer, 0x0a, true, None) {
            return Err(e.into());
        } else {
            return Ok(());
        }
    }
}

pub fn send_block_with_hash(hash: String, peer: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    let block = avrio_blockchain::getBlockFromRaw(hash);
    if block.hash == Block::default().hash {
        return Err("block does not exist".into());
    } else {
        let block_ser: String = bson::to_bson(&block)?.to_string();

        if let Err(e) = send(block_ser, peer, 0x0a, true, None) {
            return Err(e.into());
        } else {
            return Ok(());
        }
    }
}
