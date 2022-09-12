/*
    Copyright The Avrio Core Developers 2020

    api/src/v1.rs

    This file handles the JSON API version 1 of the Daemon.
*/

use avrio_core::{
    account::get_account,
    block::{get_block, get_block_from_raw, save_block, Block},
    validate::Verifiable,
};
use avrio_crypto::public_key_to_address;
use avrio_database::{get_data, iter_database};
use avrio_p2p::helper::prop_block;
use avrio_rpc::block_announce;
use log::*;
use rocket::{routes, Route};
use std::io::prelude::*;
extern crate avrio_p2p;

fn not_supported() -> String {
    "{ \"error\": \"NOT_SUPPORTED\"}".to_owned()
}

#[get("/")]
fn must_provide_method() -> &'static str {
    "{ \"success\": false, \"error\": \"METHOD_MISSING\" }"
}
#[get("/blockcount/<chain>")]
pub fn get_blockcount_v1(chain: String) -> String {
    let our_height_string = get_data(
        "chains/".to_owned() + &chain + &"-chainindex".to_owned(),
        &"blockcount".to_owned(),
    );
    if our_height_string == "-1" {
        return "{ \"success\": true, ".to_owned() + "\"blockcount\": " + &0.to_string() + " }";
    } else {
        let try_parse = our_height_string.parse::<u64>();
        if let Ok(our_height) = try_parse {
            return "{ \"success\": true, ".to_owned()
                + "\"blockcount\": "
                + &our_height.to_string()
                + " }";
        } else {
            return "{ \"success\": false, ".to_owned()
                + "\"error\": "
                + &try_parse.unwrap_err().to_string()
                + " }";
        }
    }
}

#[get("/transactioncount/<chain>")]
pub fn transaction_count(chain: String) -> String {
    let txn_count_string = get_data(
        "chains/".to_owned() + &chain + &"-chainindex".to_owned(),
        &"txncount".to_owned(),
    );
    if txn_count_string == "-1" {
        return "{ \"success\": true, ".to_owned()
            + "\"transaction_count\": "
            + &0.to_string()
            + " }";
    } else {
        let try_parse = txn_count_string.parse::<u64>();
        if let Ok(txn_count) = try_parse {
            return "{ \"success\": true, ".to_owned()
                + "\"transaction_count\": "
                + &txn_count.to_string()
                + " }";
        } else {
            return "{ \"success\": false, ".to_owned()
                + "\"error\": "
                + &try_parse.unwrap_err().to_string()
                + " }";
        }
    }
}

#[get("/balances/<chain>")]
pub fn get_balance_v1(chain: String) -> String {
    if let Ok(acc) = get_account(&chain) {
        let balance: u64 = acc.balance;
        let locked: u64 = acc.locked;

        "{ \"success\": true, ".to_owned()
            + "\"chainkey\": \""
            + &chain
            + "\", "
            + "\"balance\": "
            + &balance.to_string()
            + ", "
            + "\"locked\": "
            + &locked.to_string()
            + " }"
    } else {
        "{ \"success\": false, ".to_owned()
            + "\"chainkey\": "
            + &chain
            + ", "
            + "\"balance\": "
            + &0.to_string()
            + ", "
            + "\"locked\": "
            + &0.to_string()
            + " }"
    }
}

#[get("/blocks/<hash>")]
pub fn get_block_v1(hash: String) -> String {
    let block = get_block_from_raw(hash);
    if let Ok(block_str) = serde_json::to_string(&block) {
        return "{ \"success\": true, \"response\": { \"block\": ".to_owned() + &block_str + " } }";
    }
    "{ \"success\": false, \"response\": { \"block\": } }".to_owned()
}

#[get("/hash_at_height/<chain>/<height>")]
pub fn hash_at_height(height: u64, chain: String) -> String {
    let block = get_block(&chain, height);

    return "{ \"success\": true, \"hash\": \"".to_string() + &block.hash + "\" }";
}

#[get("/usernames")]
pub fn get_usernames_v1() -> String {
    not_supported()
}
#[get("/publickey_for_username/<username>")]
pub fn get_publickey_for_username(username: String) -> String {
    if let Ok(acc) = avrio_core::account::get_by_username(&username) {
        return "{ \"success\": true, \"publickey\": \"".to_string() + &acc.public_key + "\" }";
    } else {
        error!("Could not find an account with username = {}", username);
        return "{ \"success\": false, \"publickey\": \"\" }".to_string();
    }
}

#[get("/username_for_publickey/<publickey>")]
pub fn username_for_publickey(publickey: String) -> String {
    if let Ok(acc) = avrio_core::account::get_account(&publickey) {
        return "{ \"success\": true, \"username\": \"".to_string() + &acc.username + "\" }";
    } else {
        error!("Could not find an account with publickey = {}", publickey);
        return "{ \"success\": false, \"username\": \"\" }".to_string();
    }
}

#[get("/publickey_to_address/<publickey>")]
pub fn publickey_to_address(publickey: String) -> String {
    return "{ \"success\": true, \"address\": \"".to_string()
        + &public_key_to_address(&publickey)
        + "\" }";
}

#[get("/chainlist")]
pub fn chainlist() -> String {
    let open_attempt = iter_database("chainlist".to_owned());
    if let Ok(db) = open_attempt {
        let mut chains: Vec<String> = vec![];

        for (key, _) in db.iter() {
            chains.push(key.to_owned());
        }

        log::trace!("Our chain list: {:#?}", chains);
        if let Ok(s) = serde_json::to_string(&chains) {
            return "{ \"success\": true, \"list\": ".to_owned() + &s + " }";
        } else {
            error!("Could not seralise chainlist");
            return "{ \"success\": false, \"chain\": \"\" }".to_string();
        }
    } else {
        error!(
            "Could not open chainslist db, error: {}",
            open_attempt.unwrap_err()
        );
        return "{ \"success\": false, \"list\": \"\" }".to_string();
    }
}

#[get("/blocksabovehash/<hash>/<chain>/<amount>")]
pub fn blocks_above_hash(hash: String, chain: String, amount: u64) -> String {
    let block_from: Block;

    if hash == "0" {
        log::trace!("Getting genesis block for chain: {}", chain);
        block_from = get_block(&chain, 0);
        log::trace!("Block from: {:#?} (api)", block_from);
    } else {
        block_from = get_block_from_raw(hash.clone());
    }

    if block_from == Default::default() {
        debug!("Cant find block (context blocksabovehash api call)");
        return "{ \"success\": false, \"blocks\": [] }".to_string();
    } else {
        let mut got: u64 = block_from.header.height;
        let mut prev: Block = block_from.clone();
        let mut blks: Vec<Block> = vec![];

        while prev != Default::default() {
            if (prev == block_from && hash == "0") || got == amount {
                blks.push(prev);
            }

            got += 1;
            trace!("Sent block at height: {}", got);
            prev = get_block(&chain, got);
        }
        if let Ok(blks_string) = serde_json::to_string(&blks) {
            return "{ \"success\": true, \"blocks\":".to_string() + &blks_string + "}";
        } else {
            debug!("Could not seralise blocks vec (context getblocksabovehash api call)");
            return "{ \"success\": false, \"blocks\": [] }".to_string();
        }
    }
}

#[post("/submit_block", format = "application/json", data = "<block_data>")]
pub fn submit_block_v1(block_data: rocket::Data) -> String {
    let mut bytes_stream = block_data.open();
    let mut holder_vec: Vec<u8> = vec![];
    loop {
        let mut buffer = [0u8; 512];
        let try_read_from_stream = bytes_stream.read(&mut buffer);
        if let Ok(size) = try_read_from_stream {
            trace!("Read {} bytes into buffer", size);
            if size == 0 {
                break;
            } else {
                holder_vec.append(&mut buffer.to_vec());
            }
        } else {
            debug!(
                "Failed to read into buf, error={}",
                try_read_from_stream.unwrap_err()
            );
            return format!(" {{ \"error\" : \" failed to read from datastream \" }}");
        }
    }
    let try_utf8_to_json = String::from_utf8(holder_vec);
    if let Ok(block_pretrim) = try_utf8_to_json {
        if block_pretrim != "" {
            let mut block = block_pretrim[1..].replace("\\", "").to_string(); // this very verbose bit of code removes everything outside the { } and removes the \
            loop {
                if &block[block.len() - 1..] != "}" {
                    block = block[0..block.len() - 1].to_string();
                } else {
                    break;
                }
            }
            trace!("Block submited by API json={}", block);
            let try_string_to_block = serde_json::from_str::<Block>(&block);
            if let Ok(blk) = try_string_to_block {
                debug!("Block submited by API, block={:?}", blk);
                if let Err(e) = blk.valid() {
                    return format!(" {{ \"error\" : \" {:?} }}\"", e);
                } else if let Err(e_) = save_block(blk.clone()) {
                    return format!(" {{ \"error\" : \" {:?} }}\"", e_);
                } else {
                    if let Err(ee) = blk.enact() {
                        return format!(" {{ \"error\" : \" {:?} }}\"", ee);
                    } else if let Err(ep) = prop_block(&blk) {
                        return format!(" {{ \"error\" : \" {:?} }}\"", ep);
                    } else if let Err(eann) = block_announce(blk) {
                        return format!(" {{ \"error\" : \" {:?} }}\"", eann);
                    } else {
                        return "{ \"result\" : \"sent block\" }".to_owned();
                    }
                }
            } else {
                debug!("Failed to turn string encoded json block to block struct (from peer), gave error={}, string={}",
                try_string_to_block.unwrap_err(),
                block
            );
                return format!(" {{ \"error\" : \" string to block failed\" }}",);
            }
        } else {
            debug!("JSON string blank",);
            return format!(" {{ \"error\" : \" JSON string blank \" }}",);
        }
    } else {
        debug!(
            "Failed to turn utf8 bytes to block (submit block api, error={})",
            try_utf8_to_json.unwrap_err(),
        );
        return format!(" {{ \"error\" : \" utf8 to json failed \" }}");
    }
}

pub fn get_middleware() -> Vec<Route> {
    routes![
        must_provide_method,
        get_balance_v1,
        get_block_v1,
        get_usernames_v1,
        submit_block_v1,
        get_blockcount_v1,
        transaction_count,
        get_publickey_for_username,
        username_for_publickey,
        publickey_to_address,
        blocks_above_hash,
        chainlist,
        hash_at_height
    ]
}
