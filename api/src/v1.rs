/*
    Copyright The Avrio Core Developers 2020

    api/src/v1.rs

    This file handles the JSON API version 1 of the Daemon.
*/

use avrio_blockchain::{
    check_block, enact_block, enact_send, get_block, get_block_from_raw, save_block, Block,
    BlockType,
};
use avrio_config::config;
use avrio_core::account::get_account;
use avrio_database::get_data;
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
        config().db_path + &"/chains/".to_owned() + &chain + &"-chainindex".to_owned(),
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
        config().db_path + &"/chains/".to_owned() + &chain + &"-chainindex".to_owned(),
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
                if let Err(e) = check_block(blk.clone()) {
                    return format!(" {{ \"error\" : \" {:?} }}\"", e);
                } else if let Err(e_) = save_block(blk.clone()) {
                    return format!(" {{ \"error\" : \" {:?} }}\"", e_);
                } else {
                    if blk.block_type == BlockType::Send {
                        if let Err(ee) = enact_send(blk.clone()) {
                            return format!(" {{ \"error\" : \" {:?} }}\"", ee);
                        } else if let Err(ep) = prop_block(&blk) {
                            return format!(" {{ \"error\" : \" {:?} }}\"", ep);
                        } else {
                            return "{ \"result\" : \"sent block\" }".to_owned();
                        }
                    } else {
                        if let Err(ee) = enact_block(blk.clone()) {
                            return format!(" {{ \"error\" : \" {:?} }}\"", ee);
                        } else if let Err(ep) = prop_block(&blk) {
                            return format!(" {{ \"error\" : \" {:?} }}\"", ep);
                        } else if let Err(eann) = block_announce(blk) {
                            return format!(" {{ \"error\" : \" {:?} }}\"", eann);
                        } else {
                            return "{ \"result\" : \"sent block\" }".to_owned();
                        }
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
        hash_at_height
    ]
}
