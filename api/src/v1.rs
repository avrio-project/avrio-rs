/*
    Copyright The Avrio Core Developers 2020

    api/src/v1.rs

    This file handles the JSON API version 1 of the Daemon.
*/

use avrio_blockchain::getBlockFromRaw;
use avrio_core::account::{getAccount, Account};

use rocket::{routes, Route};

extern crate avrio_p2p;

fn not_supported() -> String {
    "{ \"error\": \"NOT_SUPPORTED\"}".to_owned()
}

#[get("/")]
fn must_provide_method() -> &'static str {
    "{ \"success\": false, \"error\": \"METHOD_MISSING\" }"
}

#[get("/balances/<chain>")]
pub fn get_balance_v1(chain: String) -> String {
    let acc: Account = getAccount(&chain).unwrap_or(Account::default());
    let balance: u64 = acc.balance;
    let locked: u64 = acc.locked;

    "{ \"success\": true, ".to_owned()
        + "\"chainkey\": "
        + &chain
        + ", "
        + "\"balance\": "
        + &balance.to_string()
        + ", "
        + "\"locked\": "
        + &locked.to_string()
        + " }"
}

#[get("/blocks/<hash>")]
pub fn get_block_v1(hash: String) -> String {
    let block = getBlockFromRaw(hash);
    let block_str = serde_json::to_string(&block).unwrap_or_default();

    "{ \"success\": true, \"response\": { \"block\": ".to_owned() + &block_str + " } }"
}

#[get("/usernames")]
pub fn get_usernames_v1() -> String {
    not_supported()
}

#[post("/blocks" /*, format = "application/json", data = "<block_data>"*/)]
pub fn submit_block_v1(/*block_data: rocket::Data*/) -> String {
    /* TODO: Find a way of getting all conections currently active (a function) wich returns a vec of refrences to mutable TcpStreams so we can prop the block
    let block_utf8 = block_dat.peek();
    let block: String = String::from_utf8(block_utf8.to_vec()).unwrap_or_default();
    let blk: Block = serde_json::from_str(&block).unwrap_or_default();
    if let Err(e) = check_block(blk.clone()) {
        return format!(" {{ \"error:\" {:?} }}", e);
    } else if let Err(e_) = saveBlock(blk.clone()) {
        return format!(" {{ \":\" {:?} }}", e_);
    } else if let Err(ee) = enact_block(blk.clone()) {
        return format!(" {{ \":\" {:?} }}", ee);
    } else if let Err(ep) = prop_block(getPeer) {
        return format!(" {{ \":\" {:?} }}", ep);
    } else {
        return "{ \"result\" : \"sent block\" }".to_owned();
    }
    */

    not_supported()
}

pub fn get_middleware() -> Vec<Route> {
    routes![
        get_balance_v1,
        get_block_v1,
        get_usernames_v1,
        submit_block_v1
    ]
}
