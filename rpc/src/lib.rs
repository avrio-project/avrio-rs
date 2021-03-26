/*
Copyright The Avrio Core Developers 2020
rpc/lib.rs -
  this file handles the json api
*/

#![feature(proc_macro_hygiene, decl_macro)]

extern crate avrio_core;
use avrio_blockchain::get_block_from_raw;
use avrio_core::account::{get_account, Account};
#[macro_use]
extern crate rocket;
use rocket::config::{Config, Environment, LoggingLevel};

extern crate avrio_p2p;

fn not_supported() -> String {
    "{ \"error\": \"this method is not yet supported\"}".to_owned()
}
#[get("/")]
fn must_provide_method() -> &'static str {
    "{ \"response\": 400, \"error\": \"Must provide a method\" }"
}

#[get("/getBalance/<chain>")]
fn get_balance(chain: String) -> String {
    let acc: Account = get_account(&chain).unwrap_or(Account::default());
    let balance: u64 = acc.balance;
    let locked: u64 = acc.locked;
    "{    \"response\": 200, \"chainkey\": ".to_owned()
        + &chain
        + ",    \"balance\" : "
        + &balance.to_string()
        + ", \"locked\""
        + &locked.to_string()
        + " }"
}

#[get("/getBlock/<hash>")]
fn get_block(hash: String) -> String {
    let blk = get_block_from_raw(hash);
    serde_json::to_string(&blk).unwrap_or_default()
}

#[get("/usernames")]
fn get_usernames() -> String {
    not_supported()
}
#[post("/submit_block", format = "application/json", data = "<_block_dat>")]
fn submit_block(_block_dat: rocket::Data) -> String {
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
pub fn start_server() {
    let config = Config::build(Environment::Staging)
        .log_level(LoggingLevel::Off) // disables logging
        .finalize()
        .unwrap();
    rocket::custom(config)
        .mount(
            "/json_rpc",
            routes![
                must_provide_method,
                submit_block,
                get_usernames,
                get_balance,
                get_block
            ],
        )
        .launch();
}
