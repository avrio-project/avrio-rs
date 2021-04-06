/*
    Copyright The Avrio Core Developers 2020

    api/src/v1.rs

    This file handles the JSON API of the headless wallet.
*/

use avrio_blockchain::{
    check_block, enact_block, enact_send, get_block, get_block_from_raw, save_block, Block,
    BlockType,
};
use avrio_config::config;
use avrio_core::account::get_account;

use log::*;
use rocket::{routes, Route};
use std::io::prelude::*;
extern crate avrio_p2p;
use serde::Deserialize;
#[derive(Default, Clone, Deserialize, Debug)]
struct TxnDetails {
    pub amount: u64,
    pub reciever: String,
    pub sender: String,
    pub txn_type: String,
    pub extra: String,
}
fn not_supported() -> String {
    "{ \"error\": \"NOT_SUPPORTED\"}".to_owned()
}

#[get("/")]
fn must_provide_method() -> &'static str {
    "{ \"success\": false, \"error\": \"METHOD_MISSING\" }"
}
#[get("/auth/<key>")]
pub fn auth(key: String) -> String {
    if key == "1234567890" {
        // TODO: use a config value
        return ("{ \"success\": true, \"token\": ".to_owned() + &key + "}").to_string();
    // TODO: generate a token and use that
    } else {
        return ("{ \"success\": false, ".to_owned() + "\"error\": \"Invalid key\"}").to_string();
    }
}

#[get("/openwallet/<walletname>/<password>")]
pub fn open_wallet(walletname: String, password: String) -> String {
    return "{ }".to_string();
}

#[get("/balance/<chain>")]
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

#[post(
    "/submit_transaction",
    format = "application/json",
    data = "<transaction_data>"
)]
pub fn submit_block_v1(transaction_data: rocket::Data) -> String {
    let mut bytes_stream = transaction_data.open();
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
    if let Ok(txn_pretrim) = try_utf8_to_json {
        if txn_pretrim != "" {
            let mut txn = txn_pretrim[1..].replace("\\", "").to_string(); // this very verbose bit of code removes everything outside the { } and removes the \
            loop {
                if &txn[txn.len() - 1..] != "}" {
                    txn = txn[0..txn.len() - 1].to_string();
                } else {
                    break;
                }
            }
            trace!("txn submited by API json={}", txn);
            let try_string_to_txn = serde_json::from_str::<TxnDetails>(&txn);
            if let Ok(txn_details) = try_string_to_txn {
                // TODO check we have loaded wallet with public key/sender key sender, create txn, block etc, submit to node
                return format!(" {{ \"error\" : \" unimplemented \" }}");
            } else {
                debug!(
                    "Failed to decode json into TxnDetails struct, gave error: {}",
                    try_string_to_txn.unwrap_err()
                );
                return format!(" {{ \"error\" : \" json to struct failed \" }}");
            }
        } else {
            debug!("JSON string blank",);
            return format!(" {{ \"error\" : \" JSON string blank \" }}",);
        }
    } else {
        debug!(
            "Failed to turn utf8 bytes to txn_detail (submit txn_detail api, error={})",
            try_utf8_to_json.unwrap_err(),
        );
        return format!(" {{ \"error\" : \" utf8 to json failed \" }}");
    }
}

pub fn get_middleware() -> Vec<Route> {
    routes![must_provide_method]
}
