/*
Copyright The Avrio Core Developers 2020
rpc/lib.rs -
  this file handles the json api
*/

#![feature(proc_macro_hygiene, decl_macro)]

extern crate avrio_core;
use avrio_core::account::{getAccount, Account};
#[macro_use]
extern crate rocket;
#[get("/")]
fn must_provide_method() -> &'static str {
    "{ \"response\": 400, \"error\": \"Must provide a method\" }"
}

#[get("/getBalance/<chain>")]
fn get_balance(chain: String) -> String {
    let acc: Account = getAccount(&chain).unwrap_or(Account::default());
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

pub fn start_server() {
    rocket::ignite()
        .mount("/json_rpc", routes![must_provide_method, get_balance])
        .launch();
}
