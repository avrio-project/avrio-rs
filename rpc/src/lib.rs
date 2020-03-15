/*
Copyright The Avrio Core Developers 2020
rpc/lib.rs - 
  this file handles the json api
*/

#![feature(proc_macro_hygiene, decl_macro)]
use serde_json::json;
#[macro_use] extern crate rocket;
#[get("/")]
fn must_provide_method() -> &'static str {
    "{ \"response\": 400, \"error\": \"Must provide a method\" }"
}

pub fn start_server() {
    rocket::ignite().mount("/json_rpc", routes![must_provide_method]).launch();
}