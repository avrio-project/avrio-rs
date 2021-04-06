/*
    Copyright The Avrio Core Developers 2020

    api/src/lib.rs

    This file handles routing of the Daemon's JSON API
*/

#![feature(proc_macro_hygiene, decl_macro)]

pub mod v1;
pub mod wallet_api;

#[macro_use]
extern crate rocket;
extern crate avrio_core;
extern crate avrio_p2p;
extern crate proc_macro;

use rocket::config::{Config, Environment, LoggingLevel};

pub fn start_server() {
    let config = Config::build(Environment::Staging)
        .log_level(LoggingLevel::Off) // disables logging
        .finalize()
        .unwrap();

    rocket::custom(config)
        .mount("/api/v1", v1::get_middleware())
        .launch();
}
