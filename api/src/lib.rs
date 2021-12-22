/*
    Copyright The Avrio Core Developers 2020

    api/src/lib.rs

    This file handles routing of the Daemon's JSON API
*/

#![feature(proc_macro_hygiene, decl_macro)]

pub mod v1;

#[macro_use]
extern crate rocket;
extern crate avrio_config;
extern crate avrio_core;
extern crate avrio_p2p;
extern crate proc_macro;

use rocket::config::{Config, Environment, LoggingLevel};

pub fn start_server() {
    let conf = avrio_config::config();
    let config = Config::build(Environment::Staging)
        .address(conf.api_address)
        .port(conf.api_port as u16)
        .log_level(LoggingLevel::Off) // disables logging
        .finalize()
        .unwrap();

    rocket::custom(config)
        .mount("/api/v1", v1::get_middleware())
        .launch();
}
