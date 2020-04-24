#[macro_use]
extern crate log;

pub fn safe_exit() {
    // TODO: save mempool to disk + send kill to all threads.

    info!("Goodbye!");
    avrio_p2p::close_all(connections_mut);
    process::exit(0);
}

pub mod account;
pub mod certificate;
pub mod epoch;
pub mod gas;
pub mod invite;
pub mod transaction;
pub mod username;
pub mod votes;
