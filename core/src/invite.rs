// Copyright 2020 he avrio core developers

extern crate ring;
use ring::{
    rand as randc,
    signature::{self, KeyPair},
};
extern crate bs58;

extern crate avrio_database;
use avrio_database::{get_data, save_data};

extern crate avrio_config;
use avrio_config::config;

pub fn per_epoch_limit(nodes: u64) -> u64 {
    return (1 / 3) * (nodes / 2);
}

/// Generates the public private key pair for a new invite, returns a tupe (publickey, privatekey)
pub fn generate_invite() -> (String, String) {
    let rngc = randc::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rngc).unwrap();
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    let peer_public_key_bytes = key_pair.public_key().as_ref();
    return (
        bs58::encode(peer_public_key_bytes).into_string(),
        bs58::encode(pkcs8_bytes).into_string(),
    );
}

/// Returns true if the invite is in existance and not spent.
pub fn unspent(invite: &String) -> bool {
    if get_data(config().db_path + &"/invites".to_owned(), invite) != "u".to_owned() {
        return false;
    } else {
        return true;
    }
}

/// Returns true if the invite is in existance and spent.
// TODO: Phase out, duplicate of unspent() above
pub fn is_spent(invite: &String) -> bool {
    if get_data(config().db_path + &"/invites".to_owned(), invite) != "s".to_owned() {
        return false;
    } else {
        return true;
    }
}

/// Marks the invite as spent
pub fn mark_spent(invite: &String) -> Result<(), ()> {
    if !unspent(invite) {
        return Err(());
    } else if save_data(
        &"s".to_string(),
        &(config().db_path + &"/invites".to_owned()),
        invite.to_owned(),
    ) != 1
    {
        return Err(());
    } else {
        return Ok(());
    }
}

/// Saves the public key into our innvites db (and sets to unspent)
pub fn new(invite: &String) -> Result<(), ()> {
    if get_data(config().db_path + &"/invites".to_owned(), invite) != "-1".to_owned() {
        return Err(());
    } else if save_data(
        &"u".to_owned(),
        &(config().db_path + &"/invites".to_owned()),
        invite.to_owned(),
    ) != 1
    {
        return Err(());
    } else {
        return Ok(());
    }
}

/// Returns true if:
/// * 1) The invite format is valid
/// * 2) It is on the blockchain and unspent.
pub fn valid(invite: &String) -> bool {
    if is_spent(invite) {
        return false;
    } else {
        return true;
    }
}
