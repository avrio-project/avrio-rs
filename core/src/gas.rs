/*
Copywrite 2020 The Avrio Core Developers
This file has all the gas per operation declarations
*/

pub const TX_GAS: u8 = 20; // the gas used in a normal transaction (no extra)
pub const GAS_PER_EXTRA_BYTE_NORMAL: u8 = 60; // fee per byte of extra data in a transaction with amount > 0 and a recipitent
pub const GAS_PER_EXTRA_BYTE_MESSAGE: u8 = 100; // fee per byte of extra data in a message transaction (a transaction with amount = 0)
pub const GENESIS_MAX_GAS: u64 = u64::max_value(); // The max gas for a genesis block
