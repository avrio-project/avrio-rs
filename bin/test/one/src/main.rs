// Testnet one,
// This testnet foucouses on the P2p code, on launch a node will conect to the seed node(/s),
// get the peer list and connect to the other nodes on this peerlist. Then every 5 mins they 
//generate a block and release it (to test the p2p propigation code). 

pub extern crate config;
pub extern crate core;
pub extern crate crypto;
pub extern crate p2p;
pub extern crate blockchain;
pub extern crate database;

