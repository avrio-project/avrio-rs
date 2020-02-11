#[macro_use]
extern crate log;
#[macro_use]
extern crate unwrap;
use clap;
use crust;
use maidsafe_utilities;
use rand;
use serde_json;

use clap::{App, AppSettings, Arg, SubCommand};

use crust::{read_config_file, ConnectionInfoResult, PeerId, PrivConnectionInfo, Service};
use rand::Rng;
use safe_crypto::{gen_encrypt_keypair, gen_sign_keypair, SecretEncryptKey};
use std::cmp;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::str::FromStr;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
// Thanks Crust example :)
struct Network {
    nodes: HashMap<usize, PeerId>,
    our_connection_infos: BTreeMap<u32, PrivConnectionInfo>,
    performance_start: Instant,
    performance_interval: Duration,
    received_msgs: u32,
    received_bytes: usize,
    peer_index: usize,
    connection_info_index: u32,
}

// simple "routing table" without any structure
impl Network {
    pub fn new() -> Network {
        Network {
            nodes: HashMap::new(),
            our_connection_infos: BTreeMap::new(),
            performance_start: Instant::now(),
            performance_interval: Duration::from_secs(10),
            received_msgs: 0,
            received_bytes: 0,
            peer_index: 0,
            connection_info_index: 0,
        }
    }

    pub fn next_peer_index(&mut self) -> usize {
        let ret = self.peer_index;
        self.peer_index += 1;
        ret
    }

    pub fn next_connection_info_index(&mut self) -> u32 {
        let ret = self.connection_info_index;
        self.connection_info_index += 1;
        ret
    }

    pub fn print_connected_nodes(&self, service: &Service) {
        println!("Node count: {}", self.nodes.len());
        for (id, node) in &self.nodes {
            let status = if service.is_connected(node) {
                "Connected   "
            } else {
                "Disconnected"
            };

            println!("[{}] {} {:?}", id, status, node);
        }

        println!();
    }

    pub fn get_peer_id(&self, n: usize) -> Option<&PeerId> {
        self.nodes.get(&n)
    }

    pub fn record_received(&mut self, msg_size: usize) {
        self.received_msgs += 1;
        self.received_bytes += msg_size;
        if self.received_msgs == 1 {
            self.performance_start = Instant::now();
        }
        if self.performance_start + self.performance_interval < Instant::now() {
            println!(
                "\nReceived {} messages with total size of {} bytes in last {} seconds.",
                self.received_msgs,
                self.received_bytes,
                self.performance_interval.as_secs()
            );
            self.received_msgs = 0;
            self.received_bytes = 0;
        }
    }
}

fn handle_new_peer(
    service: &Service,
    protected_network: Arc<Mutex<Network>>,
    peer_id: PeerId,
) -> usize {
    let mut network = unwrap!(protected_network.lock());
    let peer_index = network.next_peer_index();
    let _ = network.nodes.insert(peer_index, peer_id);
    peer_index
}

#[derive(Serialize, Deserialize, Debug)]
pub struct P2pdata {
    message_bytes: usize, // The length in bytes of message
    message_type: u16, // The type of data
    message: String,   // The serialized data
}

fn process_block(s: String) {hanks cust
    println!("Block");
}

fn process_transaction(s: String) {
    println!("Transaction");
}

fn process_registration(s: String) {
    println!("Certificate");
}

fn process_handshake(s: String) {
    println!("handshake");
}


pub enum p2p_errors {
  None,
  TimeOut,
  InvalidSocket,
  Other,
}

fn formMsg(data_s: String, data_type: u16) -> String {
    let data_len = data_s.len();
    let msg: P2pdata = P2pdata {
        message_bytes: data_len,
        message_type: data_type,
        message: data_s,
    };
    return serde_json::to_string(&msg).unwrap();
}

fn deformMsg(msg: &String) { // deforms message and excutes appropriate function to handle resultant data
    let mut msg_d:P2pdata = serde_json::from_str(msg).unwrap();
    match msg_d.message_type {
        0x0a => process_block(msg_d.message),
        0x0b => process_transaction(msg_d.message),
        0x0c => process_registration(msg_d.message),
        0x1a => process_handshake(msg_d.message),
        _ => println!("[WARN] Bad Messge type from peer. Message type {:?}. (If you ae getting,losts of these check for updates)", msg_d.message_type),
    }
}

pub fn launchP2pServer(addr: Multiaddr) {
  let tcp = TcpConfig::new();
  let _conn = tcp.dial(addr);
}
